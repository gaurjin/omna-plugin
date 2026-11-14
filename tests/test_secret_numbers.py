"""A secret's stand-in number survives a restart and never means a second secret.

Security review 2026-11-11, finding 10. Secrets live in memory only, and
their numbering used to restart from 1 with every restart (every settings
change restarts the daemon). A conversation from before the restart that
still said "SECRET_GITHUB_TOKEN_1" then got whichever token came first after
it: the production token where the staging one was meant.

Also finding 10's other half: a stand-in the AI repeats in its private
"thinking" notes must not stop the same stand-in being put back later.

All values are fake. Stand-ins are built from pieces, never typed whole.
"""

from __future__ import annotations

import json
import os

import httpx
import pytest
from starlette.responses import JSONResponse

from omna_plugin import config
from omna_plugin.engine import MaskingSession
from omna_plugin.proxy import create_app
from tests.test_proxy import Upstream

STAGING = "ghp_" + "fgYFNmLOZlhOWtmhi0EwWcTCEsLvKQdOrH3k"
PROD = "ghp_" + "Zk3HrOdQKvLsECTcWwE0ihmtWOhlZOLmNFYg"
THIRD = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
EMAIL = "maria.gonzalez@fakecorp.example"


def gh(n: int) -> str:
    return "[SECRET_GITHUB" + f"_TOKEN_{n}]"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def test_the_same_secret_keeps_its_number_after_a_restart(home):
    assert MaskingSession().mask_text(f"staging {STAGING}").masked == f"staging {gh(1)}"
    after = MaskingSession()                       # the restart: nothing in memory
    assert after.secrets_held == 0
    assert after.mask_text(f"staging {STAGING}").masked == f"staging {gh(1)}"
    assert after.restore_text(gh(1)) == STAGING


def test_a_different_secret_first_after_a_restart_never_takes_an_old_number(home):
    MaskingSession().mask_text(f"staging {STAGING}")
    after = MaskingSession()
    # The attack: another secret is the first one seen after the restart.
    assert after.mask_text(f"prod {PROD}").masked == f"prod {gh(2)}"
    # The old number is simply unknown now — never the production token.
    assert after.restore_text(gh(1)) == gh(1)
    assert after.mask_text(f"staging {STAGING}").masked == f"staging {gh(1)}"
    assert after.restore_text(gh(1)) == STAGING and after.restore_text(gh(2)) == PROD


def test_a_number_is_not_reused_even_after_forget(home):
    s = MaskingSession()
    s.mask_text(f"staging {STAGING}")
    s.forget()
    assert s.mask_text(f"prod {PROD}").masked == f"prod {gh(2)}"
    # ...and not after forget + restart either.
    s.forget()
    assert MaskingSession().mask_text(f"third {THIRD}").masked == f"third {gh(3)}"


def test_two_programs_sharing_the_folder_never_give_one_number_to_two_secrets(home):
    daemon, one_off = MaskingSession(), MaskingSession()     # both started before either saw a secret
    assert daemon.mask_text(f"staging {STAGING}").masked == f"staging {gh(1)}"
    assert one_off.mask_text(f"prod {PROD}").masked == f"prod {gh(2)}"
    assert one_off.mask_text(f"staging {STAGING}").masked == f"staging {gh(1)}"


def test_the_counters_file_missing_does_not_bring_a_number_back(home):
    MaskingSession().mask_text(f"staging {STAGING}")
    config.secret_counters_path().unlink()
    assert MaskingSession().mask_text(f"prod {PROD}").masked == f"prod {gh(2)}"


def test_no_secret_is_written_to_disk_only_numbers_and_a_keyed_fingerprint(home):
    s = MaskingSession()
    s.mask_text(f"staging {STAGING} prod {PROD}")
    for root, _, files in os.walk(home):
        for name in files:
            blob = open(os.path.join(root, name), "rb").read()
            assert STAGING.encode() not in blob and PROD.encode() not in blob, name
            assert STAGING[4:20].encode() not in blob, name
    assert json.loads(config.secret_counters_path().read_text()) == {"GITHUB_TOKEN": 2}
    assert oct(config.secret_counters_path().stat().st_mode & 0o777) == "0o600"
    saved = json.loads(config.registry_path().read_text())["secret_numbers"]
    assert sorted(saved.values()) == [1, 2]
    for key in saved:
        kind, _, fp = key.partition("\x00")
        assert kind == "GITHUB_TOKEN" and len(fp) == 32 and all(c in "0123456789abcdef" for c in fp)


def test_the_fingerprint_is_keyed_per_computer(tmp_path, monkeypatch):
    seen = []
    for name in ("a", "b"):
        monkeypatch.setenv("OMNA_HOME", str(tmp_path / name))
        MaskingSession().mask_text(f"staging {STAGING}")
        seen.append(next(iter(json.loads(config.registry_path().read_text())["secret_numbers"])))
    assert seen[0] != seen[1], "the same secret must not have the same fingerprint on two computers"


# ------------------------------------------------- through the API door
def _api(up):
    upc = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app))
    app = create_app(MaskingSession(), anthropic_upstream="http://anthropic.test", openai_upstream="http://openai.test", client=upc)
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")


class Scripted(Upstream):
    reply: dict = {}

    async def messages(self, request):
        await self._record(request)
        return JSONResponse(self.reply)


H = {"x-api-key": "k", "anthropic-version": "2023-06-01"}


async def _post(client, messages):
    r = await client.post("/v1/messages", json={"model": "m", "max_tokens": 5, "messages": messages}, headers=H)
    return r.json()


@pytest.mark.anyio
async def test_after_a_restart_the_old_number_never_hands_over_another_secret(home):
    up = Scripted()
    up.reply = {"content": [{"type": "text", "text": "noted"}]}
    await _post(_api(up), [{"role": "user", "content": f"staging token is {STAGING}"}])
    # Restart. A new task names only the PROD token; the AI answers with the
    # stand-in it remembers for STAGING (a memory file, a summary).
    up2 = Scripted()
    up2.reply = {"content": [{"type": "text", "text": "export GH_TOKEN=" + gh(1)}]}
    got = await _post(_api(up2), [{"role": "user", "content": f"prod token is {PROD}. Export the staging one."}])
    assert PROD not in json.dumps(got) and STAGING not in json.dumps(got)
    assert gh(2) in up2.calls[-1]["raw"]            # prod got a number of its own


@pytest.mark.anyio
async def test_a_stand_in_in_the_thinking_notes_does_not_stop_restore(home):
    up = Scripted()
    client = _api(up)
    email_1 = "[EMAIL" + "_1]"
    up.reply = {"content": [{"type": "thinking", "thinking": f"User's address is {email_1}.", "signature": "sig"},
                            {"type": "text", "text": f"Got it: {email_1}"}]}
    u1 = {"role": "user", "content": f"my address is {EMAIL}"}
    b1 = await _post(client, [u1])
    assert b1["content"][1]["text"] == f"Got it: {EMAIL}"
    assert b1["content"][0]["thinking"] == f"User's address is {email_1}."      # thinking is never touched
    # Turn 2: the agent resends the thinking notes as they were (stand-in and all).
    up.reply = {"content": [{"type": "tool_use", "id": "t", "name": "Write",
                             "input": {"file_path": "contact.txt", "content": f"email={email_1}\n"}}]}
    b2 = await _post(client, [u1, {"role": "assistant", "content": b1["content"]},
                              {"role": "user", "content": "save it to contact.txt"}])
    assert up.calls[-1]["json"]["messages"][1]["content"][0]["thinking"] == f"User's address is {email_1}."
    assert b2["content"][0]["input"]["content"] == f"email={EMAIL}\n", "the stand-in must not be written into the file"
