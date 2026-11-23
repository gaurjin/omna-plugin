"""One file decides what is NOT masked; it can no longer switch masking off quietly.

Security review 2026-11-11, finding 15: an allowlist entry ``.+`` in
``~/.omna/ruleset.json`` stopped ALL masking, secrets included; the receipt
showed nothing unusual, the health check did not mention it, and the file was
readable by other users of the Mac. All values are fake.
"""

from __future__ import annotations

import json
import stat

import httpx
import pytest

from omna_plugin import config, receipts, report
from omna_plugin import ruleset as ruleset_file
from omna_plugin.cli import main
from omna_plugin.engine import MaskingSession
from omna_plugin.proxy import create_app
from tests.test_proxy import Upstream

TOKEN = "ghp_" + "fgYFNmLOZlhOWtmhi0EwWcTCEsLvKQdOrH3k"
STRIPE = "sk_live_" + "GF49peQI6DeMRfGLcr0JePtE"
EMAIL = "maria.gonzalez@fakecorp.example"
SSN = "536-22-8841"
TEXT = f"token {TOKEN} mail {EMAIL} ssn {SSN} stripe {STRIPE} end"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def _mode(p) -> int:
    return stat.S_IMODE(p.stat().st_mode)


def _set(allowlist: list[str]) -> None:
    ruleset_file.write({"allowlist": allowlist, "custom_rules": []})


# ------------------------------------------------------- the engine's rules
@pytest.mark.parametrize("broad", [".+", ".*", r"[\s\S]+", r"\S+.*"])
def test_an_allowlist_entry_that_matches_everything_switches_nothing_off(home, broad):
    s = MaskingSession()
    _set([broad])
    s._cache.clear()
    out = s.mask_text(TEXT).masked
    for value in (TOKEN, EMAIL, SSN, STRIPE):
        assert value not in out, f"{broad!r} must not spare {value}"
    assert ruleset_file.summary()["ignored_allowlist"] == [broad]


def test_a_pattern_never_spares_a_secret(home):
    s = MaskingSession()
    _set(["ghp_.*", "sk_live_.*", r".*@fakecorp\.example"])
    s._cache.clear()
    out = s.mask_text(TEXT).masked
    assert TOKEN not in out and STRIPE not in out, "a pattern must not spare a secret"
    assert EMAIL in out, "a company may still mark its own addresses safe"
    assert SSN not in out


def test_one_exact_value_can_still_be_marked_safe_even_a_key(home, capsys):
    # A vendor's published example key, allowed on purpose with `omna allow`.
    assert main(["allow", TOKEN]) == 0
    out = MaskingSession().mask_text(TEXT).masked
    assert TOKEN in out and STRIPE not in out and EMAIL not in out


# ------------------------------------------------------------ the file itself
def test_the_file_is_owner_only_however_it_is_written(home):
    MaskingSession()                                              # a fresh install writes the defaults
    p = config.ruleset_path()
    assert _mode(p) == 0o600
    p.chmod(0o644)                                                # what 0.6.20 and earlier left behind
    MaskingSession()
    assert _mode(p) == 0o600, "a looser file is tightened when Omna starts"
    p.chmod(0o644)
    assert main(["allow", "ACME-000000"]) == 0
    assert _mode(p) == 0o600
    p.chmod(0o644)
    main(["categories", "off", "PHONE"])
    assert _mode(p) == 0o600


# ---------------------------------------------------------- on the record
def _api():
    up = Upstream()
    upc = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app))
    session = MaskingSession()
    app = create_app(session, anthropic_upstream="http://anthropic.test", openai_upstream="http://openai.test", client=upc)
    return up, session, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")


async def _send(client, text):
    return await client.post("/v1/messages", json={"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": text}]},
                             headers={"x-api-key": "k", "anthropic-version": "2023-06-01"})


@pytest.mark.anyio
async def test_every_receipt_carries_the_rulesets_fingerprint_and_a_change_shows(home):
    up, session, client = _api()
    await _send(client, "A " + TEXT)
    first = receipts.tail(1)[0]["ruleset"]
    assert len(first) == 16 and first == ruleset_file.fingerprint()
    _set([".+"])
    session._cache.clear()
    await _send(client, "B " + TEXT)
    second = receipts.tail(1)[0]["ruleset"]
    assert second != first, "the change to what is NOT masked is on the record"
    # ...and the request after the change was still masked.
    for value in (TOKEN, EMAIL, SSN, STRIPE):
        assert value not in up.calls[-1]["raw"]
    d = report.build(7)
    assert d["rulesets"] == [first, second]
    assert "RULES CHANGED: 2 different rulesets" in report.render_text(d)


@pytest.mark.anyio
async def test_health_and_status_say_when_an_entry_was_refused(home, capsys):
    up, session, client = _api()
    _set([".+", "localhost"])
    h = (await client.get("/omna/health")).json()
    assert h["ruleset"]["ignored_allowlist"] == [".+"] and h["ruleset"]["allowlist"] == 2
    assert h["ruleset"]["fingerprint"] == ruleset_file.fingerprint()
    lines = "\n".join(ruleset_file.status_lines())
    assert "IGNORED allowlist entry '.+'" in lines and "matches everything" in lines


def test_status_is_calm_for_an_ordinary_ruleset(home):
    MaskingSession()
    lines = ruleset_file.status_lines()
    assert len(lines) == 1 and "4 allowlist entries" in lines[0] and "fingerprint" in lines[0]


def test_one_ruleset_for_the_whole_period_reads_calm(home):
    receipts.append({"door": "api", "route": "/v1/messages", "host": "x", "status": 200, "masked": {}, "ms": 5, "ruleset": "ab" * 8})
    assert "one ruleset in force the whole period" in report.render_text(report.build(7))


def test_a_broken_ruleset_is_named_not_silently_dropped(home):
    MaskingSession()
    config.ruleset_path().write_text('{"allowlist": ["("]}')
    lines = "\n".join(ruleset_file.status_lines())
    assert "PROBLEM" in lines
    with pytest.raises(Exception):
        MaskingSession().mask_text(TEXT)            # refused (the doors answer 400), never sent unmasked


# ------------------------------------------------- #32: the client's own lists
def test_mask_always_masks_a_client_value_in_any_case_and_status_shows_both_lists(home, capsys):
    """#32 (owner 2026-11-22): clients need a "mask always" list next to the
    "never mask" list, by command, not by hand-editing JSON."""
    assert main(["mask-always", "Acme Corp & Sons"]) == 0
    assert main(["mask-always", "Project Bluebird", "--label", "PROJECT"]) == 0
    assert main(["mask-always", "Acme Corp & Sons"]) == 0          # twice = still one entry
    assert main(["allow", "support@ourshop.example"]) == 0
    out = MaskingSession().mask_text("Send ACME corp & sons the Project Bluebird plan, cc support@ourshop.example").masked
    assert "acme" not in out.lower() and "Bluebird" not in out
    assert "[CLIENT_1]" in out and "[PROJECT_1]" in out
    assert "support@ourshop.example" in out
    assert len(json.loads(config.ruleset_path().read_text())["custom_rules"]) == 2
    capsys.readouterr()
    lines = "\n".join(ruleset_file.status_lines())
    assert "always mask: Acme Corp & Sons, Project Bluebird (as PROJECT)" in lines
    assert "never mask:  support@ourshop.example" in lines
    assert "127.0.0.1" not in lines                                 # the built-in entries are not the person's list


def test_mask_always_refuses_a_bad_label(home, capsys):
    assert main(["mask-always", "Acme", "--label", "bad label"]) == 2
    p = config.ruleset_path()
    assert not p.exists() or not json.loads(p.read_text()).get("custom_rules")


def test_status_hides_exactly_the_built_in_entries():
    from omna_plugin.engine import DEFAULT_ALLOWLIST
    assert ruleset_file._BUILT_IN == set(DEFAULT_ALLOWLIST)
