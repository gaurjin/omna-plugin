"""Crash reports that a privacy buyer can audit (#132).

The hard requirement is not "we collect crashes" — it is that a crash report
can NEVER carry a prompt, an unmasked value, or the person's identity, and
that they can check that claim themselves instead of trusting a README.
"""

import json

import pytest

from omna_plugin import crashlog

FAKE_STRIPE = "sk_live_" + "51H8xk2KJ3mN4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0u"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def _boom(message: str) -> BaseException:
    try:
        raise RuntimeError(message)
    except RuntimeError as e:
        return e


# ------------------------------------------------------------- what gets kept
def test_a_crash_is_recorded_with_the_facts_we_need(home):
    crashlog.record(_boom("upstream returned nonsense"), where="proxy")
    rows = crashlog.tail(10)
    assert len(rows) == 1
    r = rows[0]
    assert r["where"] == "proxy"
    assert r["error"] == "RuntimeError"
    assert "upstream returned nonsense" in r["message"]
    assert r["plugin"] and r["python"] and r["os"]
    assert isinstance(r["traceback"], list) and r["traceback"]


def test_the_file_is_owner_only(home):
    crashlog.record(_boom("x"), where="cli")
    assert oct((home / "crashes.jsonl").stat().st_mode)[-3:] == "600"


# --------------------------------------------------- what can NEVER get in it
def test_a_secret_in_the_error_message_is_masked(home):
    crashlog.record(_boom(f"auth failed for {FAKE_STRIPE}"), where="proxy")
    blob = (home / "crashes.jsonl").read_text()
    assert "sk_live" not in blob
    assert "SECRET_" in blob or "REDACTED" in blob


def test_pii_in_the_error_message_is_masked(home):
    crashlog.record(_boom("could not route mail for jane.doe@example.com"), where="proxy")
    blob = (home / "crashes.jsonl").read_text()
    assert "jane.doe@example.com" not in blob


def test_masking_a_crash_does_not_touch_the_token_registry(home):
    """A crash must not mint registry entries — those are real values at rest.

    The crash path uses the engine's own per-call numbering (irreversible), not
    the stable MaskingSession, so nothing is persisted and nothing renumbers.
    """
    crashlog.record(_boom("mail jane.doe@example.com"), where="cli")
    assert not (home / "registry.json").exists()


def test_the_home_directory_is_stripped_from_paths(home):
    """`/Users/jane/...` is the person's real name. Every frame is reduced to a
    bare filename, and the message has the home path replaced with `~`."""
    import pathlib

    crashlog.record(_boom(f"cannot open {pathlib.Path.home()}/Documents/payroll.csv"), where="cli")
    blob = (home / "crashes.jsonl").read_text()
    assert str(pathlib.Path.home()) not in blob
    r = crashlog.tail(1)[0]
    assert all("/" not in f["file"] for f in r["traceback"])


def test_no_prompt_or_body_field_can_be_smuggled_in(home):
    """Belt and braces: even a caller that passes extra context cannot add a
    free-text field — only the allowlisted keys survive into the file."""
    crashlog.record(_boom("x"), where="proxy", extra={"route": "/v1/messages", "body": "SECRET PROMPT TEXT"})
    blob = (home / "crashes.jsonl").read_text()
    assert "SECRET PROMPT TEXT" not in blob
    assert crashlog.tail(1)[0].get("route") == "/v1/messages"


# ----------------------------------------------------------------- the basics
def test_nothing_is_ever_sent_automatically(home, monkeypatch):
    """There is no network call anywhere in this module. If one appears, this
    test is the thing that should start failing."""
    import omna_plugin.crashlog as m

    src = (m.__file__ or "").replace(".pyc", ".py")
    text = open(src).read()
    for forbidden in ("httpx", "requests", "urllib.request", "socket", "post("):
        assert forbidden not in text, f"crashlog must not be able to send anything ({forbidden!r})"


def test_the_log_is_capped_so_it_cannot_grow_forever(home):
    for i in range(crashlog.MAX_ROWS + 25):
        crashlog.record(_boom(f"boom {i}"), where="cli")
    rows = crashlog.tail(10_000)
    assert len(rows) == crashlog.MAX_ROWS
    assert "boom %d" % (crashlog.MAX_ROWS + 24) in rows[-1]["message"]  # newest kept


def test_clear_empties_it(home):
    crashlog.record(_boom("x"), where="cli")
    assert crashlog.clear() is True
    assert crashlog.tail(10) == []


def test_a_broken_line_does_not_lose_the_good_ones(home):
    crashlog.record(_boom("first"), where="cli")
    with open(home / "crashes.jsonl", "a") as f:
        f.write("{not json\n")
    crashlog.record(_boom("second"), where="cli")
    rows = crashlog.tail(10)
    assert [r["message"] for r in rows] == ["first", "second"]


def test_recording_never_raises_even_if_everything_is_broken(home, monkeypatch):
    """A crash reporter that crashes turns one bug into two. It must swallow
    its own failures, always."""
    monkeypatch.setattr(crashlog.config, "ensure_home", lambda: (_ for _ in ()).throw(OSError("disk full")))
    crashlog.record(_boom("x"), where="cli")  # must not raise


def test_issue_url_is_prefilled_and_carries_no_values(home):
    crashlog.record(_boom(f"auth failed for {FAKE_STRIPE}"), where="proxy")
    url = crashlog.issue_url(crashlog.tail(1)[0])
    assert url.startswith("https://github.com/gaurjin/omna-plugin/issues/new")
    assert "sk_live" not in url
    assert "RuntimeError" in url
