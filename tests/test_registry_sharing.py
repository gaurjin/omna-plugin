"""Two programs share registry.json: the running curl command and a one-off
`omna mask` / `omna forget` in a terminal (architecture review, MASTER #178).
Each used to save only what IT knew, so the other's new tokens were wiped —
and the same [EMAIL_n] could be given to two different people."""

import pytest

from omna_plugin import vault
from omna_plugin.engine import MaskingSession


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def _tok(s, email):
    return s.mask_text(f"mail {email}").masked.split("mail ")[1]


def test_a_token_minted_elsewhere_is_never_reused_or_wiped(home):
    daemon = MaskingSession()
    terminal = MaskingSession()
    a = _tok(daemon, "ann.lee@acme.com")
    b = _tok(terminal, "bob.ray@acme.com")      # the terminal never saw ann's token in memory
    c = _tok(daemon, "cat.fox@acme.com")
    assert len({a, b, c}) == 3, (a, b, c)
    fresh = MaskingSession()
    assert fresh.lookup(a) == "ann.lee@acme.com"
    assert fresh.lookup(b) == "bob.ray@acme.com"
    assert fresh.lookup(c) == "cat.fox@acme.com"
    # ...and the curl command itself can now put back what the terminal minted.
    assert daemon.restore_text(b) == "bob.ray@acme.com"


def test_forget_in_a_terminal_is_not_undone_by_the_running_curl_command(home):
    daemon = MaskingSession()
    a = _tok(daemon, "ann.lee@acme.com")
    MaskingSession().forget()
    _tok(daemon, "cat.fox@acme.com")
    fresh = MaskingSession()
    assert fresh.lookup(a) in (None, "cat.fox@acme.com")
    assert "ann.lee@acme.com" not in {r["value"] for r in fresh.registry_rows()}


def test_sites_from_both_programs_are_kept(home):
    one, two = MaskingSession(), MaskingSession()
    with one.sending_to("ChatGPT"):
        t = _tok(one, "ann.lee@acme.com")
    with two.sending_to("Claude"):
        _tok(two, "ann.lee@acme.com")
    _tok(one, "cat.fox@acme.com")              # one saves again
    fresh = MaskingSession()
    assert fresh.sent_to(t, "ChatGPT") and fresh.sent_to(t, "Claude")


def test_works_with_the_encrypted_registry(home, monkeypatch):
    store: dict[str, str] = {}
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION", raising=False)
    monkeypatch.setattr(vault, "_kc_supported", lambda: True)
    monkeypatch.setattr(vault, "_kc_read", lambda a: store.get(a))
    monkeypatch.setattr(vault, "_kc_write", lambda a, v: store.__setitem__(a, v))
    monkeypatch.setattr(vault, "_kc_delete", lambda a: store.pop(a, None) is not None)
    daemon, terminal = MaskingSession(), MaskingSession()
    a = _tok(daemon, "ann.lee@acme.com")
    b = _tok(terminal, "bob.ray@acme.com")
    assert a != b
    assert MaskingSession().lookup(a) == "ann.lee@acme.com"
