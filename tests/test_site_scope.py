"""Real values go back only to the site they were sent to (MASTER #179b, owner "A").

A site's own page already sees everything typed into it, so putting a value
back there tells it nothing new. Putting it into a DIFFERENT site's reply —
or putting a value Claude Code sent into any website — would.
"""

import json

import pytest

from omna_plugin.engine import MaskingSession
from omna_plugin.style import REALISTIC

EMAIL = "jane.doe@example.com"
KEY = "AKIA" + "IOSFODNN7EXAMPLE"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def _token(s: MaskingSession, text: str, site: str | None, **kw) -> str:
    if site is None:
        r = s.mask_text(text, **kw)
    else:
        with s.sending_to(site):
            r = s.mask_text(text, **kw)
    return r.masked


def test_a_value_comes_back_only_on_the_site_it_was_sent_to(home):
    s = MaskingSession()
    masked = _token(s, f"mail {EMAIL}", "ChatGPT")
    assert EMAIL not in masked
    assert EMAIL in s.for_site("ChatGPT").restore_text(masked)
    assert s.for_site("Claude").restore_text(masked) == masked


def test_a_value_claude_code_sent_never_comes_back_in_a_website(home):
    s = MaskingSession()
    masked = _token(s, f"mail {EMAIL}", None)          # the API door: no site
    assert s.for_site("Claude").restore_text(masked) == masked
    assert EMAIL in s.restore_text(masked)              # the API door's own (request-scoped) restore is separate


def test_the_same_value_sent_to_two_sites_comes_back_on_both(home):
    s = MaskingSession()
    a = _token(s, f"mail {EMAIL}", "ChatGPT")
    b = _token(s, f"mail {EMAIL}", "Claude")            # cache hit: the site is still recorded
    assert a == b
    assert EMAIL in s.for_site("ChatGPT").restore_text(a)
    assert EMAIL in s.for_site("Claude").restore_text(a)
    assert s.for_site("Gemini").restore_text(a) == a


def test_the_record_survives_a_restart(home):
    masked = _token(MaskingSession(), f"mail {EMAIL}", "ChatGPT")
    s = MaskingSession()
    assert EMAIL in s.for_site("ChatGPT").restore_text(masked)
    assert s.for_site("Claude").restore_text(masked) == masked


def test_values_saved_before_the_change_keep_working_everywhere(home):
    """Owner's choice "A", point 5: old chats must not fill up with tokens."""
    (home / "registry.json").write_text(json.dumps({
        "tokens": {"[EMAIL_1]": EMAIL}, "counters": {"EMAIL": 1}, "fakes": {}, "fake_salt": "", "meta": {}}))
    s = MaskingSession()
    assert EMAIL in s.for_site("Claude").restore_text("[EMAIL_1]")
    assert EMAIL in s.for_site("Grok").restore_text("[EMAIL_1]")
    # Sending it to one site later does not take "everywhere" away.
    _token(s, f"mail {EMAIL}", "ChatGPT")
    assert EMAIL in MaskingSession().for_site("Grok").restore_text("[EMAIL_1]")


def test_a_new_value_next_to_old_ones_is_scoped(home):
    (home / "registry.json").write_text(json.dumps({
        "tokens": {"[EMAIL_1]": EMAIL}, "counters": {"EMAIL": 1}, "fakes": {}, "fake_salt": "", "meta": {}}))
    s = MaskingSession()
    masked = _token(s, "mail bob.stone@example.org", "ChatGPT")
    assert "[EMAIL_2]" in masked
    assert s.for_site("Claude").restore_text(masked) == masked


def test_a_realistic_fake_is_scoped_the_same_way(home):
    s = MaskingSession()
    masked = _token(s, f"mail {EMAIL}", "ChatGPT", style=REALISTIC)
    assert EMAIL not in masked and "[" not in masked
    assert EMAIL in s.for_site("ChatGPT").restore_text(masked)
    assert s.for_site("Claude").restore_text(masked) == masked


def test_a_secret_is_scoped_the_same_way(home):
    s = MaskingSession()
    masked = _token(s, f"key {KEY}", "ChatGPT")
    assert KEY not in masked
    assert KEY in s.for_site("ChatGPT").restore_text(masked)
    assert s.for_site("Claude").restore_text(masked) == masked


def test_forgetting_a_mapping_forgets_its_sites(home):
    s = MaskingSession()
    masked = _token(s, f"mail {EMAIL}", "ChatGPT")
    assert s.delete_mapping("EMAIL_1")
    masked2 = _token(s, f"mail {EMAIL}", None)
    assert s.for_site("ChatGPT").restore_text(masked2) == masked2
