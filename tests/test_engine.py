import json

import pytest

from omna_plugin.engine import MaskingSession, TOKEN_RE


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def test_secret_is_redacted_and_never_restorable(home):
    s = MaskingSession()
    r = s.mask_text("key AKIAIOSFODNN7EXAMPLE here")
    assert "AKIAIOSFODNN7EXAMPLE" not in r.masked
    assert "[REDACTED:AWS_KEY]" in r.masked
    assert s.restore_text(r.masked) == r.masked  # secrets stay redacted
    assert r.counts == {"AWS_KEY": 1}


def test_pii_round_trips(home):
    s = MaskingSession()
    r = s.mask_text("Email john.smith@acme.com today")
    assert "john.smith@acme.com" not in r.masked
    assert TOKEN_RE.search(r.masked)
    assert s.restore_text("Reply to " + TOKEN_RE.search(r.masked).group(0)) == "Reply to john.smith@acme.com"
    assert r.counts == {"EMAIL": 1}


def test_same_value_same_token_across_calls(home):
    s = MaskingSession()
    a = s.mask_text("contact john.smith@acme.com").masked
    b = s.mask_text("please write to john.smith@acme.com again").masked
    ta = TOKEN_RE.search(a).group(0)
    tb = TOKEN_RE.search(b).group(0)
    assert ta == tb


def test_different_values_get_different_tokens(home):
    s = MaskingSession()
    # Second call introduces a NEW email first, so the engine's per-call numbering
    # ([EMAIL_1]) would collide with the registry's number for the older one.
    first = s.mask_text("a@example.com").masked
    both = s.mask_text("b@example.com and a@example.com").masked
    toks = [m.group(0) for m in TOKEN_RE.finditer(both)]
    assert len(set(toks)) == 2
    assert TOKEN_RE.search(first).group(0) in toks
    assert s.restore_text(both) == "b@example.com and a@example.com"


def test_registry_persists_across_sessions(home):
    s1 = MaskingSession()
    t1 = TOKEN_RE.search(s1.mask_text("mail a@example.com").masked).group(0)
    s2 = MaskingSession()
    t2 = TOKEN_RE.search(s2.mask_text("mail a@example.com").masked).group(0)
    assert t1 == t2
    assert s2.restore_text(t2) == "a@example.com"
    assert (home / "registry.json").exists()


def test_allow_stops_masking_a_value(home):
    s = MaskingSession()
    assert "[" in s.mask_text("mail a@example.com").masked
    s.allow("a@example.com")
    assert s.mask_text("mail a@example.com").masked == "mail a@example.com"
    data = json.loads((home / "ruleset.json").read_text())
    assert data["allowlist"] == ["a@example\\.com"]


def test_cache_returns_identical_result(home):
    s = MaskingSession()
    text = "Email john.smith@acme.com and key AKIAIOSFODNN7EXAMPLE"
    a = s.mask_text(text)
    b = s.mask_text(text)
    assert a.masked == b.masked and a.counts == b.counts
    assert s.cache_hits == 1
