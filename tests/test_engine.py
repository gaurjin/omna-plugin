import json

import pytest

from omna_plugin.engine import MaskingSession, TOKEN_RE

# Built at runtime so secret scanners (GitHub push protection) do not flag a fake key.
FAKE_STRIPE = "sk_live_" + "51H8xk2KJ3mN4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0u"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def test_secret_is_numbered_restorable_in_memory_and_never_on_disk(home):
    s = MaskingSession()
    r = s.mask_text("key AKIAIOSFODNN7EXAMPLE here")
    assert "AKIAIOSFODNN7EXAMPLE" not in r.masked
    assert "[SECRET_AWS_KEY_1]" in r.masked
    assert s.restore_text(r.masked) == "key AKIAIOSFODNN7EXAMPLE here"
    assert r.counts == {"AWS_KEY": 1}
    assert "AKIAIOSFODNN7EXAMPLE" not in (home / "registry.json").read_text() if (home / "registry.json").exists() else True
    # a new session (proxy restart) does not know the secret any more
    assert MaskingSession().restore_text("[SECRET_AWS_KEY_1]") == "[SECRET_AWS_KEY_1]"


def test_no_restore_secrets_keeps_engine_redaction(home):
    s = MaskingSession(restore_secrets=False)
    r = s.mask_text("key AKIAIOSFODNN7EXAMPLE here")
    assert "[REDACTED:AWS_KEY]" in r.masked
    assert s.restore_text(r.masked) == r.masked


def test_secret_span_keeps_its_newline(home):
    s = MaskingSession()
    text = "1\tDB_HOST=db.internal\n2\tSTRIPE_SECRET_KEY=" + FAKE_STRIPE + "\n3\tREGION=us-east-1\n"
    r = s.mask_text(text)
    assert "sk_live" not in r.masked
    assert r.masked.count("\n") == text.count("\n")
    assert "\n3\tREGION" in r.masked
    assert s.restore_text(r.masked) == text


def test_loopback_addresses_are_not_masked_by_default(home):
    s = MaskingSession()
    assert s.mask_text("listening on 127.0.0.1:7788 and 0.0.0.0:80").masked == "listening on 127.0.0.1:7788 and 0.0.0.0:80"


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
    assert data["allowlist"][-1] == "a@example\\.com"


def test_cache_returns_identical_result(home):
    s = MaskingSession()
    text = "Email john.smith@acme.com and key AKIAIOSFODNN7EXAMPLE"
    a = s.mask_text(text)
    b = s.mask_text(text)
    assert a.masked == b.masked and a.counts == b.counts
    assert s.cache_hits == 1


def test_assignment_keeps_the_name_outside_the_secret_token(home):
    s = MaskingSession()
    text = "DB_HOST=db.internal\nSTRIPE_SECRET_KEY=" + FAKE_STRIPE + "\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    r = s.mask_text(text)
    assert "STRIPE_SECRET_KEY=[SECRET_" in r.masked
    assert "AWS_ACCESS_KEY_ID=[SECRET_" in r.masked
    assert "sk_live" not in r.masked and "AKIA" not in r.masked
    assert s.restore_text(r.masked) == text
    assert r.secrets == 2 and r.pii == 0
