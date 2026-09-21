import json

import pytest

from omna_plugin import vault
from omna_plugin.engine import MaskingSession, TOKEN_RE
from omna_plugin.style import REALISTIC, TOKENS

# Built at runtime so secret scanners (GitHub push protection) do not flag a fake key.
FAKE_STRIPE = "sk_live_" + "51H8xk2KJ3mN4oP5qR6sT7uV8wX9yZ0aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0u"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def keychain(monkeypatch):
    """A working Keychain in a dict — never the real machine's. See test_vault.py."""
    store: dict[str, str] = {}
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION", raising=False)
    monkeypatch.setattr(vault, "_kc_supported", lambda: True)
    monkeypatch.setattr(vault, "_kc_read", lambda a: store.get(a))
    monkeypatch.setattr(vault, "_kc_write", lambda a, v: store.__setitem__(a, v))
    monkeypatch.setattr(vault, "_kc_delete", lambda a: store.pop(a, None) is not None)
    return store


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


# ------------------------------------------------------- registry at rest (#131)
def test_registry_holds_no_real_value_when_encrypted(home, keychain):
    s = MaskingSession()
    s.mask_text("Email john.smith@acme.com today")
    text = (home / "registry.json").read_text()
    assert "john.smith@acme.com" not in text
    assert "acme" not in text
    assert vault.file_state(home / "registry.json") == "encrypted"
    assert s.encrypted is True and s.locked is False


def test_encrypted_registry_round_trips_across_sessions(home, keychain):
    s1 = MaskingSession()
    tok = TOKEN_RE.search(s1.mask_text("mail a@example.com").masked).group(0)
    s2 = MaskingSession()
    assert s2.restore_text(tok) == "a@example.com"
    assert TOKEN_RE.search(s2.mask_text("mail a@example.com").masked).group(0) == tok


def test_plaintext_registry_from_an_older_install_is_encrypted_on_first_run(home, monkeypatch, keychain):
    # An install that predates #131: plaintext on disk, real value in the clear.
    monkeypatch.setenv("OMNA_REGISTRY_ENCRYPTION", "off")
    old = MaskingSession()
    tok = TOKEN_RE.search(old.mask_text("mail a@example.com").masked).group(0)
    assert "a@example.com" in (home / "registry.json").read_text()

    # Upgrade: same file, Keychain now available.
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION", raising=False)
    s = MaskingSession()
    assert s.encrypted is True
    assert "a@example.com" not in (home / "registry.json").read_text()
    # and the mappings survived the migration — the token did not renumber
    assert s.restore_text(tok) == "a@example.com"


def test_a_lost_key_retires_the_dead_file_and_starts_fresh(home, keychain):
    """The Keychain WORKS and still cannot open the file: the key is gone for
    good, so the file is unreadable forever. Refusing to save would leave a
    permanently broken masker that renumbers on every restart, so Omna sets the
    dead file aside and starts a new encrypted registry (owner call 2026-09-20).
    """
    s1 = MaskingSession()
    s1.mask_text("mail a@example.com")
    before = (home / "registry.json").read_text()

    keychain.clear()  # key gone: Keychain wiped, restored from another Mac, etc.
    s2 = MaskingSession()
    assert s2.locked is False and s2.encrypted is True
    assert "a@example.com" not in s2.mask_text("mail a@example.com").masked

    # the dead file was kept, not deleted, and not overwritten
    dead = list(home.glob("registry.json.unreadable-*"))
    assert len(dead) == 1 and dead[0].read_text() == before
    # and saving works again, with a brand-new key
    assert (home / "registry.json").read_text() != before
    assert MaskingSession().registry_size == 1


def test_an_unreachable_keychain_locks_instead_of_retiring(home, keychain, monkeypatch):
    """The OTHER case, which must NOT destroy anything: we cannot reach the
    Keychain at all, so the key may be perfectly fine. Wait, do not retire."""
    MaskingSession().mask_text("mail a@example.com")
    before = (home / "registry.json").read_text()

    monkeypatch.setenv("OMNA_REGISTRY_ENCRYPTION", "off")
    s = MaskingSession()
    assert s.locked is True
    assert "a@example.com" not in s.mask_text("mail a@example.com").masked
    assert (home / "registry.json").read_text() == before      # untouched
    assert list(home.glob("registry.json.unreadable-*")) == []  # nothing retired


def test_forget_deletes_both_the_file_and_the_key(home, keychain):
    s = MaskingSession()
    s.mask_text("mail a@example.com")
    assert keychain and (home / "registry.json").exists()
    s.forget()
    assert not (home / "registry.json").exists()
    assert keychain == {}


def test_forget_recovers_a_locked_registry(home, keychain, monkeypatch):
    MaskingSession().mask_text("mail a@example.com")
    keychain.clear()
    monkeypatch.setenv("OMNA_REGISTRY_ENCRYPTION", "off")   # unreachable => locked
    s = MaskingSession()
    assert s.locked is True
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION")
    s.forget()
    assert not (home / "registry.json").exists()
    # A new session after the wipe is healthy again, with a fresh key.
    s2 = MaskingSession()
    assert s2.locked is False and s2.encrypted is True


def test_without_a_keychain_the_registry_stays_plaintext(home):
    # The whole suite runs with OMNA_REGISTRY_ENCRYPTION=off, which is also
    # what Linux/CI/headless looks like: today's behaviour, no crash.
    s = MaskingSession()
    s.mask_text("mail a@example.com")
    assert s.encrypted is False and s.locked is False
    assert "a@example.com" in (home / "registry.json").read_text()


def test_assignment_keeps_the_name_outside_the_secret_token(home):
    s = MaskingSession()
    text = "DB_HOST=db.internal\nSTRIPE_SECRET_KEY=" + FAKE_STRIPE + "\nAWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
    r = s.mask_text(text)
    assert "STRIPE_SECRET_KEY=[SECRET_" in r.masked
    assert "AWS_ACCESS_KEY_ID=[SECRET_" in r.masked
    assert "sk_live" not in r.masked and "AKIA" not in r.masked
    assert s.restore_text(r.masked) == text
    assert r.secrets == 2 and r.pii == 0


# ---------------------------------------------------------------- realistic style

def test_realistic_style_substitutes_a_fake_value_and_restores_it(home):
    s = MaskingSession()
    r = s.mask_text("email jane.doe@acme.com today", style=REALISTIC)
    assert "jane.doe@acme.com" not in r.masked
    assert "[" not in r.masked and "]" not in r.masked
    assert "@example." in r.masked
    assert s.restore_text(r.masked) == "email jane.doe@acme.com today"


def test_the_same_value_gets_the_same_fake_every_time(home):
    """Prompt caching depends on this: a stand-in that changed between turns
    would throw the provider's cache away and confuse the model."""
    s = MaskingSession()
    a = s.mask_text("write to jane.doe@acme.com", style=REALISTIC).masked
    b = s.mask_text("again: jane.doe@acme.com please", style=REALISTIC).masked
    fake = a.split("write to ")[1]
    assert fake in b


def test_a_fake_survives_a_restart_because_it_is_in_the_registry(home):
    s1 = MaskingSession()
    masked = s1.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked
    fake = masked.split("mail ")[1]
    s2 = MaskingSession()
    assert s2.restore_text("wrote to " + fake) == "wrote to jane.doe@acme.com"
    assert s2.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked == masked


def test_a_secret_never_gets_a_fake_value_even_in_realistic_style(home):
    """A fake API key that looks real is the worst possible output: secrets
    stay numbered tokens under every style."""
    s = MaskingSession()
    r = s.mask_text("key AKIAIOSFODNN7EXAMPLE here", style=REALISTIC)
    assert "AKIAIOSFODNN7EXAMPLE" not in r.masked
    assert "[SECRET_AWS_KEY_" "1]" in r.masked
    assert s.restore_text(r.masked) == "key AKIAIOSFODNN7EXAMPLE here"
    reg = home / "registry.json"
    assert not reg.exists() or "AKIA" not in reg.read_text()


def test_a_mixed_text_fakes_the_pii_and_keeps_the_secret_numbered(home):
    s = MaskingSession()
    r = s.mask_text("mail jane.doe@acme.com key AKIAIOSFODNN7EXAMPLE", style=REALISTIC)
    assert "@example." in r.masked and "[SECRET_AWS_KEY_" in r.masked
    assert s.restore_text(r.masked) == "mail jane.doe@acme.com key AKIAIOSFODNN7EXAMPLE"


def test_a_colliding_fake_is_regenerated(home, monkeypatch):
    """A fake that already appears in the text would make restore corrupt the
    wrong thing, so the generator is asked again with the next attempt."""
    seen = []

    def fake_for(entity, value, *, salt, attempt):
        seen.append(attempt)
        return "taken-value-42" if attempt == 0 else "free-value-99"

    monkeypatch.setattr("omna_plugin.fakes.fake_for", fake_for)
    s = MaskingSession()
    r = s.mask_text("mail jane.doe@acme.com ref taken-value-42", style=REALISTIC)
    assert "free-value-99" in r.masked and "taken-value-42" in r.masked
    assert seen[:2] == [0, 1]
    assert s.restore_text(r.masked) == "mail jane.doe@acme.com ref taken-value-42"


def test_a_fake_that_would_be_someone_elses_real_value_is_regenerated(home, monkeypatch):
    s = MaskingSession()
    s.mask_text("first jane.doe@acme.com", style=TOKENS)   # jane is now a known real value

    attempts = []

    def fake_for(entity, value, *, salt, attempt):
        attempts.append(attempt)
        return "jane.doe@acme.com" if attempt == 0 else "someone.else@example.org"

    monkeypatch.setattr("omna_plugin.fakes.fake_for", fake_for)
    r = s.mask_text("second john.roe@acme.com", style=REALISTIC)
    assert "jane.doe@acme.com" not in r.masked
    assert "someone.else@example.org" in r.masked
    assert attempts[:2] == [0, 1]


def test_a_fake_that_cannot_be_made_unique_falls_back_to_the_loud_token(home, monkeypatch):
    monkeypatch.setattr("omna_plugin.fakes.fake_for",
                        lambda entity, value, *, salt, attempt: value)
    s = MaskingSession()
    r = s.mask_text("mail jane.doe@acme.com", style=REALISTIC)
    assert "jane.doe@acme.com" not in r.masked
    assert TOKEN_RE.search(r.masked), r.masked


def test_labels_are_the_same_under_both_styles(home):
    """Receipts count these, so the audit trail must not change just because
    the output stopped carrying brackets."""
    s = MaskingSession()
    a = s.mask_text("mail jane.doe@acme.com", style=TOKENS)
    b = s.mask_text("mail jane.doe@acme.com", style=REALISTIC)
    assert a.labels == b.labels == ["EMAIL_1"]


def test_the_cache_does_not_hand_one_style_the_other_styles_answer(home):
    s = MaskingSession()
    tokens = s.mask_text("mail jane.doe@acme.com", style=TOKENS).masked
    realistic = s.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked
    assert "[EMAIL_" in tokens and "[EMAIL_" not in realistic


def test_restore_json_escapes_the_real_value_behind_a_fake(home):
    s = MaskingSession()
    s.mask_text("mail jane.doe@acme.com", style=REALISTIC)
    # A real value with characters JSON must escape. Mapped by hand because no
    # detector produces one; the escaping itself is what is under test.
    s._remember_fake("stand-in@example.org", 'Ann "AJ" Jones', "PERSON")
    out = s.restore_text('{"to": "stand-in@example.org"}', json_escape=True)
    assert '\\"AJ\\"' in out


def test_hold_from_finds_a_partial_fake_value(home):
    s = MaskingSession()
    masked = s.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked
    fake = masked.split("mail ")[1]
    assert s.hold_from("hello " + fake[:4]) == len("hello ")
    assert s.hold_from("hello there") == len("hello there")
    assert s.hold_from("done " + fake) == len("done " + fake)


def test_hold_from_still_finds_a_partial_token(home):
    s = MaskingSession()
    assert s.hold_from("hi [EMAI") == 3
    assert s.hold_from("hi there") == 8


def test_forget_wipes_the_fakes_too(home):
    s = MaskingSession()
    masked = s.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked
    fake = masked.split("mail ")[1]
    s.forget()
    assert s.restore_text(fake) == fake
    assert s.hold_from("x " + fake[:3]) == len("x " + fake[:3])


def test_the_fake_salt_is_per_machine_not_a_constant(home, tmp_path, monkeypatch):
    """Without a salt the fake is a pure function of the real value, so anyone
    holding a fake could confirm a guess at the real one by running the same
    function."""
    s1 = MaskingSession()
    a = s1.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked
    other = tmp_path / "other-machine"
    other.mkdir()
    monkeypatch.setenv("OMNA_HOME", str(other))
    s2 = MaskingSession()
    b = s2.mask_text("mail jane.doe@acme.com", style=REALISTIC).masked
    assert a != b


def test_a_complete_fake_is_never_split_by_the_hold_back(home):
    """The bug: a fake can END with the first character of another fake
    ("...@example.com" before one starting with "m"). Holding that character
    back cuts the finished value in two, so neither half is ever recognised and
    the fake reaches the person as if masking had failed."""
    s = MaskingSession()
    s._remember_fake("maria.taylor@example.com", "jane.doe@acme.com", "EMAIL")
    buf = "wrote to maria.taylor@example.com"
    assert s.hold_from(buf) == len(buf)
    assert s.restore_text(buf) == "wrote to jane.doe@acme.com"


def test_a_partial_fake_after_a_complete_one_is_still_held(home):
    s = MaskingSession()
    s._remember_fake("maria.taylor@example.com", "jane.doe@acme.com", "EMAIL")
    buf = "wrote to maria.taylor@example.com and maria.tay"
    assert s.hold_from(buf) == len("wrote to maria.taylor@example.com and ")
