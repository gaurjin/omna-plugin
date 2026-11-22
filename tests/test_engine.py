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
    # The receipts key (which the L6 fingerprint key comes from) stays on purpose.
    assert "registry-key" not in keychain and set(keychain) <= {"receipts-key"}


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


# ------------------------------------------------- mappings review (#144)
def test_registry_rows_carries_layer_validated_style_and_created(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    rows = s.registry_rows()
    assert len(rows) == 1
    r = rows[0]
    assert r["label"] == "EMAIL_1"
    assert r["kind"] == "EMAIL"
    assert r["value"] == "john.smith@acme.com"
    assert r["layer"] in ("L1", "L2", "L3")  # whichever layer this build's engine used
    assert isinstance(r["validated"], bool)
    assert r["style"] == TOKENS
    assert r["created"]  # non-empty ISO timestamp


def test_registry_rows_records_the_style_actually_used_realistic(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=REALISTIC)
    rows = s.registry_rows()
    assert rows[0]["style"] == REALISTIC
    assert rows[0]["fake"]  # a fake was minted


def test_delete_mapping_removes_the_token_and_the_value_no_longer_restores(home):
    s = MaskingSession()
    r = s.mask_text("email john.smith@acme.com", style=TOKENS)
    assert s.delete_mapping("EMAIL_1") is True
    assert s.registry_rows() == []
    assert s.restore_text(r.masked) == r.masked  # the token is now unrecognised, not restored


def test_delete_mapping_of_a_realistic_row_also_drops_the_fake(home):
    s = MaskingSession()
    r = s.mask_text("email john.smith@acme.com", style=REALISTIC)
    fake = s.registry_rows()[0]["fake"]
    assert fake and fake in r.masked
    assert s.delete_mapping("EMAIL_1") is True
    # the fake must not resolve back to the real value any more
    assert s.restore_text(fake) == fake


def test_delete_mapping_of_an_unknown_label_returns_false(home):
    s = MaskingSession()
    assert s.delete_mapping("EMAIL_99") is False


def test_the_same_real_value_gets_a_brand_new_token_after_delete(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    s.delete_mapping("EMAIL_1")
    r2 = s.mask_text("email john.smith@acme.com", style=TOKENS)
    # counter is NOT reused — the old label must never come back to life
    assert "[EMAIL_" "1]" not in r2.masked
    assert "[EMAIL_" "2]" in r2.masked


def test_delete_mapping_persists_across_a_restart(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    s.delete_mapping("EMAIL_1")
    assert MaskingSession().registry_rows() == []


# The engine reports span positions in UTF-8 BYTES; Python slices by
# CHARACTER. Any character wider than one byte before a value (a dash, an
# emoji, an accented letter, a curly quote) shifted every later mask: on
# 2026-10-24 "Note — ok — fine — yes. Call at maria.lopez@example.org today"
# went out as "... Call at maria.[EMAIL_2]" — part of the real email leaked
# and the word after it was swallowed.
@pytest.mark.parametrize("before", ["Note — ok — fine — yes.", "🙂🙂🙂🙂", "José Müller said “hi”", "日本語のテキスト"])
@pytest.mark.parametrize("style", [TOKENS, REALISTIC])
def test_wide_characters_before_a_value_do_not_shift_the_mask(home, before, style):
    # The real email's names must never be in the fake-name lists: with
    # "maria.lopez" the realistic stand-in was "maria.porter17@…" ~1 run in
    # 10 and this test failed for no reason (MASTER #164).
    from omna_plugin.fakes import FIRST_NAMES, LAST_NAMES
    assert not {"zoltan", "quayle"} & {n.lower() for n in FIRST_NAMES + LAST_NAMES}
    s = MaskingSession()
    text = f"{before} Call at zoltan.quayle@example.org today, key AKIAIOSFODNN7EXAMPLE end."
    r = s.mask_text(text, style)
    assert "zoltan" not in r.masked and "quayle" not in r.masked
    assert "AKIAIOSFODNN7EXAMPLE" not in r.masked
    assert r.masked.startswith(f"{before} Call at ")
    assert r.masked.endswith(" end.") and " today, key " in r.masked
    assert s.restore_text(r.masked) == text


def test_an_omna_stand_in_is_never_masked_again(home, monkeypatch):
    """#11 (client test 2026-11-21): Omna for Chrome sent "[EMAIL_1]"; the smart
    model read "EMAIL_1" as a name and the curl command sent "[[PERSON_72]]"."""
    from omna_plugin import smart as smart_models
    text = "My email is " + "[EMAIL" + "_1] and my phone is " + "[PHONE" + "_1]"
    i = text.index("EMAIL")
    fake = {"spans": [{"start": i, "end": i + 7, "entity": "PERSON", "layer": "L3", "token": "[PERSON" + "_1]"}], "audit": []}
    monkeypatch.setattr(smart_models, "mask", lambda t, s, r=None: fake if t == text else {"spans": [], "audit": []})
    from omna_plugin.engine import from_extension
    with from_extension():                                  # the request Omna for Chrome labelled
        r = MaskingSession().mask_text(text)
    assert r.masked == text and not r.counts


def test_this_macs_home_folder_is_never_masked(home, monkeypatch):
    """#16 (client test 2026-11-21): inside a long conversation the smart model
    read part of a path under the person's home folder as a value; the path
    went out as /[DIGITAL_n]/… and the agent's commands on it failed."""
    from pathlib import Path
    from omna_plugin import smart as smart_models
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/Users/priyar")))
    text = "open /Users/priyar/Developer/app/main.py and mail ana" + "@acme-mail.com"
    i = text.index("Users/priyar")
    j = text.index("ana" + "@")
    fake = {"spans": [{"start": i, "end": i + len("Users/priyar"), "entity": "DIGITAL", "layer": "L3", "token": "[DIGITAL" + "_1]"},
                      {"start": j, "end": len(text), "entity": "EMAIL", "layer": "L1", "token": "[EMAIL" + "_1]"}],
            "audit": []}
    monkeypatch.setattr(smart_models, "mask", lambda t, sm, r=None: fake if t == text else {"spans": [], "audit": []})
    r = MaskingSession().mask_text(text)
    assert "/Users/priyar/Developer/app/main.py" in r.masked
    assert "ana" + "@acme-mail.com" not in r.masked              # a real value next to it is still masked


def test_wi_fi_is_not_a_persons_name(home):
    r = MaskingSession().mask_text("the Wi" + "-Fi network is on and Wi" + "-Fi is fast")
    assert "Wi-Fi" in r.masked and not r.counts


def test_a_real_value_shaped_like_a_stand_in_is_still_masked(home, monkeypatch):
    """Checker finding (2026-11-21): "[SSN_123456789]" looks like a stand-in
    but Omna never issued it — the value inside must still be masked. And a
    secret (L2) touching a real stand-in is never skipped."""
    from omna_plugin import smart as smart_models
    text = "my ssn: [SSN_" + "123456789] and key ghp_" + "[EMAIL_1]abcdefghijklmnopqrstuvwxyz0123"
    i = text.index("123456789")
    j = text.index("ghp_")
    fake = {"spans": [{"start": i, "end": i + 9, "entity": "SSN", "layer": "L1", "token": "[SSN" + "_1]"},
                      {"start": j, "end": len(text), "entity": "GITHUB_TOKEN", "layer": "L2", "token": "[SECRET_GITHUB_TOKEN" + "_1]"}],
            "audit": []}
    monkeypatch.setattr(smart_models, "mask", lambda t, sm, r=None: fake if t == text else {"spans": [], "audit": []})
    s = MaskingSession()
    s._token_to_value["[EMAIL" + "_1]"] = "x@y.com"         # a stand-in Omna really issued
    r = s.mask_text(text)
    assert "123456789" not in r.masked and "abcdefghijklmnopqrstuvwxyz0123" not in r.masked


def test_a_value_in_a_home_folder_path_is_still_masked(home, monkeypatch):
    """Checker finding 2026-11-21: grep output like <home>/app/.env:3:ADMIN_EMAIL=<email>
    sent the email unmasked. Only the home folder's own name is spared."""
    from pathlib import Path
    from omna_plugin import smart as smart_models
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/Users/priyar")))
    em = "ana" + "@acme-mail.com"
    text = "/Users/priyar/app/.env:3:ADMIN_EMAIL=" + em
    j = text.index(em)
    fake = {"spans": [{"start": j, "end": j + len(em), "entity": "EMAIL", "layer": "L1", "token": "[EMAIL" + "_1]"}], "audit": []}
    monkeypatch.setattr(smart_models, "mask", lambda t, sm, r=None: fake if t == text else {"spans": [], "audit": []})
    r = MaskingSession().mask_text(text)
    assert em not in r.masked


def test_a_plain_path_under_home_is_not_a_personal_url(home, monkeypatch):
    from pathlib import Path
    from omna_plugin import smart as smart_models
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/Users/priyar")))
    text = "The file is /Users/priyar/.claude/settings.json now"
    i = text.index("/Users")
    j = i + len("/Users/priyar/.claude/settings.json")
    fake = {"spans": [{"start": i, "end": j, "entity": "PERSONAL_URL", "layer": "L3", "token": "[PERSONAL_URL" + "_1]"}], "audit": []}
    monkeypatch.setattr(smart_models, "mask", lambda t, sm, r=None: fake if t == text else {"spans": [], "audit": []})
    assert MaskingSession().mask_text(text).masked == text
    # but the same catch with a value in it is kept
    text2 = "/Users/priyar/app/.env:3:EMAIL=ana" + "@acme-mail.com"
    fake2 = {"spans": [{"start": 0, "end": len(text2), "entity": "PERSONAL_URL", "layer": "L3", "token": "[PERSONAL_URL" + "_1]"}], "audit": []}
    monkeypatch.setattr(smart_models, "mask", lambda t, sm, r=None: fake2 if t == text2 else {"spans": [], "audit": []})
    assert "acme-mail" not in MaskingSession().mask_text(text2).masked


def _one_catch(monkeypatch, text, a, b, entity, layer="L3"):
    from omna_plugin import smart as smart_models
    fake = {"spans": [{"start": a, "end": b, "entity": entity, "layer": layer, "token": "[" + entity + "_1]"}], "audit": []}
    monkeypatch.setattr(smart_models, "mask", lambda t, sm, r=None: fake if t == text else {"spans": [], "audit": []})
    return MaskingSession().mask_text(text).masked


def test_a_catch_in_the_middle_of_a_home_path_is_not_a_value(home, monkeypatch):
    # Gate G13 (#30): the compact model caught only "plugin/smart.py", the END
    # of a path under the home folder (a folder name with a space before it).
    from pathlib import Path
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/Users/priyar")))
    text = "then open /Users/priyar/Developer/Omna Labs/omna-plugin/src/omna_plugin/smart.py and run it"
    a = text.index("plugin/smart.py")
    assert _one_catch(monkeypatch, text, a, a + len("plugin/smart.py"), "PERSONAL_URL") == text


def test_a_value_after_a_home_path_is_still_masked(home, monkeypatch):
    from pathlib import Path
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/Users/priyar")))
    # a name as its own word after the path: not inside the path
    t1 = "see /Users/priyar/notes.txt Maria Lopez said so"
    a = t1.index("Maria")
    assert "Maria" not in _one_catch(monkeypatch, t1, a, a + len("Maria Lopez"), "PERSON")
    # grep output: a value after ":" is not part of the path
    t2 = "/Users/priyar/app/.env:3:OWNER=maria_lopez"
    a = t2.index("maria_lopez")
    assert "maria_lopez" not in _one_catch(monkeypatch, t2, a, len(t2), "PERSON")
    # a long number inside the caught piece stays masked
    t3 = "/Users/priyar/clients/acct_48213377/file.txt"
    a = t3.index("acct_")
    assert "48213377" not in _one_catch(monkeypatch, t3, a, a + len("acct_48213377"), "FINANCIAL")
    # a secret (L2) is never dropped for the path
    t4 = "/Users/priyar/keys/sk_live_abcdefghijklmnop"
    a = t4.index("sk_live")
    assert "sk_live" not in _one_catch(monkeypatch, t4, a, len(t4), "SECRET", layer="L2")


def test_our_company_name_is_never_masked(home, monkeypatch):
    # #31 (owner 2026-11-22: "never mask Omna in any case"): the compact model
    # calls "Omna" a PERSON in the owner's own messages.
    for word in ("Omna", "OMNA", "omna", "Omna's", "Omna Labs", "Omna for Chrome", "Omna Plugin",
                 "omna.dev", "omna.dev/admin/dashboard", "https://omna.dev/cli/install.sh"):
        text = f"Open {word}, then ship."
        a = text.index(word)
        for kind in ("PERSON", "ORGANIZATION", "ADDRESS", "PERSONAL_URL", "DIGITAL_ID"):
            assert _one_catch(monkeypatch, text, a, a + len(word), kind) == text, (word, kind)


def test_a_catch_with_more_than_our_name_stays_masked(home, monkeypatch):
    # Only a catch made of our name alone is spared — never a person, an email
    # at our domain, a secret, or a web address carrying values.
    cases = [("Omna Tiwari joined the call.", "Omna Tiwari", "PERSON"),
             ("Kiji Watanabe called.", "Kiji Watanabe", "PERSON"),
             ("mail ana" + "@omna.dev today", "ana" + "@omna.dev", "EMAIL"),
             ("go to omna.dev/r?email=ana" + "@x.com now", "omna.dev/r?email=ana" + "@x.com", "PERSONAL_URL"),
             ("key omna_" + "sk_live_51HxQ2aBcD9eF now", "omna_" + "sk_live_51HxQ2aBcD9eF", "SECRET")]
    for text, value, kind in cases:
        a = text.index(value)
        layer = "L2" if kind == "SECRET" else "L3"
        assert value not in _one_catch(monkeypatch, text, a, a + len(value), kind, layer=layer), text


def test_checker_leaks_of_the_our_name_rule_stay_masked(home, monkeypatch):
    # Fresh checker 2026-11-22 on 30a0559: our website rule let any omna.dev
    # path through (a name in it, a reset code), any kind of catch was dropped,
    # names in other alphabets were invisible, and web domains as folder names
    # under the home folder were dropped.
    from pathlib import Path
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/Users/priyar")))
    cases = [
        ("see https://omna.dev/u/john-smith now", "https://omna.dev/u/john-smith", "PERSONAL_URL"),
        ("reset at omna.dev/reset/9f8a7b6c5d4e3f2a1b0c now", "omna.dev/reset/9f8a7b6c5d4e3f2a1b0c", "PERSONAL_URL"),
        ("pay omna.dev/4111111111111111 now", "omna.dev/4111111111111111", "CREDIT_CARD"),
        ("call Omna \u674e\u660e today", "Omna \u674e\u660e", "PERSON"),
        ("hi \u0930\u093e\u0939\u0941\u0932 Omna today", "\u0930\u093e\u0939\u0941\u0932 Omna", "PERSON"),
        ("Omna \u0410\u043d\u043d\u0430 joined", "Omna \u0410\u043d\u043d\u0430", "PERSON"),
        ("pw Omna-For-Chrome-S ok", "Omna-For-Chrome-S", "PASSWORD"),
        ("mail omna" + "@labs ok", "omna" + "@labs", "EMAIL"),
        ("ls /Users/priyar/Sites/johnsmith.com", "johnsmith.com", "PERSONAL_URL"),
        ("ls /Users/priyar/mail/john.smith-gmail.com", "john.smith-gmail.com", "PERSONAL_URL"),
    ]
    for text, value, kind in cases:
        a = len(text[:text.index(value)].encode())      # the engine speaks UTF-8 byte offsets
        assert value not in _one_catch(monkeypatch, text, a, a + len(value.encode()), kind), (text, kind)
    # our real pages stay readable
    for page in ("omna.dev", "https://omna.dev/sample-report", "omna.dev/admin/dashboard", "omna.dev/cli/install.sh"):
        text = f"open {page} now"
        a = text.index(page)
        assert _one_catch(monkeypatch, text, a, a + len(page), "PERSONAL_URL") == text, page


def test_checker_leaks_after_a_home_path_stay_masked(home, monkeypatch):
    # Fresh checker 2026-11-21 on the first G13 fix: the walk back to the home
    # folder crossed spaces into ordinary words, and dropped IP, MAC and names.
    from pathlib import Path
    monkeypatch.setattr(Path, "home", staticmethod(lambda: Path("/Users/priyar")))
    ip = "10.4.2" + ".17"
    mac = "a4:83:e7:1f:" + "2b:9c"
    cases = [
        ("/Users/priyar/logs/host-" + ip + ".log", ip, "IP_ADDRESS"),
        ("/Users/priyar/vpn/" + ip + "/config.ovpn", ip, "IP_ADDRESS"),
        ("/Users/priyar/dev/" + mac + ".cfg", mac, "DEVICE_ID"),
        ("see /Users/priyar/logs and host-" + ip + " was the attacker", ip, "IP_ADDRESS"),
        ("/Users/priyar/dev and flash board-" + mac + " today", mac, "DEVICE_ID"),
        ("/Users/priyar/dev then call Lopez/Maria later", "Maria", "PERSON"),
        ("/Users/priyar/dev then call Lopez/Maria later", "Maria", "PERSONAL_URL"),
        ("/Users/priyar/notes/linkedin.com/in/maria-lopez", "linkedin.com/in/maria-lopez", "PERSONAL_URL"),
    ]
    for text, value, kind in cases:
        a = text.index(value)
        assert value not in _one_catch(monkeypatch, text, a, a + len(value), kind), (text, kind)


