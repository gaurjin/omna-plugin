"""At-rest protection for the token registry.

These tests never touch the real macOS Keychain: `conftest.py` forces
`OMNA_REGISTRY_ENCRYPTION=off` for the whole suite, and the tests that need a
working key swap in the in-memory fake below.
"""

import json

import pytest

from omna_plugin import vault


@pytest.fixture
def fake_keychain(monkeypatch):
    """A working Keychain that lives in a dict instead of on the real machine."""
    store: dict[str, str] = {}
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION", raising=False)
    monkeypatch.setattr(vault, "_kc_supported", lambda: True)
    monkeypatch.setattr(vault, "_kc_read", lambda account: store.get(account))
    monkeypatch.setattr(vault, "_kc_write", lambda account, value: store.__setitem__(account, value))
    monkeypatch.setattr(vault, "_kc_delete", lambda account: store.pop(account, None) is not None)
    return store


# ---------------------------------------------------------------- the envelope
def test_seal_hides_the_value_and_open_gets_it_back():
    key = vault.new_key()
    blob = vault.seal({"tokens": {"x": "jane.doe@example.com"}}, key)
    assert "jane.doe@example.com" not in blob
    assert json.loads(blob)["enc"] == vault.ALGORITHM
    assert vault.open_sealed(blob, key) == {"tokens": {"x": "jane.doe@example.com"}}


def test_a_different_key_cannot_open_it():
    blob = vault.seal({"tokens": {}}, vault.new_key())
    with pytest.raises(vault.RegistryLocked):
        vault.open_sealed(blob, vault.new_key())


def test_no_key_cannot_open_it():
    blob = vault.seal({"tokens": {}}, vault.new_key())
    with pytest.raises(vault.RegistryLocked):
        vault.open_sealed(blob, None)


def test_tampering_with_the_file_is_detected():
    key = vault.new_key()
    env = json.loads(vault.seal({"tokens": {"a": "b"}}, key))
    # Flip one character of the ciphertext. AES-GCM authenticates, so this must
    # fail loudly rather than return garbage that we would then write back.
    env["ct"] = ("A" if env["ct"][0] != "A" else "B") + env["ct"][1:]
    with pytest.raises(vault.RegistryLocked):
        vault.open_sealed(json.dumps(env), key)


def test_two_seals_of_the_same_data_differ():
    key = vault.new_key()
    a = vault.seal({"tokens": {"a": "b"}}, key)
    b = vault.seal({"tokens": {"a": "b"}}, key)
    assert a != b  # fresh nonce every write


# ------------------------------------------------------------------ file state
def test_file_state_reads_the_header_without_a_key(tmp_path):
    missing = tmp_path / "nope.json"
    assert vault.file_state(missing) == "missing"

    plain = tmp_path / "plain.json"
    plain.write_text(json.dumps({"tokens": {}, "counters": {}}))
    assert vault.file_state(plain) == "plaintext"

    enc = tmp_path / "enc.json"
    enc.write_text(vault.seal({"tokens": {}}, vault.new_key()))
    assert vault.file_state(enc) == "encrypted"


def test_unreadable_file_is_not_called_encrypted(tmp_path):
    p = tmp_path / "junk.json"
    p.write_text("not json at all")
    assert vault.file_state(p) == "plaintext"


# --------------------------------------------------------------------- the key
def test_key_is_created_once_and_reused(fake_keychain):
    k1 = vault.load_key(create=True)
    k2 = vault.load_key(create=True)
    assert k1 is not None and k1 == k2
    assert len(k1) == 32


def test_load_key_without_create_returns_nothing_when_there_is_none(fake_keychain):
    assert vault.load_key(create=False) is None
    vault.load_key(create=True)
    assert vault.load_key(create=False) is not None


def test_delete_key_removes_it(fake_keychain):
    vault.load_key(create=True)
    assert vault.delete_key() is True
    assert vault.load_key(create=False) is None


def test_encryption_off_never_touches_the_keychain(fake_keychain, monkeypatch):
    monkeypatch.setenv("OMNA_REGISTRY_ENCRYPTION", "off")
    assert vault.keychain_supported() is False
    assert vault.load_key(create=True) is None
    assert fake_keychain == {}


def test_a_corrupt_stored_key_is_treated_as_no_key(fake_keychain):
    vault._kc_write(vault.ACCOUNT, "this is not base64 at all !!!")
    assert vault.load_key(create=False) is None


def test_delete_key_also_honours_the_off_switch(monkeypatch):
    """With encryption off, NOTHING in here may reach the real Keychain.

    `delete_key` is the easy one to forget, because "clean up a stray key"
    sounds unconditional — but an unguarded version means a test run or a CI
    job deletes the developer's own key from their own login keychain.
    conftest.py has already set OMNA_REGISTRY_ENCRYPTION=off for this test.
    """
    called: list[str] = []
    monkeypatch.setattr(vault, "_kc_supported", lambda: True)
    monkeypatch.setattr(vault, "_kc_delete", lambda a: called.append(a) or True)
    assert vault.delete_key() is False
    assert called == []
