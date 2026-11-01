import json
import threading

import pytest

from omna_plugin import receipts


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def test_append_chains_and_verifies(home):
    a = receipts.append({"route": "/v1/messages", "masked": {"EMAIL": 2}})
    b = receipts.append({"route": "/v1/messages", "masked": {"AWS_KEY": 1}})
    assert a["prev"] == receipts.GENESIS
    assert b["prev"] == a["hash"]
    ok, n, msg = receipts.verify()
    assert ok and n == 2
    assert receipts.count() == 2
    assert receipts.summary(receipts.tail(10)) == {"EMAIL": 2, "AWS_KEY": 1}


def test_tampering_breaks_the_chain(home):
    receipts.append({"masked": {"EMAIL": 2}})
    receipts.append({"masked": {"EMAIL": 1}})
    receipts.append({"masked": {}})
    p = home / "receipts.jsonl"
    lines = p.read_text().splitlines()
    rec = json.loads(lines[1])
    rec["masked"] = {"EMAIL": 0}
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    p.write_text("\n".join(lines) + "\n")
    ok, n, msg = receipts.verify()
    assert not ok and n == 2 and "hash" in msg


def test_concurrent_appends_do_not_fork_the_chain(home):
    # The API door and the system door run on separate OS threads sharing one
    # Pipeline (daemon.py); both can call append() at once.
    n = 40
    barrier = threading.Barrier(n)

    def go(i):
        barrier.wait()
        receipts.append({"route": f"/t{i}", "masked": {}})

    threads = [threading.Thread(target=go, args=(i,)) for i in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    ok, count, msg = receipts.verify()
    assert ok, msg
    assert count == n


def test_receipt_never_contains_values(home):
    rec = receipts.append({"route": "/v1/messages", "masked": {"EMAIL": 1}, "bytes_in": 120})
    assert "@" not in json.dumps(rec)
    assert set(rec) >= {"ts", "prev", "hash", "route", "masked", "bytes_in"}


# ------------------------------------------------- receipts at rest (#132 follow-on)
@pytest.fixture
def receipt_keychain(monkeypatch):
    """A working Keychain in a dict — never this machine's real one."""
    from omna_plugin import vault

    store: dict[str, str] = {}
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION", raising=False)
    monkeypatch.setattr(vault, "_kc_supported", lambda: True)
    monkeypatch.setattr(vault, "_kc_read", lambda a: store.get(a))
    monkeypatch.setattr(vault, "_kc_write", lambda a, v: store.__setitem__(a, v))
    monkeypatch.setattr(vault, "_kc_delete", lambda a: store.pop(a, None) is not None)
    return store


def test_receipts_are_encrypted_on_disk_but_readable_through_the_api(home, receipt_keychain):
    receipts.append({"route": "/v1/messages", "host": "api.anthropic.com",
                     "app": "Claude Code", "masked": {"EMAIL": 2}})
    blob = (home / "receipts.jsonl").read_text()
    # the metadata that says what you use is not sitting there in the clear
    assert "api.anthropic.com" not in blob
    assert "Claude Code" not in blob
    assert "/v1/messages" not in blob
    # ...but the app reads it back perfectly
    rows = receipts.tail(5)
    assert rows[0]["host"] == "api.anthropic.com" and rows[0]["app"] == "Claude Code"


def test_the_hash_chain_still_verifies_when_encrypted(home, receipt_keychain):
    for i in range(4):
        receipts.append({"route": f"/v1/{i}", "masked": {"EMAIL": i}})
    ok, n, msg = receipts.verify()
    assert ok and n == 4, msg


def test_receipts_use_their_own_key_so_omna_forget_cannot_blind_them(home, receipt_keychain):
    from omna_plugin import vault

    receipts.append({"route": "/v1/messages"})
    assert vault.ACCOUNT != vault.RECEIPTS_ACCOUNT
    # `omna forget` deletes the REGISTRY key only
    vault.delete_key(vault.ACCOUNT)
    assert receipts.tail(5)[0]["route"] == "/v1/messages", "receipts must survive `omna forget`"


def test_an_old_plaintext_file_still_reads_and_verifies(home, receipt_keychain, monkeypatch):
    # Written by a build that predates encryption...
    monkeypatch.setenv("OMNA_REGISTRY_ENCRYPTION", "off")
    receipts.append({"route": "/v1/old", "masked": {"EMAIL": 1}})
    assert "/v1/old" in (home / "receipts.jsonl").read_text()

    # ...and now the Keychain is available. Old lines keep working, new ones seal.
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION", raising=False)
    receipts.append({"route": "/v1/new"})
    rows = receipts.tail(5)
    assert [r["route"] for r in rows] == ["/v1/old", "/v1/new"]
    ok, n, msg = receipts.verify()
    assert ok and n == 2, msg


def test_a_sealed_line_we_cannot_open_is_reported_not_skipped(home, receipt_keychain):
    """A receipt you cannot read is as bad as one that was tampered with, so it
    must break verify() rather than quietly vanish from the count."""
    receipts.append({"route": "/v1/messages"})
    receipt_keychain.clear()          # key gone
    ok, n, msg = receipts.verify()
    assert ok is False
    assert n == 1, "the unreadable line must still be counted, not skipped"
    assert "not valid JSON" in msg


# ------------------------------------------------- cost of one receipt (MASTER #178)
def test_a_new_receipt_does_not_reread_the_whole_log(home, receipt_keychain, monkeypatch):
    """Each receipt decrypted EVERY earlier line to find the last hash, and
    asked the Keychain for the key each time: the curl command got slower
    with every request it had ever handled (architecture review)."""
    from omna_plugin import vault

    for i in range(50):
        receipts.append({"route": "/v1/messages", "masked": {"EMAIL": i}})
    opened = []
    real_open = vault.open_sealed
    monkeypatch.setattr(vault, "open_sealed", lambda t, k: opened.append(1) or real_open(t, k))
    looked_up = []
    real_load = vault.load_key
    monkeypatch.setattr(vault, "load_key", lambda *a, **kw: looked_up.append(1) or real_load(*a, **kw))
    for i in range(10):
        receipts.append({"route": "/v1/messages", "masked": {"EMAIL": i}})
    assert len(opened) <= 10, f"{len(opened)} lines decrypted for 10 receipts"
    assert len(looked_up) <= 1, f"{len(looked_up)} Keychain look-ups for 10 receipts"
    monkeypatch.setattr(vault, "open_sealed", real_open)
    assert receipts.verify()[:2] == (True, 60)


def test_a_receipt_written_by_another_program_still_chains(home):
    receipts.append({"route": "a"})
    path = receipts.config.receipts_path()
    # another program appends a line (its own process: no shared memory)
    other = dict(receipts.tail(1)[0])
    rec = {"route": "b", "ts": "x", "prev": other["hash"]}
    rec["hash"] = receipts._hash(rec["prev"], rec)
    with open(path, "a") as f:
        f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
    receipts.append({"route": "c"})
    assert receipts.verify() == (True, 3, "chain intact")


# ---------------------------------------------------------------- format 1 (#184)

def test_shared_vectors_hash_the_same_in_every_product():
    """The same file is in Omna for Chrome's tests: both products must write
    these exact bytes and seals, or one report could not check the other."""
    from pathlib import Path
    doc = json.loads((Path(__file__).parent / "fixtures" / "record_vectors.json").read_text())
    prev = doc["genesis"]
    for item in doc["chain"]:
        rec = item["record"]
        assert rec["prev"] == prev
        assert receipts._canonical(rec) == item["canonical"]
        assert receipts._hash(prev, rec) == item["hash"]
        prev = item["hash"]


def test_finds_group_l6_events_and_never_carry_a_value():
    events = [
        {"entity": "EMAIL", "layer": "L1", "risk": "direct_identifier", "action": "tokenized",
         "confidence": 0.6, "span_hash": "aaaaaaaaaaaaaaaa"},
        {"entity": "EMAIL", "layer": "L1", "risk": "direct_identifier", "action": "tokenized",
         "confidence": 0.6, "span_hash": "aaaaaaaaaaaaaaaa"},
        {"entity": "AWS_KEY", "layer": "L2", "risk": "secret", "action": "redacted",
         "confidence": 0.9, "span_hash": "bbbbbbbbbbbbbbbb"},
    ]
    finds = receipts.finds_of(events)
    assert finds == [
        {"entity": "AWS_KEY", "layer": "L2", "risk": "secret", "action": "redacted", "n": 1, "fp": ["bbbbbbbbbbbbbbbb"]},
        {"entity": "EMAIL", "layer": "L1", "risk": "direct_identifier", "action": "tokenized", "n": 2, "fp": ["aaaaaaaaaaaaaaaa"]},
    ]
    assert receipts.totals_of(finds) == {"masked": {"AWS_KEY": 1, "EMAIL": 2}, "secrets": 1, "pii": 2,
                                         "by_layer": {"L2": 1, "L1": 2}}
    # Merging two requests' finds adds the counts and keeps fingerprints distinct.
    both = receipts.merge_finds(finds, finds)
    assert [f["n"] for f in both] == [2, 4] and both[1]["fp"] == ["aaaaaaaaaaaaaaaa"]
    # A picture's values are blacked out, whatever the engine would do with text.
    assert {f["action"] for f in receipts.finds_of(events, action="redacted")} == {"redacted"}


def test_fingerprint_key_is_stable_per_computer_and_never_shared(home, tmp_path_factory, monkeypatch):
    a = receipts.fingerprint_key()
    assert len(a) == 32 and receipts.fingerprint_key() == a
    other = tmp_path_factory.mktemp("other-computer")
    monkeypatch.setenv("OMNA_HOME", str(other))
    assert receipts.fingerprint_key() != a


def test_real_masking_fingerprints_are_keyed(home):
    """End to end through the masking engine (omna-pii-mask): the receipt's
    fingerprint is the keyed one, not a plain hash anyone could recompute."""
    import hashlib
    from omna_plugin.engine import MaskingSession
    r = MaskingSession().mask_text("my ssn is 123-45-6789 and mail bob@acme.com")
    fps = [fp for f in r.finds for fp in f["fp"]]
    assert fps and all(len(fp) == 16 for fp in fps)
    for value in ("123-45-6789", "bob@acme.com"):
        assert hashlib.sha256(value.encode()).hexdigest()[:16] not in fps
        assert value not in json.dumps(r.finds)


@pytest.mark.parametrize("bad", [
    None, "x", [{}],
    [{"entity": "EMAIL", "layer": "L1", "risk": "r", "action": "a", "n": 1, "fp": ["notHEX!notHEX!no"]}],
    [{"entity": "EMAIL", "layer": "L1", "risk": "r", "action": "a", "n": 0, "fp": []}],
    [{"entity": "EMAIL", "layer": "L1", "risk": "r", "action": "a", "n": True, "fp": []}],
    [{"entity": "EMAIL", "layer": "L1", "risk": "r", "action": "a", "n": 1, "fp": [], "value": "bob@acme.com"}],
    [{"entity": "", "layer": "L1", "risk": "r", "action": "a", "n": 1, "fp": []}],
])
def test_untrusted_finds_are_refused_unless_exact(bad):
    assert receipts.valid_finds(bad) is None
