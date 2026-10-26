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
