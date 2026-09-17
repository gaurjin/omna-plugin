import json

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


def test_receipt_never_contains_values(home):
    rec = receipts.append({"route": "/v1/messages", "masked": {"EMAIL": 1}, "bytes_in": 120})
    assert "@" not in json.dumps(rec)
    assert set(rec) >= {"ts", "prev", "hash", "route", "masked", "bytes_in"}
