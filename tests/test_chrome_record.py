"""Omna for Chrome's records join the curl command's chain (MASTER #184).

POST /omna/record: extension only, every field checked exactly, written in
the one record format (receipts.py) as product "chrome", door "chrome".
"""

from __future__ import annotations

import httpx
import pytest

from omna_plugin import receipts
from omna_plugin.engine import MaskingSession
from omna_plugin.proxy import create_app

from tests.ext_helpers import EXT
FINDS = [{"entity": "EMAIL", "layer": "L1", "risk": "direct_identifier", "action": "tokenized",
          "n": 2, "fp": ["0123456789abcdef"]}]


@pytest.fixture
def c(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    app = create_app(MaskingSession())
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")


@pytest.mark.anyio
async def test_only_the_extension_may_record(c):
    r = await c.post("/omna/record", json={"kind": "typed", "site": "claude.ai", "finds": FINDS})
    assert r.status_code == 403
    assert receipts.count() == 0


@pytest.mark.anyio
async def test_a_chrome_record_joins_the_chain(c):
    receipts.append({"route": "/v1/messages", "masked": {}})          # a curl command receipt first
    r = await c.post("/omna/record", auth=EXT,
                     json={"kind": "file", "site": "chatgpt.com", "finds": FINDS, "engine": "0.2.19+abc"})
    assert r.status_code == 200 and r.json() == {"ok": True, "kept": True}
    rec = receipts.tail(1)[0]
    assert rec["product"] == "chrome" and rec["door"] == "chrome" and rec["upstream"] == "chatgpt.com"
    assert rec["v"] == 1 and rec["kind"] == "file" and rec["finds"] == FINDS
    assert rec["masked"] == {"EMAIL": 2} and rec["pii"] == 2 and rec["secrets"] == 0
    ok, n, _ = receipts.verify()
    assert ok and n == 2


@pytest.mark.anyio
@pytest.mark.parametrize("body", [
    {"kind": "typed", "site": "claude.ai"},                                  # no finds
    {"kind": "nope", "site": "claude.ai", "finds": FINDS},                   # unknown kind
    {"kind": "typed", "site": "Claude.AI/../x", "finds": FINDS},             # not a site
    {"kind": "typed", "site": "claude.ai", "finds": FINDS, "unlisted": -1},
    {"kind": "typed", "site": "claude.ai", "finds": [{**FINDS[0], "value": "bob@acme.com"}]},
    ["not", "a", "record"],
])
async def test_anything_but_an_exact_record_is_refused(c, body):
    r = await c.post("/omna/record", auth=EXT, json=body)
    assert r.status_code == 400
    assert receipts.count() == 0


@pytest.mark.anyio
async def test_reports_off_keeps_nothing(c, monkeypatch):
    from omna_plugin import proxy

    class Off:
        reports_enabled = False
    monkeypatch.setattr(proxy.Policy, "load", classmethod(lambda cls: Off()))
    r = await c.post("/omna/record", auth=EXT, json={"kind": "typed", "site": "claude.ai", "finds": FINDS})
    assert r.json() == {"ok": True, "kept": False} and receipts.count() == 0


@pytest.mark.anyio
async def test_the_report_counts_chrome_records_and_their_distinct_values(c):
    from omna_plugin import report
    secret = {"entity": "AWS_KEY", "layer": "L2", "risk": "secret", "action": "redacted", "n": 1, "fp": ["aaaaaaaaaaaaaaaa"]}
    for _ in range(2):   # the same key and email, twice
        r = await c.post("/omna/record", auth=EXT, json={"kind": "typed", "site": "claude.ai", "finds": FINDS + [secret]})
        assert r.status_code == 200
    rep = report.build(days=7)
    assert rep["requests"] == 2
    assert "chrome" in str(rep)
    assert rep["distinct_secrets"] == 1 and rep["distinct_pii"] == 1, rep


@pytest.mark.anyio
async def test_a_file_chrome_could_not_read_is_recorded_as_sent_unread(c):
    # Security review 2026-11-11, finding 7: a zip Omna for Chrome released as
    # it is used to leave no trace; now it lands in the same report line as
    # the curl command's own unread files.
    r = await c.post("/omna/record", auth=EXT, json={"kind": "not_read", "site": "claude.ai", "finds": [], "not_read": "zip"})
    assert r.status_code == 200
    rec = receipts.tail(1)[0]
    assert rec["kind"] == "not_read" and rec["note"] == "file-not-masked:zip" and rec["product"] == "chrome"
    from omna_plugin import report
    assert report.build(7)["not_masked"] == {"zip": 1}


@pytest.mark.anyio
@pytest.mark.parametrize("body", [
    {"kind": "not_read", "site": "claude.ai", "finds": []},                                          # no word
    {"kind": "not_read", "site": "claude.ai", "finds": [], "not_read": "Jane Doe SSN 402-99-1234"},   # free text
    {"kind": "not_read", "site": "claude.ai", "finds": [], "not_read": 7},
    {"kind": "typed", "site": "claude.ai", "finds": [], "not_read": "zip"},                           # word on another kind
])
async def test_a_not_read_record_carries_only_a_known_word(c, body):
    r = await c.post("/omna/record", auth=EXT, json=body)
    assert r.status_code == 400 and receipts.count() == 0


@pytest.mark.anyio
async def test_values_chrome_hid_in_a_file_name_are_recorded(c):
    # Finding 12: Omna for Chrome masks a file's NAME; what it hid there is counted.
    r = await c.post("/omna/record", auth=EXT, json={"kind": "file_name", "site": "claude.ai", "finds": FINDS})
    assert r.status_code == 200
    rec = receipts.tail(1)[0]
    assert rec["kind"] == "file_name" and rec["masked"] == {"EMAIL": 2} and "note" not in rec


@pytest.mark.anyio
async def test_a_chrome_record_says_which_masking_was_used(c):
    r = await c.post("/omna/record", auth=EXT, json={"kind": "typed", "site": "claude.ai", "finds": FINDS, "masking": "smart"})
    assert r.status_code == 200 and receipts.tail(1)[0]["masking"] == "smart"
    await c.post("/omna/record", auth=EXT, json={"kind": "typed", "site": "claude.ai", "finds": FINDS, "masking": "<b>"})
    assert "masking" not in receipts.tail(1)[0]              # only the two known words are kept
