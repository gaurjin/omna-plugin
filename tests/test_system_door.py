import asyncio
import ssl

import httpx
import pytest

from omna_plugin import receipts
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline
from omna_plugin.policy import Policy
from omna_plugin.system_door import OmnaAddon, build_master
from tests.tls_helpers import FakeUpstream, make_ca_and_leaf

EMAIL = "jane.doe@example.com"
TOK = "[EMAIL_" "1]"


@pytest.fixture
async def door(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    ca_pem, leaf, key = make_ca_and_leaf(tmp_path)
    up = FakeUpstream()
    await up.start(leaf, key)
    pol = Policy()
    pol.hosts = ["127.0.0.1"]                                       # the fake upstream is "an AI host" here
    pol.allow_hosts = lambda: [rf"^127\.0\.0\.1:{up.port}$"]      # its port is not 443
    pipe = Pipeline(MaskingSession())
    addon = OmnaAddon(pipe, pol, door="system", resolver=lambda peer: (999, "TestApp"))
    master = build_master(pol, addon, port=0, ca_dir=tmp_path / "ca", upstream_ca=str(ca_pem))
    task = asyncio.create_task(master.run())
    await asyncio.sleep(0.5)                                        # let mitmproxy bind
    port = next(a[1] for inst in master.addons.get("proxyserver").servers for a in inst.listen_addrs)
    client_ctx = ssl.create_default_context(cafile=str(tmp_path / "ca" / "mitmproxy-ca-cert.pem"))
    yield up, port, client_ctx, addon
    master.shutdown()
    await task
    await up.stop()


async def test_prompt_is_masked_and_stream_restored(door):
    up, port, ctx, _ = door
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/backend-api/conversation/stream",
                         json={"messages": [{"content": {"parts": [f"hi, {EMAIL}"]}}]})
    assert r.status_code == 200
    assert EMAIL.encode() not in up.last_body and TOK.encode() in up.last_body   # upstream saw the token only
    assert up.last_headers.get("accept-encoding") == "identity"
    assert EMAIL in r.text and TOK not in r.text                                # restored inside the stream
    assert "[PER" "SON_1]" in r.text                                             # unknown token passes through
    rec = receipts.tail(1)[0]
    assert rec["door"] == "system" and rec["app"] == "TestApp" and rec["masked"].get("EMAIL") == 1


async def test_holdback_chunk_does_not_truncate_the_stream(door):
    """Regression: when a wire chunk is EXACTLY a partial-token prefix (e.g. `[EMAIL_`),
    `TextRestorer.feed` legitimately returns "" for it. `cb` must not turn that into a
    `b""` return — under HTTP/1 chunked transfer-encoding that serializes to `0\\r\\n\\r\\n`,
    byte-identical to the real terminating chunk, and silently truncates the reply."""
    up, port, ctx, _ = door
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/backend-api/conversation/stream-holdback",
                         json={"messages": [{"content": {"parts": [f"hi, {EMAIL}"]}}]})
    assert r.status_code == 200
    # Everything after the held-back chunk must still arrive: the restored email, the
    # tail of that data frame, and the final `data: [DONE]` frame.
    assert r.text.count("start ") == 1
    assert EMAIL in r.text and TOK not in r.text
    assert 'end"}' in r.text
    assert "data: [DONE]" in r.text


async def test_stream_abort_still_writes_a_receipt(door):
    """Regression: if the upstream connection dies mid-stream (no final `chunk == b""`
    call, no `0\\r\\n\\r\\n`), the addon's `error` hook must still write one receipt with
    note="stream-aborted" — otherwise an aborted request leaves no audit trail at all."""
    up, port, ctx, _ = door
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        with pytest.raises(Exception):
            await c.post(f"https://127.0.0.1:{up.port}/backend-api/conversation/stream-abort",
                         json={"messages": [{"content": {"parts": ["hi"]}}]})
    await asyncio.sleep(0.2)  # let the error hook run
    rec = receipts.tail(1)[0]
    assert rec["door"] == "system" and rec["note"] == "stream-aborted"


async def test_json_reply_is_restored(door):
    up, port, ctx, _ = door
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": f"for {EMAIL}"})
    assert r.status_code == 200
    assert TOK.encode() in up.last_body
    assert r.json()["reply"] == "hi " + EMAIL
    assert r.json()["echo"]["prompt"] == "for " + EMAIL                         # the echoed token came back restored


async def test_unparseable_prompt_is_refused_not_forwarded(door):
    up, port, ctx, _ = door
    up.last_body = b"UNTOUCHED"
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/api/chat", content=b"{broken", headers={"content-type": "application/json"})
    assert r.status_code == 400 and "omna_refused" in r.text
    assert up.last_body == b"UNTOUCHED"


async def test_bypassed_app_is_tunnelled_untouched(door):
    up, port, _ctx, addon = door
    addon.policy.set_app("TestApp", "bypass")
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=False) as c:   # we now see the UPSTREAM cert
        r = await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": EMAIL})
    assert r.status_code == 200
    assert EMAIL.encode() in up.last_body                                        # bypass = really untouched
    assert receipts.tail(1)[0]["note"] == "bypassed-by-policy"
