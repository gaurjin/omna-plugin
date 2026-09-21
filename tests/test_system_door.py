import asyncio
import json
import ssl
import time

import httpx
import pytest

from omna_plugin import receipts
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline
from omna_plugin.policy import Policy
from mitmproxy import http
from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketData, WebSocketMessage
from wsproto.frame_protocol import Opcode

from omna_plugin.style import REALISTIC, TOKENS
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


async def test_slow_resolver_does_not_serialize_concurrent_flows(tmp_path, monkeypatch):
    """Regression: ProcessResolver.resolve() shells out to lsof/ps and can block for up
    to ~2.5s on a cache miss. If the addon called it synchronously from inside a hook, a
    slow resolution would stall mitmproxy's single event loop thread for its whole
    duration — serializing every other flow behind it. The fix runs it via
    loop.run_in_executor so only the flow that's waiting on it is delayed.

    Each HTTPS flow calls the resolver twice (tls_clienthello, then request) — those two
    calls are necessarily sequential within ONE flow (request can't fire before the TLS
    handshake completes), so a single flow's own critical path is ~2x the resolver's
    delay. What must NOT happen is that delay compounding ACROSS flows too. Prove it by
    running two requests concurrently through a resolver that sleeps 0.4s per call: fully
    serialized (the bug) is 4 sequential calls = ~1.6s; correctly concurrent flows (the
    fix) is two ~0.8s per-flow critical paths running in parallel = ~0.8-0.9s."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    ca_pem, leaf, key = make_ca_and_leaf(tmp_path)
    up = FakeUpstream()
    await up.start(leaf, key)

    def slow_resolver(peer):
        time.sleep(0.4)
        return (1, "SlowApp")

    pol = Policy()
    pol.hosts = ["127.0.0.1"]
    pol.allow_hosts = lambda: [rf"^127\.0\.0\.1:{up.port}$"]
    pipe = Pipeline(MaskingSession())
    addon = OmnaAddon(pipe, pol, door="system", resolver=slow_resolver)
    master = build_master(pol, addon, port=0, ca_dir=tmp_path / "ca", upstream_ca=str(ca_pem))
    task = asyncio.create_task(master.run())
    await asyncio.sleep(0.5)
    port = next(a[1] for inst in master.addons.get("proxyserver").servers for a in inst.listen_addrs)
    client_ctx = ssl.create_default_context(cafile=str(tmp_path / "ca" / "mitmproxy-ca-cert.pem"))
    try:
        async def one_request():
            async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=client_ctx) as c:
                return await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": "hi"})

        t0 = time.monotonic()
        results = await asyncio.gather(one_request(), one_request())
        elapsed = time.monotonic() - t0
    finally:
        master.shutdown()
        await task
        await up.stop()

    assert all(r.status_code == 200 for r in results)
    # ~1.6s would mean all 4 resolver calls (2 flows x 2 hooks) ran serially (the bug);
    # ~0.8-0.9s is two flows' own ~0.8s critical paths running concurrently (the fix).
    assert elapsed < 1.2, f"two concurrent flows took {elapsed:.2f}s — looks serialized, not concurrent"


def test_remove_deep_redirector_app_deletes_the_bundle(monkeypatch, tmp_path):
    from omna_plugin import system_door

    bundle = tmp_path / "Mitmproxy Redirector.app"
    (bundle / "Contents").mkdir(parents=True)
    monkeypatch.setattr(system_door, "DEEP_REDIRECTOR_APP", bundle)

    system_door.remove_deep_redirector_app()

    assert not bundle.exists()


def test_remove_deep_redirector_app_on_a_missing_bundle_does_not_raise(monkeypatch, tmp_path):
    from omna_plugin import system_door

    monkeypatch.setattr(system_door, "DEEP_REDIRECTOR_APP", tmp_path / "does-not-exist.app")

    system_door.remove_deep_redirector_app()  # no error


# ---------------------------------------------- extension / plugin token clash
async def test_extension_tagged_request_is_masked_but_not_restored(door):
    """The bug this guards: both halves mint tokens named [EMAIL_1] and number
    them independently, so a token the EXTENSION minted for one person would be
    restored by the plugin into a DIFFERENT person's real value.

    Masking must still happen (never leave a gap); only restore steps aside.
    """
    up, port, ctx, _ = door
    # The plugin's own registry already knows this value as [EMAIL_1] — exactly
    # what any machine that has run Claude Code for a while looks like.
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": f"for {EMAIL}"})

    # Now the extension sends a request it has already masked, carrying a token
    # that means someone else entirely.
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(
            f"https://127.0.0.1:{up.port}/api/chat",
            json={"prompt": f"ask {TOK} about it"},
            headers={"x-omna-extension": "1"},
        )
    assert r.status_code == 200
    # The reply echoes the token back. It must come back as the TOKEN, not as
    # jane.doe@example.com — that substitution is the bug.
    assert EMAIL not in r.text, "plugin restored a token the extension minted — wrong person's value"
    assert TOK in r.text


async def test_extension_header_is_not_forwarded_to_the_provider(door):
    up, port, ctx, _ = door
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": "hello"},
                     headers={"x-omna-extension": "1"})
    seen = {k.lower() for k in (up.last_headers or {})}
    assert "x-omna-extension" not in seen, "our internal tag leaked to the AI provider"


async def test_untagged_request_still_restores(door):
    """The plugin-only path must keep working exactly as before — this is the
    common case for anyone who never installs the extension."""
    up, port, ctx, _ = door
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": f"for {EMAIL}"})
    assert TOK.encode() in up.last_body          # masked on the way out
    assert r.json()["reply"] == "hi " + EMAIL    # restored on the way back


async def test_restore_browser_off_masks_but_shows_tokens(door):
    """The menu-bar toggle. Masking is unaffected; only the reply changes."""
    up, port, ctx, addon = door
    addon.policy.restore_browser = False
    async with httpx.AsyncClient(proxy=f"http://127.0.0.1:{port}", verify=ctx) as c:
        r = await c.post(f"https://127.0.0.1:{up.port}/api/chat", json={"prompt": f"for {EMAIL}"})
    assert TOK.encode() in up.last_body, "masking must never be optional"
    assert EMAIL not in r.text
    assert TOK in r.text


# ---------------------------------------------------------------- masking styles

def a_prompt_flow(body: bytes = b'{"prompt": "mail jane.doe@acme.com"}'):
    f = tflow.tflow()
    f.request.host = "claude.ai"
    f.request.path = "/api/messages"
    f.request.method = "POST"
    f.request.headers["content-type"] = "application/json"
    f.request.set_content(body)
    return f


def an_addon(tmp_path, monkeypatch, door: str, style: str):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pol = Policy()
    pol.style = style
    return OmnaAddon(Pipeline(MaskingSession()), pol, door=door, resolver=lambda peer: (1, "TestApp"))


async def test_the_system_door_sends_a_fake_value_when_the_policy_says_realistic(tmp_path, monkeypatch):
    addon = an_addon(tmp_path, monkeypatch, "system", REALISTIC)
    flow = a_prompt_flow()
    await addon.request(flow)
    sent = flow.request.get_content().decode()
    assert "jane.doe@acme.com" not in sent
    assert "[" not in sent and "@example." in sent


async def test_the_deep_door_refuses_realistic_like_the_api_door(tmp_path, monkeypatch):
    """The deep door captures a NAMED desktop app, and that list can hold an
    editor as easily as a chat app — so it sits with the file-writing doors."""
    addon = an_addon(tmp_path, monkeypatch, "deep", REALISTIC)
    flow = a_prompt_flow()
    await addon.request(flow)
    sent = flow.request.get_content().decode()
    assert "[EMAIL_" in sent and "@example." not in sent


async def test_the_system_door_defaults_to_numbered_tokens(tmp_path, monkeypatch):
    addon = an_addon(tmp_path, monkeypatch, "system", TOKENS)
    flow = a_prompt_flow()
    await addon.request(flow)
    assert "[EMAIL_" in flow.request.get_content().decode()


async def test_a_secret_stays_a_numbered_token_at_the_system_door(tmp_path, monkeypatch):
    addon = an_addon(tmp_path, monkeypatch, "system", REALISTIC)
    flow = a_prompt_flow(b'{"prompt": "key AKIAIOSFODNN7EXAMPLE mail jane.doe@acme.com"}')
    await addon.request(flow)
    sent = flow.request.get_content().decode()
    assert "AKIAIOSFODNN7EXAMPLE" not in sent
    assert "[SECRET_AWS_KEY_" in sent          # loud, even here
    assert "@example." in sent                  # ...while the e-mail is realistic


async def test_the_receipt_names_the_style_each_door_used(tmp_path, monkeypatch):
    addon = an_addon(tmp_path, monkeypatch, "system", REALISTIC)
    flow = a_prompt_flow()
    await addon.request(flow)
    flow.response = http.Response.make(200, b'{"reply": "ok"}', {"content-type": "application/json"})
    addon.response(flow)
    assert receipts.tail(1)[0]["style"] == REALISTIC


async def test_a_realistic_reply_is_restored_at_the_system_door(tmp_path, monkeypatch):
    addon = an_addon(tmp_path, monkeypatch, "system", REALISTIC)
    flow = a_prompt_flow()
    await addon.request(flow)
    fake = json.loads(flow.request.get_content())["prompt"].split("mail ")[1]
    flow.response = http.Response.make(200, json.dumps({"reply": "wrote to " + fake}).encode(),
                                       {"content-type": "application/json"})
    addon.response(flow)
    assert "jane.doe@acme.com" in flow.response.get_content().decode()


async def test_a_websocket_message_honours_the_door_style(tmp_path, monkeypatch):
    addon = an_addon(tmp_path, monkeypatch, "system", REALISTIC)
    flow = a_prompt_flow()
    flow.websocket = WebSocketData()
    flow.websocket.messages.append(WebSocketMessage(Opcode.TEXT, True, b"mail jane.doe@acme.com"))
    addon.websocket_message(flow)
    sent = flow.websocket.messages[-1].content.decode()
    assert "jane.doe@acme.com" not in sent and "[" not in sent and "@example." in sent
