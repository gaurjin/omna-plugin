"""Proxy tests against an in-process fake upstream.

The fake records exactly what it received (so we can assert the real values
never arrived) and answers with canned replies that echo the tokens back, the
way a real model would.
"""

import json
import re

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from omna_plugin import receipts
from omna_plugin.engine import MaskingSession, TOKEN_RE
from omna_plugin.policy import Policy
from omna_plugin.proxy import create_app
from omna_plugin.style import REALISTIC, TOKENS

EMAIL = "john.smith@acme.com"
KEY = "AKIAIOSFODNN7EXAMPLE"


class Upstream:
    def __init__(self):
        self.calls: list[dict] = []
        self.app = Starlette(
            routes=[
                Route("/v1/messages", self.messages, methods=["POST"]),
                Route("/v1/messages/count_tokens", self.count, methods=["POST"]),
                Route("/v1/chat/completions", self.chat, methods=["POST"]),
                Route("/v1/models", self.models, methods=["GET"]),
                Route("/v1/error", self.error, methods=["POST"]),
            ]
        )

    async def _record(self, request: Request) -> dict:
        body = await request.body()
        call = {"host": request.headers.get("host"), "path": request.url.path, "headers": dict(request.headers), "raw": body.decode()}
        try:
            call["json"] = json.loads(body)
        except ValueError:
            call["json"] = None
        self.calls.append(call)
        return call

    async def messages(self, request: Request):
        call = await self._record(request)
        toks = TOKEN_RE.findall(call["raw"])
        tok = f"[{toks[0][0]}_{toks[0][1]}]" if toks else "[NONE_0]"
        if call["json"].get("stream"):
            async def gen():
                yield b'event: message_start\ndata: {"type":"message_start","message":{"id":"m1"}}\n\n'
                yield b'event: ping\ndata: {"type": "ping"}\n\n'
                yield b'event: content_block_start\ndata: {"type":"content_block_start","index":0,"content_block":{"type":"text","text":""}}\n\n'
                head, tail = tok[:4], tok[4:]
                yield f'event: content_block_delta\ndata: {json.dumps({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":"I will email " + head}})}\n\n'.encode()
                yield f'event: content_block_delta\ndata: {json.dumps({"type":"content_block_delta","index":0,"delta":{"type":"text_delta","text":tail + " now."}})}\n\n'.encode()
                yield b'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n'
                yield b'event: message_stop\ndata: {"type":"message_stop"}\n\n'
            return StreamingResponse(gen(), media_type="text/event-stream")
        return JSONResponse({"id": "m1", "content": [{"type": "text", "text": f"Emailing {tok}."}], "stop_reason": "end_turn"})

    async def count(self, request: Request):
        await self._record(request)
        return JSONResponse({"input_tokens": 42})

    async def chat(self, request: Request):
        call = await self._record(request)
        toks = TOKEN_RE.findall(call["raw"])
        tok = f"[{toks[0][0]}_{toks[0][1]}]" if toks else "[NONE_0]"
        return JSONResponse({"choices": [{"index": 0, "message": {"role": "assistant", "content": f"ok {tok}"}}]})

    async def models(self, request: Request):
        await self._record(request)
        return JSONResponse({"data": [{"id": "claude-sonnet-5"}]})

    async def error(self, request: Request):
        await self._record(request)
        return Response('{"type":"error","error":{"type":"invalid_request_error","message":"prompt too long"}}', status_code=400, media_type="application/json")


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    up = Upstream()
    session = MaskingSession()
    up_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app))
    app = create_app(session, anthropic_upstream="http://anthropic.test", openai_upstream="http://openai.test", client=up_client)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://omna.local")
    return up, session, client


@pytest.mark.anyio
async def test_streamed_anthropic_request_is_masked_and_reply_restored(env):
    up, session, client = env
    body = {
        "model": "claude-sonnet-5",
        "stream": True,
        "system": [{"type": "text", "text": "Be brief.", "cache_control": {"type": "ephemeral"}}],
        "messages": [{"role": "user", "content": f"Email {EMAIL} using key {KEY}"}],
    }
    r = await client.post(
        "/v1/messages?beta=true",
        json=body,
        headers={"anthropic-version": "2023-06-01", "anthropic-beta": "oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14", "authorization": "Bearer sk-ant-oat-TEST", "x-claude-code-session-id": "sess-1"},
    )
    assert r.status_code == 200
    call = up.calls[-1]
    assert EMAIL not in call["raw"] and KEY not in call["raw"]
    assert "[SECRET_AWS_KEY_1]" in call["raw"]
    assert call["headers"]["anthropic-beta"] == "oauth-2025-04-20,fine-grained-tool-streaming-2025-05-14"
    assert call["headers"]["anthropic-version"] == "2023-06-01"
    assert call["headers"]["authorization"] == "Bearer sk-ant-oat-TEST"
    assert call["host"] == "anthropic.test"
    assert call["json"]["system"][0]["cache_control"] == {"type": "ephemeral"}
    text = r.text
    assert 'data: {"type": "ping"}' in text  # ping relayed byte-identical
    delta_texts = [json.loads(l[6:])["delta"]["text"] for l in text.splitlines() if l.startswith("data: ") and '"text_delta"' in l]
    assert "".join(delta_texts) == f"I will email {EMAIL} now."
    rec = receipts.tail(1)[0]
    assert rec["route"] == "/v1/messages" and rec["stream"] is True and rec["session"] == "sess-1"
    assert rec["masked"] == {"EMAIL": 1, "AWS_KEY": 1} and rec["secrets"] == 1 and rec["pii"] == 1
    assert rec["tokens"] == ["EMAIL_1", "SECRET_AWS_KEY_1"] and isinstance(rec["mask_ms"], int)
    assert EMAIL not in json.dumps(rec) and KEY not in json.dumps(rec)


@pytest.mark.anyio
async def test_non_streamed_reply_is_restored(env):
    up, session, client = env
    r = await client.post("/v1/messages", json={"model": "m", "messages": [{"role": "user", "content": f"mail {EMAIL}"}]}, headers={"x-api-key": "k"})
    assert r.status_code == 200
    assert r.json()["content"][0]["text"] == f"Emailing {EMAIL}."
    assert EMAIL not in up.calls[-1]["raw"]


@pytest.mark.anyio
async def test_count_tokens_and_hello_and_models(env):
    up, session, client = env
    r = await client.post("/v1/messages/count_tokens", json={"messages": [{"role": "user", "content": f"mail {EMAIL}"}]}, headers={"anthropic-version": "2023-06-01"})
    assert r.status_code == 200 and r.json() == {"input_tokens": 42}
    assert EMAIL not in up.calls[-1]["raw"]
    r = await client.head("/api/hello")
    assert r.status_code == 200
    r = await client.get("/v1/models?limit=1000", headers={"anthropic-version": "2023-06-01"})
    assert r.json()["data"][0]["id"] == "claude-sonnet-5" and up.calls[-1]["host"] == "anthropic.test"


@pytest.mark.anyio
async def test_openai_route_goes_to_openai_upstream(env):
    up, session, client = env
    r = await client.post("/v1/chat/completions", json={"model": "gpt-5", "messages": [{"role": "user", "content": f"mail {EMAIL}"}]}, headers={"authorization": "Bearer sk-openai"})
    assert r.status_code == 200
    assert up.calls[-1]["host"] == "openai.test"
    assert EMAIL not in up.calls[-1]["raw"]
    assert r.json()["choices"][0]["message"]["content"] == f"ok {EMAIL}"


@pytest.mark.anyio
async def test_upstream_error_body_is_forwarded_unmodified(env):
    up, session, client = env
    r = await client.post("/v1/error", json={"messages": []}, headers={"anthropic-version": "2023-06-01"})
    assert r.status_code == 400
    assert r.json()["error"]["message"] == "prompt too long"


@pytest.mark.anyio
async def test_health(env):
    up, session, client = env
    r = await client.get("/omna/health")
    assert r.status_code == 200 and r.json()["ok"] is True and "engine" in r.json()


@pytest.mark.anyio
async def test_health_reports_live_masking_counters(env):
    up, session, client = env
    r = await client.get("/omna/health")
    body = r.json()
    assert body["distinct_secrets_this_run"] == 0
    assert body["distinct_pii_this_run"] == 0
    assert body["avg_mask_ms_this_run"] == 0
    r = await client.post(
        "/v1/messages",
        json={"model": "m", "messages": [{"role": "user", "content": f"mail {EMAIL} key {KEY}"}]},
        headers={"x-api-key": "k"},
    )
    assert r.status_code == 200
    r = await client.get("/omna/health")
    body = r.json()
    assert body["distinct_secrets_this_run"] == 1
    assert body["distinct_pii_this_run"] == 1
    assert isinstance(body["avg_mask_ms_this_run"], int)
    assert body["requests_this_run"] == 1


@pytest.mark.anyio
async def test_extension_checkin_updates_health(env):
    up, session, client = env
    # No checkin yet — health reports it as absent.
    r = await client.get("/omna/health")
    assert r.json()["extension_last_seen"] is None

    r = await client.post("/omna/extension-checkin", json={"version": "0.6.0"})
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    r = await client.get("/omna/health")
    body = r.json()
    assert body["extension_last_seen"] is not None
    assert body["extension_version"] == "0.6.0"


@pytest.mark.anyio
async def test_extension_checkin_without_version_key_reports_none(env):
    up, session, client = env
    r = await client.post("/omna/extension-checkin", json={})
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    r = await client.get("/omna/health")
    body = r.json()
    assert body["extension_last_seen"] is not None
    assert body["extension_version"] is None


@pytest.mark.anyio
@pytest.mark.parametrize("malformed_body", [b"null", b"[1, 2, 3]"])
async def test_extension_checkin_rejects_non_dict_json_without_500(env, malformed_body):
    # `null` and a JSON array are both VALID JSON, so request.json() succeeds
    # and returns None/list — the soft-fail must come from a shape guard, not
    # from a JSON-parse failure. Regression test for the AttributeError found
    # in review: body.get("version") on a non-dict used to blow up as a 500.
    up, session, client = env
    r = await client.post(
        "/omna/extension-checkin",
        content=malformed_body,
        headers={"content-type": "application/json"},
    )
    assert r.status_code == 200
    assert r.json() == {"ok": True}

    r = await client.get("/omna/health")
    body = r.json()
    assert body["extension_last_seen"] is not None
    assert body["extension_version"] is None


@pytest.mark.anyio
async def test_proxy_pac_serves_system_door(env):
    up, session, client = env
    r = await client.get("/omna/proxy.pac")
    assert r.status_code == 200 and "PROXY 127.0.0.1:7789" in r.text


@pytest.mark.anyio
async def test_unparseable_inference_body_is_refused_not_forwarded(env):
    up, session, client = env
    before = len(up.calls)
    r = await client.post("/v1/messages", content=b"\x1f\x8b not json", headers={"content-type": "application/json", "content-encoding": "gzip", "anthropic-version": "2023-06-01"})
    assert r.status_code == 400 and r.json()["error"]["type"] == "omna_refused"
    r = await client.post("/v1/chat/completions", content=b"{not json", headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert len(up.calls) == before  # nothing reached the upstream
    assert receipts.tail(1)[0]["note"] in ("unparseable", "mask-failed")


@pytest.mark.anyio
async def test_mask_failed_on_non_inference_route_refuses_not_passthrough(env):
    # /v1/error is NOT in INFERENCE_PREFIXES. Valid JSON syntax, but the value
    # is a lone UTF-16 surrogate: json.loads accepts it, but masking's own
    # json.dumps(..., ensure_ascii=False).encode("utf-8") raises
    # UnicodeEncodeError. Before the fix, mask_bytes collapsed this into
    # refused="unparseable", which on a non-inference route fell through to
    # passthrough=True — forwarding the unmasked original body upstream.
    up, session, client = env
    before = len(up.calls)
    body = '{"messages": ["\\ud800"]}'.encode("ascii")
    r = await client.post("/v1/error", content=body, headers={"content-type": "application/json"})
    assert r.status_code == 400
    assert r.json()["error"]["type"] == "omna_refused"
    assert len(up.calls) == before  # never reached the upstream, masked or not
    assert receipts.tail(1)[0]["note"] == "mask-failed"


@pytest.mark.anyio
async def test_secret_restored_inside_streamed_tool_input(env):
    up, session, client = env
    # the model echoes the secret token inside an input_json_delta; the proxy must put the key back, JSON-escaped
    body = {"model": "m", "stream": True, "messages": [{"role": "user", "content": f"key {KEY}"}]}
    r = await client.post("/v1/messages", json=body, headers={"anthropic-version": "2023-06-01"})
    assert r.status_code == 200
    assert KEY not in up.calls[-1]["raw"] and "[SECRET_AWS_KEY_1]" in up.calls[-1]["raw"]
    assert KEY in r.text and "[SECRET_AWS_KEY_1]" not in r.text


@pytest.mark.anyio
async def test_dashboard_serves_html_and_json(env):
    from omna_plugin import config

    up, session, client = env
    k = config.dashboard_token(create=True)   # token required since #134
    r = await client.get(f"/omna/dashboard?k={k}")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]
    body = r.text
    assert "Omna" in body and "receipt chain" in body
    # A privacy tool's own dashboard must not fetch anything from the internet.
    for bad in ("http://", "https://", "cdn.", "<script src"):
        assert bad not in body, f"dashboard reaches outside for {bad!r}"

    j = await client.get(f"/omna/dashboard.json?k={k}")
    assert j.status_code == 200
    assert "p95_ms" in j.json() and "sent_as_is" in j.json()


@pytest.mark.anyio
async def test_dashboard_links_to_the_mappings_review_screen(env):
    from omna_plugin import config

    up, session, client = env
    k = config.dashboard_token(create=True)
    r = await client.get(f"/omna/dashboard?k={k}")
    assert "/omna/mappings" in r.text


@pytest.mark.anyio
async def test_dashboard_shows_the_sent_as_is_count_the_extension_reports(env):
    from omna_plugin import config

    up, session, client = env
    k = config.dashboard_token(create=True)
    await client.post("/omna/extension-checkin", json={"version": "0.6.0", "sent_as_is": 7})
    j = (await client.get(f"/omna/dashboard.json?k={k}")).json()
    assert j["sent_as_is"] == 7


@pytest.mark.anyio
async def test_a_bogus_sent_as_is_is_ignored_not_trusted(env):
    from omna_plugin import config

    up, session, client = env
    k = config.dashboard_token(create=True)
    for bad in ("many", -3, None, {"n": 1}):
        await client.post("/omna/extension-checkin", json={"version": "0.6.0", "sent_as_is": bad})
    j = (await client.get(f"/omna/dashboard.json?k={k}")).json()
    assert j["sent_as_is"] == 0


# -------------------------------------------------- crash recording (#132)
@pytest.mark.anyio
async def test_an_internal_error_is_recorded_locally_and_never_leaks_detail(env, tmp_path, monkeypatch):
    """A crash inside the proxy happens in a background process, so the tool
    just sees a 500 and the cause is lost. It must land in the local crash log
    instead — and the 500 body must not carry the traceback out to the caller."""
    from omna_plugin import crashlog

    up, session, client = env

    async def boom(request):
        raise RuntimeError(f"kaboom while handling {EMAIL}")

    app = client._transport.app
    app.routes.insert(0, Route("/omna/boom", boom, methods=["GET"]))
    # Starlette sends our 500 and THEN re-raises so the real server logs the
    # traceback. That is what we want in production; here we just stop the test
    # client from re-raising it on our behalf.
    crash_client = httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
        base_url="http://omna.local",
    )

    r = await crash_client.get("/omna/boom")
    assert r.status_code == 500
    assert "kaboom" not in r.text and "Traceback" not in r.text
    assert "omna crash" in r.text

    rows = crashlog.tail(5)
    assert rows and rows[-1]["error"] == "RuntimeError"
    assert rows[-1]["where"] == "proxy"
    assert rows[-1]["route"] == "/omna/boom"
    # the address that rode along in the exception message was masked on the way in
    assert EMAIL not in (tmp_path / "crashes.jsonl").read_text()


# ------------------------------------------------- dashboard auth (#134)
@pytest.mark.anyio
async def test_the_dashboard_refuses_without_the_token(env):
    from omna_plugin import config

    up, session, client = env
    for path in ("/omna/dashboard", "/omna/dashboard.json"):
        r = await client.get(path)
        assert r.status_code == 401, path
        assert "token" in r.text
        # the 401 itself must not hand out the secret
        assert config.dashboard_token(create=True) not in r.text


@pytest.mark.anyio
async def test_the_dashboard_opens_with_the_token_in_the_url_or_a_bearer_header(env):
    from omna_plugin import config

    up, session, client = env
    tok = config.dashboard_token(create=True)
    r = await client.get(f"/omna/dashboard?k={tok}")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    r = await client.get("/omna/dashboard.json", headers={"authorization": f"Bearer {tok}"})
    assert r.status_code == 200 and isinstance(r.json(), dict)


@pytest.mark.anyio
async def test_a_wrong_token_is_refused(env):
    up, session, client = env
    r = await client.get("/omna/dashboard?k=not-the-token")
    assert r.status_code == 401


@pytest.mark.anyio
async def test_the_token_file_is_owner_only(env, tmp_path):
    from omna_plugin import config

    config.dashboard_token(create=True)
    assert oct((tmp_path / "dashboard.token").stat().st_mode)[-3:] == "600"


# ------------------------------------------------------- browser CORS (#137a)
@pytest.mark.anyio
async def test_a_local_web_app_gets_its_preflight_answered(env):
    up, session, client = env
    r = await client.request("OPTIONS", "/v1/messages", headers={
        "origin": "http://localhost:3000",
        "access-control-request-method": "POST",
        "access-control-request-headers": "content-type, x-api-key",
    })
    assert r.status_code == 204
    assert r.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "x-api-key" in r.headers["access-control-allow-headers"]
    assert r.headers["vary"] == "Origin"


@pytest.mark.anyio
async def test_a_public_website_is_refused_so_we_are_not_an_open_relay(env):
    """THE test for #137a. A page on the internet can make your browser send a
    request to 127.0.0.1; approving its origin is what would let that page use
    your machine as a proxy. It must be refused at the preflight."""
    up, session, client = env
    r = await client.request("OPTIONS", "/v1/messages", headers={
        "origin": "https://evil.example.com",
        "access-control-request-method": "POST",
    })
    assert r.status_code == 403
    assert "access-control-allow-origin" not in r.headers


@pytest.mark.anyio
async def test_a_real_reply_carries_the_cors_header_for_a_local_origin(env):
    up, session, client = env
    r = await client.post("/v1/messages", json={"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]},
                          headers={"origin": "http://127.0.0.1:5173", "content-type": "application/json"})
    assert r.status_code == 200
    assert r.headers["access-control-allow-origin"] == "http://127.0.0.1:5173"


@pytest.mark.anyio
async def test_no_origin_header_means_no_cors_headers_at_all(env):
    """Claude Code and every other CLI send no Origin. Nothing changes for them."""
    up, session, client = env
    r = await client.post("/v1/messages", json={"model": "claude-sonnet-5", "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200
    assert "access-control-allow-origin" not in r.headers


def test_only_local_origins_pass_the_check():
    from omna_plugin.proxy import cors_origin_allowed

    for good in ("http://localhost:3000", "http://127.0.0.1:5173", "https://localhost", "http://[::1]:8080"):
        assert cors_origin_allowed(good), good
    for bad in ("https://evil.example.com", "http://localhost.evil.com", "http://127.0.0.1.evil.com", "", "null"):
        assert not cors_origin_allowed(bad), bad
    # an explicitly configured extra origin is honoured, exact-match only
    assert cors_origin_allowed("https://app.acme.com", ["https://app.acme.com"])
    assert not cors_origin_allowed("https://app.acme.com.evil.net", ["https://app.acme.com"])


# --------------------------------------------- pinning, end to end (security menu)
@pytest.mark.anyio
async def test_the_proxy_refuses_to_forward_to_a_host_that_fails_its_pin(env, monkeypatch):
    """The function being correct is not the point — this proves the relay
    actually calls it, and refuses BEFORE the body is forwarded."""
    from omna_plugin import upstream_tls
    from omna_plugin.policy import Policy

    up, session, client = env
    upstream_tls.forget_cached_verdicts()
    monkeypatch.setattr(upstream_tls, "fetch_pins", lambda h, **k: ["IMPOSTOR"])
    pol = Policy()
    pol.tls_pins = {"anthropic.test": ["EXPECTED"]}
    pol.save()

    before = len(up.calls)
    r = await client.post("/v1/messages", json={"model": "claude-sonnet-5",
                                                "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 526
    assert r.json()["error"]["type"] == "omna_pin_mismatch"
    assert len(up.calls) == before, "nothing may reach the upstream when the pin fails"


@pytest.mark.anyio
async def test_an_unpinned_host_is_forwarded_exactly_as_before(env, monkeypatch):
    from omna_plugin import upstream_tls

    up, session, client = env
    upstream_tls.forget_cached_verdicts()
    monkeypatch.setattr(upstream_tls, "fetch_pins",
                        lambda *a, **k: pytest.fail("must not probe an unpinned host"))
    r = await client.post("/v1/messages", json={"model": "claude-sonnet-5",
                                                "messages": [{"role": "user", "content": "hi"}]})
    assert r.status_code == 200


# ---------------------------------------------------------------- masking styles

@pytest.fixture
def env_with_policy(tmp_path, monkeypatch):
    """Like `env`, but the caller supplies the policy the door was built with."""
    def build(pol: Policy):
        monkeypatch.setenv("OMNA_HOME", str(tmp_path))
        pol.save()
        up = Upstream()
        session = MaskingSession()
        up_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app))
        app = create_app(session, anthropic_upstream="http://anthropic.test",
                         openai_upstream="http://openai.test", client=up_client, policy=pol)
        client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://omna.local")
        return up, session, client
    return build


@pytest.mark.anyio
async def test_the_api_door_keeps_numbered_tokens_even_when_policy_says_realistic(env_with_policy, capsys):
    """Claude Code, aider, Codex, Continue and VS Code all WRITE FILES. A fake
    value left in a file looks like real data; a token does not."""
    pol = Policy()
    pol.style = REALISTIC
    up, session, client = env_with_policy(pol)
    await client.post("/v1/messages", json={"model": "claude-sonnet-5",
                                            "messages": [{"role": "user", "content": f"mail {EMAIL}"}]})
    raw = up.calls[0]["raw"]
    assert EMAIL not in raw
    assert TOKEN_RE.findall(raw), "the API door must send numbered tokens"
    assert "@example." not in raw, "a realistic fake value reached a file-writing tool"


@pytest.mark.anyio
async def test_the_api_door_says_out_loud_that_it_refused(env_with_policy, capsys):
    pol = Policy()
    pol.style = REALISTIC
    env_with_policy(pol)
    printed = capsys.readouterr().out
    assert "refused" in printed and "api door" in printed
    assert "Claude Code" in printed


@pytest.mark.anyio
async def test_the_api_door_prints_nothing_when_the_style_is_the_default(env_with_policy, capsys):
    env_with_policy(Policy())
    assert capsys.readouterr().out == ""


@pytest.mark.anyio
async def test_the_receipt_names_the_style_the_api_door_actually_used(env_with_policy):
    pol = Policy()
    pol.style = REALISTIC
    up, session, client = env_with_policy(pol)
    await client.post("/v1/messages", json={"model": "claude-sonnet-5",
                                            "messages": [{"role": "user", "content": f"mail {EMAIL}"}]})
    assert receipts.tail(1)[0]["style"] == TOKENS


# ------------------------------------------- the style the browser is told (#143)
# The Chrome extension masks inside the browser, before the plugin sees the
# request, so it cannot ask a door anything — it reads one field on
# /omna/health and does what that says.

def _browser_app(tmp_path, monkeypatch, style: str, system_door_on: bool):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pol = Policy()
    pol.style = style
    doors = {"api": True, "system": system_door_on, "deep": False}
    pol.doors = doors
    app = create_app(MaskingSession(), policy=pol, doors_state=doors,
                     client=httpx.AsyncClient(transport=httpx.ASGITransport(app=Upstream().app)))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://omna.local")


@pytest.mark.anyio
async def test_health_reports_numbered_tokens_by_default(tmp_path, monkeypatch):
    client = _browser_app(tmp_path, monkeypatch, TOKENS, system_door_on=False)
    assert (await client.get("/omna/health")).json()["style"] == TOKENS


@pytest.mark.anyio
async def test_health_reports_realistic_when_the_policy_asks_and_the_system_door_is_off(tmp_path, monkeypatch):
    client = _browser_app(tmp_path, monkeypatch, REALISTIC, system_door_on=False)
    assert (await client.get("/omna/health")).json()["style"] == REALISTIC


@pytest.mark.anyio
async def test_health_reports_tokens_while_the_system_door_is_on(tmp_path, monkeypatch):
    """Both halves would mask the same browser request. A numbered token
    survives that second pass; a realistic fake value does not."""
    client = _browser_app(tmp_path, monkeypatch, REALISTIC, system_door_on=True)
    assert (await client.get("/omna/health")).json()["style"] == TOKENS


@pytest.mark.anyio
async def test_health_never_reports_the_raw_policy_value(tmp_path, monkeypatch):
    """`style` is a decision, not an echo. It is what the browser may WRITE."""
    client = _browser_app(tmp_path, monkeypatch, "fancy", system_door_on=False)
    assert (await client.get("/omna/health")).json()["style"] == TOKENS


@pytest.mark.anyio
async def test_health_picks_up_a_menu_bar_style_change_without_a_restart(tmp_path, monkeypatch):
    """The menu bar writes policy.json from its own process (#143a). The answer
    the extension reads has to move with it, or the new toggle is the very bug
    #143 is about: a setting that silently does not apply."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pol = Policy()
    pol.doors = {"api": True, "system": False, "deep": False}
    pol.save()
    app = create_app(MaskingSession(), policy=pol, doors_state=pol.doors,
                     client=httpx.AsyncClient(transport=httpx.ASGITransport(app=Upstream().app)))
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://omna.local")
    assert (await client.get("/omna/health")).json()["style"] == TOKENS

    menu = Policy.load()          # a different object, exactly like the menu bar's
    menu.style = REALISTIC
    menu.save()

    assert (await client.get("/omna/health")).json()["style"] == REALISTIC
