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
from omna_plugin.proxy import create_app

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
    assert rec["masked"] == {"EMAIL": 1, "AWS_KEY": 1}
    assert EMAIL not in json.dumps(rec)


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
async def test_secret_restored_inside_streamed_tool_input(env):
    up, session, client = env
    # the model echoes the secret token inside an input_json_delta; the proxy must put the key back, JSON-escaped
    body = {"model": "m", "stream": True, "messages": [{"role": "user", "content": f"key {KEY}"}]}
    r = await client.post("/v1/messages", json=body, headers={"anthropic-version": "2023-06-01"})
    assert r.status_code == 200
    assert KEY not in up.calls[-1]["raw"] and "[SECRET_AWS_KEY_1]" in up.calls[-1]["raw"]
    assert KEY in r.text and "[SECRET_AWS_KEY_1]" not in r.text
