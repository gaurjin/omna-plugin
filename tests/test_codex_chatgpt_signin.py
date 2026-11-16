"""Codex signed in with a ChatGPT account, pointed at the API door by omna's
line in ~/.codex/config.toml (recorded live 2026-11-16, Codex 0.169):

- it marks every request with a "chatgpt-account-id" header, and such a
  request belongs at chatgpt.com/backend-api/codex/…, not api.openai.com
  (which answered 403 "Missing scopes");
- it sends the turn zstd-compressed, which the API door refused outright
  ("omna only forwards JSON … content-encoding 'zstd'") — nothing leaked,
  and Codex did not work."""
import json

import httpx
import pytest
from mitmproxy.net import encoding
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, StreamingResponse
from starlette.routing import Route

from omna_plugin import receipts
from omna_plugin.engine import MaskingSession, TOKEN_RE
from omna_plugin.proxy import create_app

EMAIL = "john.smith@acme.com"
KEY = "AKIAIOSFODNN7EXAMPLE"
TURN = {"model": "gpt-x", "instructions": "You are Codex.", "stream": False,
        "input": [{"type": "message", "role": "user", "content": [{"type": "input_text", "text": f"mail {EMAIL} key {KEY}"}]}]}
CHATGPT = {"authorization": "Bearer chatgpt-token", "chatgpt-account-id": "0f9e8d7c-6b5a-4f3e-9d2c-1b0a9f8e7d6c"}


class Upstream:
    def __init__(self):
        self.calls: list[dict] = []
        self.app = Starlette(routes=[Route("/{rest:path}", self.any, methods=["GET", "POST"])])

    async def any(self, request: Request):
        self.calls.append({"host": request.headers.get("host"), "path": request.url.path, "query": request.url.query,
                           "headers": dict(request.headers), "raw": await request.body()})
        raw = self.calls[-1]["raw"].decode("utf-8", "replace")
        if request.url.path.endswith("/responses") and '"stream": true' in raw:
            # As recorded: the reply stream comes with NO content-type header.
            tok = next((f"[{a}_{b}]" for a, b in TOKEN_RE.findall(raw) if a == "EMAIL"), "[NONE_0]")

            async def gen():
                for piece in ("mail ", tok[:4], tok[4:], " today"):
                    yield ("event: response.output_text.delta\ndata: " + json.dumps(
                        {"type": "response.output_text.delta", "delta": piece}) + "\n\n").encode()
                yield b'event: response.completed\ndata: {"type":"response.completed"}\n\n'
            return StreamingResponse(gen(), media_type=None)
        return JSONResponse({"ok": True})


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    up = Upstream()
    app = create_app(MaskingSession(), anthropic_upstream="http://anthropic.test", openai_upstream="http://openai.test",
                     chatgpt_upstream="http://chatgpt.test/backend-api/codex",
                     client=httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app)))
    return up, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")


def _zstd(obj) -> bytes:
    return encoding.encode(json.dumps(obj).encode(), "zstd")


@pytest.mark.anyio
async def test_a_chatgpt_sign_in_turn_goes_to_chatgpt_masked(env):
    up, client = env
    r = await client.post("/v1/responses", content=_zstd(TURN),
                          headers={"content-type": "application/json", "content-encoding": "zstd", **CHATGPT})
    assert r.status_code == 200
    call = up.calls[-1]
    assert (call["host"], call["path"]) == ("chatgpt.test", "/backend-api/codex/responses")
    sent = json.loads(call["raw"])                               # plain JSON now, and said so
    assert "content-encoding" not in call["headers"]
    assert EMAIL not in call["raw"].decode() and KEY not in call["raw"].decode()
    assert sent["instructions"] == TURN["instructions"]
    assert call["headers"]["authorization"] == "Bearer chatgpt-token"
    assert call["headers"]["chatgpt-account-id"] == CHATGPT["chatgpt-account-id"]
    assert receipts.tail(1)[0]["masked"] == {"EMAIL": 1, "AWS_KEY": 1}


@pytest.mark.anyio
async def test_its_model_list_goes_to_chatgpt_too(env):
    up, client = env
    await client.get("/v1/models?client_version=0.169.0", headers=CHATGPT)
    call = up.calls[-1]
    assert (call["host"], call["path"], call["query"]) == ("chatgpt.test", "/backend-api/codex/models", "client_version=0.169.0")


@pytest.mark.anyio
async def test_an_api_key_turn_still_goes_to_the_openai_api_and_may_be_compressed(env):
    up, client = env
    r = await client.post("/v1/responses", content=_zstd(TURN),
                          headers={"content-type": "application/json", "content-encoding": "zstd", "authorization": "Bearer sk-test"})
    assert r.status_code == 200
    call = up.calls[-1]
    assert (call["host"], call["path"]) == ("openai.test", "/v1/responses")
    assert EMAIL not in call["raw"].decode() and "content-encoding" not in call["headers"]


@pytest.mark.anyio
@pytest.mark.parametrize("enc,body", [("zstd", b"\x28\xb5\x2f\xfd not zstd"), ("zstd", None), ("snappy", b"whatever")])
async def test_a_compressed_turn_omna_cannot_read_is_still_refused(env, enc, body):
    up, client = env
    if body is None:
        body = encoding.encode(b"not json at all", "zstd")
    r = await client.post("/v1/responses", content=body, headers={"content-type": "application/json", "content-encoding": enc, **CHATGPT})
    assert r.status_code == 400 and r.json()["error"]["type"] == "omna_refused"
    assert up.calls == []


@pytest.mark.anyio
async def test_the_reply_stream_has_no_content_type_and_is_still_restored(env):
    """Found live: chatgpt.com answers Codex's turn with an event stream and no
    content-type header, so the reply reached Codex with the stand-ins in it."""
    up, client = env
    r = await client.post("/v1/responses", content=_zstd({**TURN, "stream": True}),
                          headers={"content-type": "application/json", "content-encoding": "zstd", **CHATGPT})
    assert r.status_code == 200
    said = "".join(json.loads(l[6:]).get("delta", "") for l in r.text.splitlines() if l.startswith("data: "))
    assert said == f"mail {EMAIL} today"
    assert receipts.tail(1)[0]["stream"] is True
