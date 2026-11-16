"""The API door takes Codex's WebSocket (/v1/responses). Recorded live
2026-11-16 (Codex 0.169): refused, Codex retried seven times — about eight
seconds at every start — before falling back to HTTPS. The socket is relayed
to the provider with the same rules the system door applies to it."""
import json
import socket
import threading
import time

import pytest
import uvicorn
from starlette.applications import Starlette
from starlette.routing import WebSocketRoute
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from omna_plugin import receipts
from omna_plugin.engine import MaskingSession, TOKEN_RE
from omna_plugin.proxy import create_app

EMAIL = "john.smith@acme.com"
KEY = "AKIAIOSFODNN7EXAMPLE"
UUID = "0f9e8d7c-6b5a-7f3e-9d2c-1b0a9f8e7d6c"
TURN = {"type": "response.create", "model": "gpt-x", "prompt_cache_key": UUID,
        "client_metadata": {"session_id": UUID},
        "input": [{"type": "message", "role": "developer", "content": [{"type": "input_text", "text": "Mail help@example.com."}]},
                  {"type": "message", "role": "user", "content": [{"type": "input_text", "text": f"mail {EMAIL} key {KEY}"}]}]}
# The test client names the host "testserver"; a real tool names this machine.
HERE = {"host": "127.0.0.1:7788"}
CHATGPT = {**HERE, "authorization": "Bearer chatgpt-token", "chatgpt-account-id": UUID}


class Upstream:
    """A real WebSocket server on this machine, standing in for the provider."""

    def __init__(self):
        self.calls: list[dict] = []
        app = Starlette(routes=[WebSocketRoute("/backend-api/codex/responses", self.ws), WebSocketRoute("/v1/responses", self.ws)])
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=self.port, log_level="error", ws="wsproto"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        for _ in range(200):
            if self.server.started:
                break
            time.sleep(0.02)

    async def ws(self, websocket):
        call = {"path": websocket.url.path, "headers": dict(websocket.headers), "frames": []}
        self.calls.append(call)
        await websocket.accept()
        try:
            while True:
                raw = await websocket.receive_text()
                call["frames"].append(raw)
                tok = next((f"[{a}_{b}]" for a, b in TOKEN_RE.findall(raw) if a == "EMAIL"), "[NONE_0]")
                await websocket.send_text(json.dumps({"type": "response.output_text.done", "text": f"mail {tok} today"}))
        except WebSocketDisconnect:
            pass

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=5)


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    up = Upstream()
    app = create_app(MaskingSession(), anthropic_upstream="http://anthropic.test",
                     openai_upstream=f"http://127.0.0.1:{up.port}",
                     chatgpt_upstream=f"http://127.0.0.1:{up.port}/backend-api/codex")
    with TestClient(app, base_url="http://127.0.0.1:7788") as client:
        yield up, client
    up.stop()


def test_codexs_websocket_is_relayed_masked_and_the_reply_restored(env):
    up, client = env
    with client.websocket_connect("/v1/responses", headers=CHATGPT) as ws:
        ws.send_text(json.dumps(TURN))
        reply = json.loads(ws.receive_text())
    assert reply["text"] == f"mail {EMAIL} today"
    call = up.calls[-1]
    assert call["path"] == "/backend-api/codex/responses"
    assert call["headers"]["authorization"] == "Bearer chatgpt-token" and call["headers"]["chatgpt-account-id"] == UUID
    sent = json.loads(call["frames"][0])
    text = sent["input"][1]["content"][0]["text"]
    assert EMAIL not in text and KEY not in text
    want = json.loads(json.dumps(TURN))
    want["input"][1]["content"][0]["text"] = text
    assert sent == want                                   # Codex's own parts exactly as sent
    for _ in range(100):                                  # the receipt is written as the socket closes
        rec = receipts.tail(1)
        if rec and rec[0].get("note") == "websocket":
            break
        time.sleep(0.02)
    assert rec[0]["masked"] == {"EMAIL": 1, "AWS_KEY": 1} and rec[0]["door"] == "api"


def test_an_api_key_websocket_goes_to_the_openai_api(env):
    up, client = env
    with client.websocket_connect("/v1/responses", headers={**HERE, "authorization": "Bearer sk-test"}) as ws:
        ws.send_text(json.dumps(TURN))
        ws.receive_text()
    assert up.calls[-1]["path"] == "/v1/responses" and EMAIL not in up.calls[-1]["frames"][0]


def test_a_message_that_is_not_a_request_is_masked_whole(env):
    up, client = env
    with client.websocket_connect("/v1/responses", headers=CHATGPT) as ws:
        ws.send_text(f"plain words with {KEY}")
        ws.receive_text()
    assert KEY not in up.calls[-1]["frames"][0]


@pytest.mark.parametrize("path,headers", [
    ("/v1/responses", {**CHATGPT, "origin": "https://evil.example"}),      # a web page's socket
    ("/v1/responses", {**CHATGPT, "host": "evil.example"}),                # not this machine by name
    ("/v1/realtime", CHATGPT),                                             # a path never recorded
    ("/omna/health", CHATGPT),
])
def test_other_sockets_are_refused_before_the_provider_is_reached(env, path, headers):
    up, client = env
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(path, headers=headers):
            pass
    assert up.calls == []


def test_when_the_provider_refuses_so_does_omna(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        dead = s.getsockname()[1]
    app = create_app(MaskingSession(), openai_upstream=f"http://127.0.0.1:{dead}", chatgpt_upstream=f"http://127.0.0.1:{dead}/x")
    with TestClient(app, base_url="http://127.0.0.1:7788") as client:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/v1/responses", headers=CHATGPT):
                pass
    assert receipts.tail(1)[0]["note"] == "websocket-refused"
