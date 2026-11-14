"""A reply from one website never gets back a value that was sent to another.

Security review 2026-11-11, lead L4 ("not run"): through the system door,
could chatgpt.com answer with a stand-in claude.ai was given, and have Omna
put the real value into ITS page? Tested here on every reply shape the door
restores: JSON, streamed text, streamed JSON and a WebSocket message.
All values are fake; stand-ins are built from pieces.
"""

from __future__ import annotations

import asyncio
import json

import pytest
from mitmproxy import http
from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketData, WebSocketMessage
from wsproto.frame_protocol import Opcode

from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline
from omna_plugin.policy import Policy
from omna_plugin.system_door import OmnaAddon

EMAIL = "zoe.madeup@example.com"
TOKEN = "ghp_" + "fgYFNmLOZlhOWtmhi0EwWcTCEsLvKQdOrH3k"
EMAIL_1 = "[EMAIL" + "_1]"
SECRET_1 = "[SECRET_GITHUB" + "_TOKEN_1]"


@pytest.fixture
def addon(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return OmnaAddon(Pipeline(MaskingSession()), Policy(), door="system", resolver=lambda peer: (1, "Google Chrome"))


def _flow(host, path="/api/chat/completion", body=b"{}"):
    f = tflow.tflow()
    f.request.host, f.request.port, f.request.scheme = host, 443, "https"
    f.request.headers["host"] = host
    f.request.path, f.request.method = path, "POST"
    f.request.headers["content-type"] = "application/json"
    f.request.set_content(body)
    return f


def _ask(addon, host, prompt):
    f = _flow(host, body=json.dumps({"prompt": prompt}).encode())
    asyncio.run(addon.request(f))
    assert f.response is None
    return f


def _reply(addon, f, body: bytes, ctype: str) -> str:
    f.response = http.Response.make(200, body, {"content-type": ctype})
    addon.responseheaders(f)
    if callable(f.response.stream):
        out = f.response.stream(body)
        end = f.response.stream(b"")
        join = lambda x: b"".join(x) if isinstance(x, list) else x   # noqa: E731
        return (join(out) + join(end)).decode()
    addon.response(f)
    return f.response.get_content().decode()


@pytest.mark.parametrize("ctype, shape", [
    ("application/json", lambda s: json.dumps({"answer": f"it is {s}"}).encode()),
    ("text/event-stream", lambda s: f'data: {json.dumps({"delta": "it is " + s})}\n\n'.encode()),
    ("text/plain", lambda s: f"it is {s}".encode()),
])
def test_another_sites_reply_gets_the_stand_in_back_not_the_value(addon, ctype, shape):
    sent = _ask(addon, "claude.ai", f"my email is {EMAIL} and my token is {TOKEN}")
    seen = sent.request.get_content().decode()
    assert EMAIL not in seen and TOKEN not in seen and EMAIL_1 in seen and SECRET_1 in seen

    # The site the values were sent to gets them back...
    own = _reply(addon, sent, shape(EMAIL_1), ctype)
    assert EMAIL in own

    # ...another site, guessing the same stand-ins, gets nothing.
    other = _ask(addon, "chatgpt.com", "hello there, nothing private")
    got = _reply(addon, other, shape(f"{EMAIL_1} {SECRET_1}"), ctype)
    assert EMAIL not in got and TOKEN not in got
    assert EMAIL_1 in got and SECRET_1 in got


def test_a_websocket_on_another_site_gets_nothing_back_either(addon):
    _ask(addon, "claude.ai", f"my email is {EMAIL}")
    f = _flow("chatgpt.com", path="/ws")
    f.request.method = "GET"
    f.websocket = WebSocketData()
    f.websocket.messages.append(WebSocketMessage(Opcode.TEXT, False, json.dumps({"text": f"it is {EMAIL_1}"}).encode()))
    addon.websocket_message(f)
    assert EMAIL not in f.websocket.messages[-1].content.decode()


def test_a_sister_address_of_the_same_site_still_gets_its_own_values(addon):
    # chatgpt.com and its own file storage are one site (sites.site_of).
    _ask(addon, "chatgpt.com", f"my email is {EMAIL}")
    f = _ask(addon, "chatgpt.com", "again")
    assert EMAIL in _reply(addon, f, json.dumps({"answer": EMAIL_1}).encode(), "application/json")


def test_the_same_value_sent_to_both_sites_comes_back_on_both(addon):
    a = _ask(addon, "claude.ai", f"my email is {EMAIL}")
    b = _ask(addon, "chatgpt.com", f"my email is {EMAIL}")
    for f in (a, b):
        assert EMAIL in _reply(addon, f, json.dumps({"answer": EMAIL_1}).encode(), "application/json")
