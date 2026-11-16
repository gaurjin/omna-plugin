"""Codex signed in with a ChatGPT account (recorded live 2026-11-16, Codex
0.169 inside the ChatGPT desktop app): the conversation goes over a WebSocket
to chatgpt.com/backend-api/codex/responses, each client message a Responses
request ({"type": "response.create", "model", "input": [...]}). Masking the
whole message as flat text edited 37 of Codex's own fields — ids, tool
descriptions, even two KEY NAMES ("access_programs", "session_id") — and
OpenAI refused the turn ("Unsupported parameter"). Owner rule 2026-11-15:
only the person's data is masked. Shapes below are that message's, ids made up."""
import copy
import json

import pytest
from mitmproxy.test import tflow
from mitmproxy.websocket import WebSocketData, WebSocketMessage
from wsproto.frame_protocol import Opcode

from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline
from omna_plugin.policy import Policy
from omna_plugin.system_door import OmnaAddon

GH = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"[:36]
UUID = "0f9e8d7c-6b5a-7f3e-9d2c-1b0a9f8e7d6c"
FRAME = {
    "type": "response.create", "model": "gpt-x", "stream": True,
    "previous_response_id": "resp_00aa11bb22cc33dd44ee55ff66aa77bb88cc99dd00ee11ff22",
    "input": [
        {"type": "additional_tools", "id": "at_" + UUID, "role": "developer",
         "tools": [{"type": "namespace", "name": "functions", "tools": [
             {"type": "custom", "name": "spawn_agent", "description": "Spawn an agent. Mail ops@example.com, token " + GH}]}]},
        {"type": "message", "id": "msg_" + UUID, "role": "developer",
         "internal_chat_message_metadata_passthrough": {"turn_id": UUID, "content_item_kinds": ["model.base_instructions"]},
         "content": [{"type": "input_text", "text": "Avoid asking Jane Doe. Write to help@example.com."}]},
        {"type": "message", "id": "msg_" + UUID, "role": "user",
         "internal_chat_message_metadata_passthrough": {"turn_id": UUID, "content_item_kinds": ["user.text"]},
         "content": [{"type": "input_text", "text": f"mail jane.doe@example.com, card 4111 1111 1111 1111, token {GH}"}]},
    ],
    "tool_choice": "auto", "store": False, "prompt_cache_key": UUID,
    "client_metadata": {"session_id": UUID, "thread_id": UUID, "x-codex-installation-id": UUID},
    "access_programs": {"enabled": True},
}


@pytest.fixture(autouse=True)
def iso(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))


def _send(frame, host="chatgpt.com", path="/backend-api/codex/responses", opcode=Opcode.TEXT):
    a = OmnaAddon(Pipeline(MaskingSession()), Policy(), door="system", resolver=lambda peer: (1, "Codex"))
    f = tflow.tflow()
    f.request.host = host; f.request.path = path; f.request.method = "GET"
    f.websocket = WebSocketData()
    f.websocket.messages.append(WebSocketMessage(opcode, True, json.dumps(frame).encode()))
    a.websocket_message(f)
    return f.websocket.messages[-1].content.decode()


@pytest.mark.parametrize("host,path", [("chatgpt.com", "/backend-api/codex/responses"), ("api.openai.com", "/v1/responses")])
def test_only_the_persons_message_is_masked(host, path):
    sent = json.loads(_send(FRAME, host, path))
    text = sent["input"][2]["content"][0]["text"]
    assert "jane.doe@example.com" not in text and "4111 1111 1111 1111" not in text and GH not in text
    want = copy.deepcopy(FRAME)
    want["input"][2]["content"][0]["text"] = text
    assert sent == want          # Codex's ids, tools, instructions and key names: exactly as sent


def test_a_binary_frame_that_is_json_gets_the_same_rule():
    sent = json.loads(_send(FRAME, opcode=Opcode.BINARY))
    assert sent["client_metadata"] == FRAME["client_metadata"] and GH not in sent["input"][2]["content"][0]["text"]


def test_a_message_that_is_not_a_request_is_still_masked_whole():
    """Anything else on the socket keeps the old rule: the whole text is checked."""
    sent = _send({"type": "conversation.item.create", "item": {"content": [{"type": "input_text", "text": "token " + GH}]}})
    assert GH not in sent
    assert GH not in _send({"type": "response.create", "input": "token " + GH})      # no "model": not the API shape


# ---- Codex's own notes inside the conversation (same recording): its
# "<environment_context>" message (folder, shell, today's date — the date was
# masked as a birth date) and each message's label block
# ("internal_chat_message_metadata_passthrough": "user.text" read as a person).
ENV = ("<environment_context>\n  <cwd>/Users/sam/work</cwd>\n  <shell>zsh</shell>\n"
       "  <current_date>2026-11-16</current_date>\n</environment_context>")


def _texts_checked(monkeypatch, frame):
    from omna_plugin import smart
    from omna_plugin.body import mask_body
    monkeypatch.setattr(smart, "ready_models", lambda: [smart.COMPACT, smart.PRIVACY_FILTER])
    seen, real = [], smart.mask

    def spy(text, on, ruleset=None):
        seen.append(text)
        return real(text, False, ruleset)

    monkeypatch.setattr(smart, "mask", spy)
    s = MaskingSession(smart=True)
    with s.sending_to("ChatGPT"):
        return mask_body(s, frame)[0], seen


def _with_env(text=ENV):
    frame = copy.deepcopy(FRAME)
    frame["input"].insert(2, {"type": "message", "id": "msg_" + UUID, "role": "user",
                              "internal_chat_message_metadata_passthrough": {
                                  "turn_id": UUID, "content_item_kinds": ["environments.environment_context"]},
                              "content": [{"type": "input_text", "text": text}]})
    return frame


def test_codexs_environment_note_and_message_labels_go_as_they_are(monkeypatch):
    frame = _with_env()
    out, seen = _texts_checked(monkeypatch, frame)
    assert out["input"][2] == frame["input"][2]
    assert out["input"][3]["internal_chat_message_metadata_passthrough"] == frame["input"][3]["internal_chat_message_metadata_passthrough"]
    assert not any("environment_context" in t or "user.text" in t or UUID in t for t in seen)
    assert GH not in str(out["input"][3]["content"])          # the person's message is still masked


def test_data_glued_behind_the_environment_note_is_checked(monkeypatch):
    """Same tiebreaker as Claude Code's notes: anything after the note's own
    closing tag makes the block the person's data."""
    out, _ = _texts_checked(monkeypatch, _with_env(ENV + "\nmy token is " + GH))
    assert GH not in str(out["input"][2])
