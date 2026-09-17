import copy

import pytest

from omna_plugin.body import mask_body, restore_body
from omna_plugin.engine import MaskingSession, TOKEN_RE

EMAIL = "john.smith@acme.com"
KEY = "AKIAIOSFODNN7EXAMPLE"
B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJ" * 12  # >256 chars, base64 only


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return MaskingSession()


def anthropic_body():
    return {
        "model": "claude-sonnet-5",
        "stream": True,
        "system": [
            {"type": "text", "text": f"You help {EMAIL}.", "cache_control": {"type": "ephemeral"}}
        ],
        "messages": [
            {"role": "user", "content": f"My key is {KEY}"},
            {
                "role": "assistant",
                "content": [
                    {"type": "thinking", "thinking": f"user mentioned {EMAIL}", "signature": "abc=="},
                    {"type": "tool_use", "id": "toolu_1", "name": "Read", "input": {"file_path": "/x", "note": EMAIL}},
                ],
            },
            {
                "role": "user",
                "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": f"contact: {EMAIL}"},
                    {"type": "tool_result", "tool_use_id": "toolu_2", "content": [{"type": "text", "text": f"again {EMAIL}"}]},
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": B64}},
                ],
            },
        ],
        "tools": [{"name": "Read", "description": f"reads {EMAIL}", "input_schema": {"type": "object"}}],
        "stop_sequences": ["[END]"],
    }


def test_anthropic_request_masked_everywhere_it_should_be(session):
    body = anthropic_body()
    original = copy.deepcopy(body)
    masked, counts = mask_body(session, body)
    assert body == original, "input must not be mutated"
    s = str(masked)
    assert KEY not in s
    # every prose occurrence of the email is gone...
    assert masked["system"][0]["text"] != original["system"][0]["text"]
    assert EMAIL not in masked["messages"][1]["content"][1]["input"]["note"]
    assert EMAIL not in masked["messages"][2]["content"][0]["content"]
    assert EMAIL not in masked["messages"][2]["content"][1]["content"][0]["text"]
    # ...but thinking, signature, tools, image data, cache_control are untouched
    assert masked["messages"][1]["content"][0] == original["messages"][1]["content"][0]
    assert masked["tools"] == original["tools"]
    assert masked["messages"][2]["content"][2]["source"]["data"] == B64
    assert masked["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert masked["stop_sequences"] == ["[END]"]
    assert masked["model"] == "claude-sonnet-5" and masked["stream"] is True
    assert counts["EMAIL"] == 4 and counts["AWS_KEY"] == 1
    assert "[SECRET_AWS_KEY_1]" in s
    # the same email became the same token everywhere (one email token + one secret token)
    toks = set(m.group(0) for m in TOKEN_RE.finditer(s))
    assert toks == {"[SECRET_AWS_KEY_1]", next(t for t in toks if t.startswith("[EMAIL_"))}


def test_openai_request_masked(session):
    body = {
        "model": "gpt-5",
        "messages": [
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": [{"type": "text", "text": f"mail {EMAIL}"}]},
            {"role": "tool", "tool_call_id": "c1", "content": f"row: {EMAIL}"},
        ],
    }
    masked, counts = mask_body(session, body)
    assert EMAIL not in str(masked)
    assert masked["messages"][0]["content"] == "You are helpful."
    assert counts == {"EMAIL": 2, "_pii": 2}


def test_response_restore_puts_values_back(session):
    tok = TOKEN_RE.search(session.mask_text(f"mail {EMAIL}").masked).group(0)
    resp = {
        "id": "msg_1",
        "content": [
            {"type": "text", "text": f"I emailed {tok}."},
            {"type": "tool_use", "id": "t", "name": "Write", "input": {"content": f"to: {tok}"}},
            {"type": "thinking", "thinking": f"about {tok}", "signature": "s"},
        ],
    }
    out = restore_body(session, resp)
    assert out["content"][0]["text"] == f"I emailed {EMAIL}."
    assert out["content"][1]["input"]["content"] == f"to: {EMAIL}"
    assert out["content"][2]["thinking"] == f"about {tok}"  # thinking stays as the model wrote it
