"""Antigravity CLI (`agy`, Google's coding tool for personal accounts since
2026-06-18), recorded live 2026-11-16 through the system door.

Its message goes to daily-cloudcode-pa.googleapis.com/v1internal:
streamGenerateContent wrapped in Google's Code Assist envelope:
{"project", "requestId", "model", "userAgent", "requestType",
 "request": {"contents", "systemInstruction", "tools", "labels",
             "generationConfig", "sessionId"}}.
Before this, the envelope was not read as an AI API request, so the whole
body was masked: 32 of Antigravity's own words in its instructions and tool
list were edited (owner rule 2026-11-15: only what the person sends).
"""

import pytest

from omna_plugin import sites
from omna_plugin.body import is_api_request, mask_body
from omna_plugin.engine import MaskingSession

EMAIL = "matteo.ak@ridgelinebuild.example"
GH = "ghp_" + "aB3dE5fG7hJ9kL1mN3pQ5rS7tU9vW1xY3zA5"[:36]


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return MaskingSession()


def _body():
    return {
        "project": "aicode-consumers", "requestId": "agent/1/2", "model": "gemini-4-argon-medium",
        "userAgent": "antigravity", "requestType": "agent",
        "request": {
            "contents": [{"role": "user", "parts": [{"text":
                f"<USER_REQUEST>\nour contractor's email is {EMAIL}, token {GH}\n</USER_REQUEST>"}]}],
            "systemInstruction": {"role": "user", "parts": [{"text":
                f"You are Antigravity. Example: write to {EMAIL} using key {GH}."}]},
            "tools": [{"functionDeclarations": [{"name": "run_command",
                       "description": f"Runs a command. Example: curl -H 'Authorization: {GH}'"}]}],
            "labels": {"product": "antigravity"},
            "generationConfig": {"temperature": 1},
            "sessionId": "-123",
        },
    }


def test_the_envelope_is_an_ai_api_request():
    assert is_api_request(_body())


def test_only_the_persons_message_is_masked(session):
    body = _body()
    masked, _, _ = mask_body(session, body)
    text = masked["request"]["contents"][0]["parts"][0]["text"]
    assert EMAIL not in text and GH not in text
    # Antigravity's own instructions and tool list go exactly as they came.
    for key in ("systemInstruction", "tools", "labels", "generationConfig", "sessionId"):
        assert masked["request"][key] == body["request"][key], key
    for key in ("project", "requestId", "model", "userAgent", "requestType"):
        assert masked[key] == body[key], key


def test_an_envelope_without_a_conversation_is_not_an_api_request():
    assert not is_api_request({"project": "p", "request": {"settings": "x"}})


def test_both_antigravity_addresses_are_listed():
    """"daily-" is a prefix, not a subdomain: both names must be listed."""
    for host in ("daily-cloudcode-pa.googleapis.com", "cloudcode-pa.googleapis.com"):
        assert host in sites.all_hosts()
        assert sites.is_agent_api(host)


# ---- the reply: Gemini's streamed events, wrapped in "response" by Code Assist

import json as _json

from omna_plugin.engine import TOKEN_RE
from omna_plugin.stream import StreamRestorer

PHONE = "212-555-0118"


def _evt(text=None, finish=None, call=None, wrap=True):
    parts = []
    if text is not None:
        parts.append({"text": text})
    if call is not None:
        parts.append({"functionCall": call})
    cand = {"content": {"role": "model", "parts": parts}, "index": 0}
    if finish:
        cand["finishReason"] = finish
    g = {"candidates": [cand]}
    return f"data: {_json.dumps({'response': g} if wrap else g)}\r\n\r\n".encode()


def _texts(out: bytes):
    res = []
    for frame in out.replace(b"\r\n", b"\n").split(b"\n\n"):
        for line in frame.split(b"\n"):
            if line.startswith(b"data:"):
                e = _json.loads(line[5:])
                g = e.get("response", e)
                for c in g.get("candidates", []):
                    for p in (c.get("content") or {}).get("parts", []):
                        if "text" in p:
                            res.append(p["text"])
    return "".join(res)


@pytest.mark.parametrize("wrap", [True, False])
def test_a_stand_in_cut_between_two_events_is_restored(session, wrap):
    """Live 2026-11-16: the reply showed the phone's stand-in, cut over two
    events — the flat restorer saw JSON between the halves."""
    tok = TOKEN_RE.search(session.mask_text(f"call {PHONE}").masked).group(0)
    r = StreamRestorer(session)
    out = r.feed(_evt("cell: " + tok[:4], wrap=wrap)) + r.feed(_evt(tok[4:] + ", thanks", wrap=wrap))
    out += r.feed(_evt("", finish="STOP", wrap=wrap)) + r.flush()
    assert _texts(out) == f"cell: {PHONE}, thanks"


def test_held_text_is_released_when_the_stream_ends_without_a_finish(session):
    r = StreamRestorer(session)
    out = r.feed(_evt("ends with [")) + r.flush()
    assert _texts(out) == "ends with ["


def test_a_secret_stays_a_stand_in_inside_a_tool_call(session):
    masked = session.mask_text(f"token {GH}").masked
    tok = TOKEN_RE.search(masked).group(0)

    class Tools:      # the tool-call view: a secret is never put back
        def restore_text(self, text, json_escape=False):
            return text

        def hold_from(self, text):
            return len(text)

    r = StreamRestorer(session, tools=Tools())
    out = r.feed(_evt(call={"name": "run_command", "args": {"command": f"git push {tok}"}})) + r.flush()
    assert GH not in out.decode() and tok in out.decode()
