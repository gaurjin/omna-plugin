import json

import pytest

from omna_plugin.engine import MaskingSession, TOKEN_RE
from omna_plugin.stream import StreamRestorer
from omna_plugin.style import REALISTIC

EMAIL = "john.smith@acme.com"


@pytest.fixture
def session(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    s = MaskingSession()
    return s


def token_for(session, value):
    return TOKEN_RE.search(session.mask_text(f"x {value} x").masked).group(0)


def a_delta(text, index=0):
    evt = {"type": "content_block_delta", "index": index, "delta": {"type": "text_delta", "text": text}}
    return f"event: content_block_delta\ndata: {json.dumps(evt)}\n\n".encode()


def a_json_delta(pj, index=0):
    evt = {"type": "content_block_delta", "index": index, "delta": {"type": "input_json_delta", "partial_json": pj}}
    return f"event: content_block_delta\ndata: {json.dumps(evt)}\n\n".encode()


def texts(out: bytes):
    """Collect text_delta texts from a stream of frames."""
    res = []
    for frame in out.split(b"\n\n"):
        for line in frame.split(b"\n"):
            if line.startswith(b"data:"):
                evt = json.loads(line[5:])
                d = evt.get("delta") or {}
                if "text" in d:
                    res.append(d["text"])
                if "partial_json" in d:
                    res.append(d["partial_json"])
    return res


def test_token_split_across_chunks_is_restored(session):
    tok = token_for(session, EMAIL)  # e.g. [EMAIL_1]
    r = StreamRestorer(session)
    out = r.feed(a_delta("Hi " + tok[:4])) + r.feed(a_delta(tok[4:] + "!"))
    out += r.feed(b"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
    out += r.flush()
    assert "".join(texts(out)) == f"Hi {EMAIL}!"


def test_lone_bracket_is_released_at_block_end(session):
    r = StreamRestorer(session)
    out = r.feed(a_delta("array[")) + r.feed(a_delta("0] done"))
    out += r.feed(b"event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
    out += r.flush()
    assert "".join(texts(out)) == "array[0] done"


def test_input_json_delta_restores_with_json_escaping(session):
    name = 'O"Brien Ltd'
    tok = token_for(session, "quote@example.com")
    session._token_to_value[tok] = name  # force a value that needs escaping
    r = StreamRestorer(session)
    out = r.feed(a_json_delta('{"content": "to ' + tok[:3])) + r.feed(a_json_delta(tok[3:] + '"}'))
    out += r.flush()
    joined = "".join(texts(out))
    assert json.loads(joined) == {"content": f"to {name}"}


def test_ping_and_unknown_frames_pass_through_byte_identical(session):
    r = StreamRestorer(session)
    ping = b"event: ping\ndata: {\"type\": \"ping\"}\n\n"
    start = b"event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m\"}}\n\n"
    comment = b": keep-alive\n\n"
    assert r.feed(ping) == ping
    assert r.feed(start) == start
    assert r.feed(comment) == comment


def test_partial_frame_waits_for_completion(session):
    tok = token_for(session, EMAIL)
    r = StreamRestorer(session)
    frame = a_delta("mail " + tok)
    assert r.feed(frame[:10]) == b""
    out = r.feed(frame[10:]) + r.flush()
    assert texts(out) == [f"mail {EMAIL}"]


def test_openai_chat_delta_restored(session):
    tok = token_for(session, EMAIL)
    r = StreamRestorer(session)
    e1 = {"choices": [{"index": 0, "delta": {"content": "See " + tok[:5]}}]}
    e2 = {"choices": [{"index": 0, "delta": {"content": tok[5:] + "."}, "finish_reason": "stop"}]}
    out = r.feed(f"data: {json.dumps(e1)}\n\n".encode()) + r.feed(f"data: {json.dumps(e2)}\n\n".encode())
    out += r.feed(b"data: [DONE]\n\n") + r.flush()
    contents = []
    for frame in out.split(b"\n\n"):
        if frame.startswith(b"data: {"):
            contents.append(json.loads(frame[6:])["choices"][0]["delta"].get("content", ""))
    assert "".join(contents) == f"See {EMAIL}."
    assert out.endswith(b"data: [DONE]\n\n")


def test_responses_api_delta_restored(session):
    tok = token_for(session, EMAIL)
    r = StreamRestorer(session)
    e = {"type": "response.output_text.delta", "output_index": 0, "content_index": 0, "delta": "to " + tok}
    out = r.feed(f"event: response.output_text.delta\ndata: {json.dumps(e)}\n\n".encode()) + r.flush()
    assert json.loads(out.split(b"data: ")[1])["delta"] == f"to {EMAIL}"


# ---------------------------------------------------------------- realistic style

def fake_for_value(session, value):
    """Mask `value` in the realistic style and return the fake that replaced it."""
    return session.mask_text(f"x {value} x", style=REALISTIC).masked[2:-2]


def test_a_fake_value_split_across_chunks_is_restored(session):
    """A fake value has no brackets, so a stream can split it anywhere. The
    hold-back has to work from the registry, not from a '[' it will never see."""
    fake = fake_for_value(session, EMAIL)
    r = StreamRestorer(session)
    out = b""
    for piece in ("Hi " + fake[:3], fake[3:7], fake[7:] + "!"):
        out += r.feed(a_delta(piece))
    out += r.feed(b'event: content_block_stop\ndata: {"type":"content_block_stop","index":0}\n\n')
    out += r.flush()
    joined = "".join(texts(out))
    assert joined == f"Hi {EMAIL}!"
    assert fake not in joined


def test_a_fake_value_broken_one_character_at_a_time_is_restored(session):
    fake = fake_for_value(session, EMAIL)
    r = StreamRestorer(session)
    out = b"".join(r.feed(a_delta(ch)) for ch in fake)
    out += r.flush()
    assert "".join(texts(out)) == EMAIL


def test_a_fake_value_in_tool_call_arguments_is_restored_and_json_escaped(session):
    fake = fake_for_value(session, EMAIL)
    session._fake_to_value[fake] = 'O"Brien Ltd'      # a value that needs escaping
    r = StreamRestorer(session)
    out = r.feed(a_json_delta('{"to": "' + fake[:4])) + r.feed(a_json_delta(fake[4:] + '"}'))
    out += r.flush()
    assert '{"to": "O\\"Brien Ltd"}' == "".join(texts(out))


def test_text_with_no_fakes_and_no_tokens_passes_through(session):
    fake_for_value(session, EMAIL)        # the registry is not empty
    r = StreamRestorer(session)
    out = r.feed(a_delta("nothing to see here")) + r.flush()
    assert "".join(texts(out)) == "nothing to see here"
