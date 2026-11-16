"""A request body in the packed binary format (protobuf) is read and masked.

Found live 2026-11-15: the Claude desktop app 5.1231.2 sends the person's
message as ``application/proto`` to
``/claudeai-rpc/…ConversationService/PerformAction`` and opens its reply
channel as ``application/connect+proto`` (``…/StreamTimeline``). The curl
command could read neither: the message went out unmasked and the reply
channel was refused ("Claude's replies aren't reaching this page"). The app
had worked on 2026-10-25 (3.6556.1), when it still sent JSON.

The bodies below have the recorded request's shape, built by hand."""

import struct

import pytest

from omna_plugin import protobuf
from omna_plugin.adapters import for_host
from omna_plugin.adapters.base import RequestView
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline

EMAIL = "jane.doe@example.com"
GH = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
MSG = f"Test only, fake data: my name is Jane Doe, email {EMAIL}. Reply with only the email address written backwards."
SESSION = "960e9c32-328b-4891-b226-57c976a67815"
SIGNATURE = bytes(range(128, 192))                      # 64 raw bytes: not text, not a message
TOK = "[EMAIL_" "1]"        # two pieces: see CLAUDE.md "Token literals"
RPC = "/claudeai-rpc/anthropic.bard.api.v1alpha.ConversationService/"


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def f(num: int, value) -> bytes:
    """One field: an int is a varint, bytes/str a length-delimited value."""
    if isinstance(value, int):
        return varint(num << 3) + varint(value)
    raw = value.encode() if isinstance(value, str) else value
    return varint(num << 3 | 2) + varint(len(raw)) + raw


def perform_action(message: str = MSG) -> bytes:
    """The recorded PerformAction: a header (session, flags, locale, a
    32-byte value), then the turn — two message ids, the typed message, the
    model, the tool ids — and a signed registration at the end."""
    header = f(1, f(1, "sess_1c06c9ad4a5d982c") + f(2, 1)) + f(2, SESSION) + f(3, 3) + f(14, "en-US") + f(15, bytes(range(200, 232)))
    tools = f(1, f(1, "dc4fc007-8f4f-46ed-a58c-b8a74a276eff:get_company_data") + f(2, 1)) * 4
    turn = (f(1, "edfd4639-cb00-46d1-96d5-1aad502b4b9e") + f(2, "14f2337e-a4a4-45f1-834b-7b9cfbe09a56")
            + f(3, message) + f(7, f(2, "claude-haiku-5-5")) + f(8, f(1, 1) + f(8, tools)))
    signed = f(1, "e5f9b7ea-513e-46b3-b753-1dd377655dfc") + f(2, f(1, "creg_e5f9b7ea") + f(2, SIGNATURE))
    return f(1, header) + f(2, turn) + f(40, signed) + struct.pack("<BI", 0x5D, 7)   # + a fixed32 field


def frame(payload: bytes, flags: int = 0) -> bytes:
    return bytes([flags]) + struct.pack(">I", len(payload)) + payload


def _mask(body: bytes, ct: str = "application/proto", path: str = RPC + "PerformAction", session=None):
    pipe = Pipeline(session or MaskingSession())
    req = RequestView(host="claude.ai", method="POST", path=path, content_type=ct, body=body, headers={})
    with pipe.session.sending_to("Claude"):
        return for_host("claude.ai").mask(pipe, req), pipe


# ---------------------------------------------------------------- the reader

def test_a_body_with_nothing_to_mask_comes_back_byte_for_byte():
    body = perform_action("hello there, how are you today")
    assert protobuf.rewrite(body, lambda s: s) is body


def test_changing_a_text_fixes_every_length_around_it():
    body = perform_action()
    out = protobuf.rewrite(body, lambda s: s.replace(EMAIL, TOK))
    assert out == perform_action(MSG.replace(EMAIL, TOK))


def test_raw_bytes_are_never_touched():
    seen = []
    protobuf.rewrite(perform_action(), lambda s: seen.append(s) or s)
    assert MSG in seen and SESSION in seen
    assert not any("�" in s for s in seen)


@pytest.mark.parametrize("junk", [b"", b"\x07", b"\x0a\x05ab", b"\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01", b"plain words, not a packed body"])
def test_what_is_not_this_format_is_reported_not_guessed(junk):
    assert protobuf.rewrite(junk, lambda s: s + "!") is None


def test_a_framed_stream_is_read_frame_by_frame():
    a, b = perform_action(), f(1, SESSION)
    out = protobuf.rewrite_frames(frame(a) + frame(b), lambda s: s.replace(EMAIL, TOK))
    assert out == frame(perform_action(MSG.replace(EMAIL, TOK))) + frame(b)
    end = frame(b'{"metadata":{}}', flags=2)                   # the end-of-stream note is JSON: left alone
    assert protobuf.rewrite_frames(frame(b) + end, lambda s: s.upper()).endswith(end)
    same = frame(b) + end
    assert protobuf.rewrite_frames(same, lambda s: s) is same
    assert protobuf.rewrite_frames(b"\x00\x00\x00\x00\x09abc", lambda s: s) is None      # length runs past the end


# ---------------------------------------------------------------- the product

def test_the_claude_desktop_apps_message_is_masked():
    out, _ = _mask(perform_action())
    assert out.refused is None and out.body is not None
    assert EMAIL.encode() not in out.body and b"Jane Doe" not in out.body
    seen = []
    assert protobuf.rewrite(out.body, lambda s: seen.append(s) or s) is not None      # still a valid body
    sent = next(s for s in seen if s.startswith("Test only"))
    assert TOK in sent
    # the app's own parts are exactly as they came
    assert SESSION in seen and "claude-haiku-5-5" in seen and "sess_1c06c9ad4a5d982c" in seen
    assert SIGNATURE in out.body and bytes(range(200, 232)) in out.body
    assert out.stats.pii >= 1


def test_a_secret_in_the_message_is_masked_too():
    out, _ = _mask(perform_action(f"deploy with {GH} please"))
    assert GH.encode() not in out.body


def test_the_reply_channel_is_opened_not_refused():
    """StreamTimeline's request holds only the app's ids: it must go through
    untouched, or the app shows "Claude's replies aren't reaching this page"."""
    body = frame(f(1, SESSION) + f(3, 1) + f(5, "en-US") + f(8, "America/New_York"))
    out, _ = _mask(body, ct="application/connect+proto", path=RPC + "StreamTimeline")
    assert out.refused is None
    assert out.body is None or out.body == body


def test_a_packed_body_omna_cannot_read_on_a_prompt_address_is_still_refused():
    out, _ = _mask(b"\xff\xfe not this format", ct="application/proto", path="/api/chat/completion")
    assert out.refused == "unparseable"


def test_only_text_that_reads_like_writing_gets_the_smart_models(monkeypatch, tmp_path):
    """Owner rule 2026-11-15: the person's message gets smart masking; the
    app's ids, model and tool names get fast masking (the tiebreaker)."""
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin import smart
    monkeypatch.setattr(smart, "ready_models", lambda: [smart.COMPACT, smart.PRIVACY_FILTER])
    seen = {}
    real = smart.mask

    def spy(text, on, ruleset=None):
        seen[text] = smart._choice() if on else None
        return real(text, False, ruleset)

    monkeypatch.setattr(smart, "mask", spy)
    _mask(perform_action(), session=MaskingSession(smart=True))
    assert seen[MSG] is not None
    for own in (SESSION, "claude-haiku-5-5", "en-US", "dc4fc007-8f4f-46ed-a58c-b8a74a276eff:get_company_data"):
        assert seen.get(own) is None, own


# ---------------------------------------------------------------- the reply

def _reply_frames(text: str) -> bytes:
    """StreamTimeline's reply, as recorded: some frames compressed (gzip),
    some not, the same answer in more than one, an end-of-stream note last."""
    import gzip
    one = f(1, f(2, SESSION) + f(3, f(1, text)))
    return (frame(gzip.compress(one), flags=1) + frame(one) + frame(f(1, SESSION))
            + frame(b'{"metadata":{}}', flags=2))


def _texts(frames: bytes) -> list[str]:
    import gzip
    seen, i = [], 0
    while i < len(frames):
        flags, size = frames[i], struct.unpack(">I", frames[i + 1:i + 5])[0]
        body = frames[i + 5:i + 5 + size]
        i += 5 + size
        if not flags & 2:
            assert protobuf.rewrite(gzip.decompress(body) if flags & 1 else body, lambda s: seen.append(s) or s) is not None
    return seen


def _pipe_that_knows_the_email():
    pipe = Pipeline(MaskingSession())
    with pipe.session.sending_to("Claude"):
        masked, _ = pipe.mask_text(f"mail {EMAIL}")
    assert TOK in masked
    return pipe


@pytest.mark.parametrize("piece", [1, 7, 64, 100000])
def test_the_streamed_reply_gets_the_real_values_back(piece):
    """Whatever size the pieces arrive in, every frame comes out whole."""
    pipe = _pipe_that_knows_the_email()
    data = _reply_frames(f"The address is {TOK}, as you asked.")
    reader = pipe.proto_restorer(site="Claude")
    out = b"".join(reader.feed(data[i:i + piece]) for i in range(0, len(data), piece)) + reader.flush()
    texts = _texts(out)
    assert texts.count(f"The address is {EMAIL}, as you asked.") == 2
    assert not any(TOK in t for t in texts)
    assert out.endswith(frame(b'{"metadata":{}}', flags=2))


def test_a_reply_omna_cannot_read_arrives_exactly_as_it_came():
    pipe = _pipe_that_knows_the_email()
    junk = frame(b"\xff\xfe not this format") + frame(b"not gzip", flags=1) + b"\x00\x00"
    reader = pipe.proto_restorer(site="Claude")
    assert reader.feed(junk) + reader.flush() == junk
    assert pipe.restore_proto(b"\xff\xfe not this format", site="Claude") == b"\xff\xfe not this format"


def test_a_plain_reply_gets_the_real_values_back():
    pipe = _pipe_that_knows_the_email()
    out = pipe.restore_proto(f(1, f(3, f"mail {TOK} today")), site="Claude")
    assert out == f(1, f(3, f"mail {EMAIL} today"))


def test_a_value_sent_to_another_site_is_not_put_back_here():
    pipe = _pipe_that_knows_the_email()
    body = f(1, f(3, f"mail {TOK} today"))
    assert pipe.restore_proto(body, site="ChatGPT") == body


def _door_flow(tmp_path, monkeypatch, content_type):
    from mitmproxy.test import tflow
    from omna_plugin.policy import Policy
    from omna_plugin.system_door import OmnaAddon
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pipe = _pipe_that_knows_the_email()
    addon = OmnaAddon(pipe, Policy(), door="system", resolver=lambda peer: (1, "Claude"))
    fl = tflow.tflow(resp=True)
    fl.request.host, fl.request.port, fl.request.scheme = "claude.ai", 443, "https"
    fl.request.headers["host"] = "claude.ai"
    fl.request.path = RPC + "StreamTimeline"
    fl.response.headers["content-type"] = content_type
    return addon, fl


def test_the_door_restores_the_desktop_apps_streamed_reply(tmp_path, monkeypatch):
    addon, fl = _door_flow(tmp_path, monkeypatch, "application/connect+proto")
    addon.responseheaders(fl)
    assert callable(fl.response.stream)
    data = _reply_frames(f"The address is {TOK}.")
    out = b"".join(x for i in range(0, len(data), 50) for x in [fl.response.stream(data[i:i + 50])] if x)
    out += fl.response.stream(b"")
    assert f"The address is {EMAIL}." in _texts(out)


def test_the_door_restores_the_desktop_apps_plain_reply(tmp_path, monkeypatch):
    addon, fl = _door_flow(tmp_path, monkeypatch, "application/proto")
    fl.response.content = f(1, f(3, f"mail {TOK} today"))
    addon.responseheaders(fl)
    assert fl.response.stream is False
    addon.response(fl)
    assert fl.response.content == f(1, f(3, f"mail {EMAIL} today"))
