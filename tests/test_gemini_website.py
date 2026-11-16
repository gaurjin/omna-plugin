"""The Gemini website: the message is masked, Google's own parts go as they are.

Found live 2026-11-16 (gemini.google.com, signed in, one typed message):

1. The message no longer goes to gemini.google.com. The page opens a channel
   to ``geminiweb-pa.clients6.google.com/v1/processSession`` and sends it
   there as a form of base64 values, each one the packed binary format. That
   address was on no list: the message went out unmasked. Once listed, the
   fast rules damaged the base64 and Google refused it ("Unable to
   base64-decode request data").
2. Every call the page makes itself (``/_/BardChatUi/data/batchexecute``) was
   masked as one flat text: Google's function names became people and
   secrets, the anti-forgery token ``at`` was edited on every call.

The bodies below have the recorded requests' shape, built by hand."""

import base64
import json
from urllib.parse import quote, unquote_plus, unquote_to_bytes

import pytest

from omna_plugin import batchexecute, protobuf, sites, webchannel
from omna_plugin.adapters import for_host
from omna_plugin.adapters.base import RequestView
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline

EMAIL = "cosima.vl@pinehollowtravel.org"
MSG = f"Write a handover note. The guest is Cosima Varghese, her booking went to {EMAIL}. Keep it short."
TOK = "[EMAIL_" "1]"        # two pieces: see CLAUDE.md "Token literals"
CHANNEL = "geminiweb-pa.clients6.google.com"
SESSION_PATH = "/v1/processSession?VER=8&gsessionid=8_hQvyAYH&SID=uINExNjE9Ix&RID=77821&AID=0&zx=ioou5afb61zs&t=1"
BATCH_PATH = "/_/BardChatUi/data/batchexecute?rpcids=MaZiqc&source-path=%2Fapp&bl=boq_gemini-web-uiserver_20261115.13_p0&hl=en&rt=c"
# Google's anti-abuse token: starts with "!", ~1650 letters, digits, "-" and "_".
GUARD = "!QkGlQSXNAAbg-Lv5wPhCT4Wafwp51Vk7AEABjq4o36nI_jOmIE7QxrCUlibZXy4AWLZshM8a2H2WVwvQK3v7u1ctTLggLz88FrZsa7ey2wogb" * 15
DEVICE = "38138D5C-A30B-44B8-AAE5-1D6283B39AA8"
AT = "AFk0UUVzMEkcBrz6ErzpESIAXd6G:1794843561592"
FORM = "application/x-www-form-urlencoded;charset=UTF-8"


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def f(num: int, value) -> bytes:
    if isinstance(value, int):
        return varint(num << 3) + varint(value)
    raw = value.encode() if isinstance(value, str) else value
    return varint(num << 3 | 2) + varint(len(raw)) + raw


def start(message: str = MSG) -> bytes:
    """The recorded opening value: device id, language, the message, Google's
    anti-abuse token, a request id."""
    turn = (f(1, f(1, message) + f(2, 0) + f(7, 0)) + f(2, f(1, "en")) + f(4, GUARD)
            + f(5, "fd68cadce5574a27824c8d0778a563f1") + f(8, 1) + f(60, DEVICE))
    return f(1, f(1, f(1, 1) + f(3, "en") + f(4, DEVICE)) + f(2, 0) + f(8, f(5, f(1, turn) + f(4, 1))))


def send(message: str = MSG) -> bytes:
    return f(2, f(1, 1) + f(9, f(1, message)))


def form(*values: bytes, ofs: int = 0) -> bytes:
    pairs = [f"count={len(values)}", f"ofs={ofs}"]
    pairs += [f"req{i}___data__=" + quote(base64.b64encode(v), safe="") for i, v in enumerate(values)]
    return "&".join(pairs).encode()


def values(body: bytes) -> list[bytes]:
    return [base64.b64decode(unquote_to_bytes(p.partition(b"=")[2]), validate=True)
            for p in body.split(b"&") if b"___data__" in p]


def texts(packed: bytes) -> list[str]:
    seen = []
    assert protobuf.rewrite(packed, lambda s: seen.append(s) or s) is not None
    return seen


def _mask(body: bytes, host: str = CHANNEL, path: str = SESSION_PATH, ct: str = "application/x-www-form-urlencoded", session=None):
    pipe = Pipeline(session or MaskingSession())
    req = RequestView(host=host, method="POST", path=path, content_type=ct, body=body, headers={})
    with pipe.session.sending_to(sites.site_of(host)):
        return for_host(host).mask(pipe, req), pipe


# ---------------------------------------------------------------- the list

def test_the_address_the_message_goes_to_is_on_the_list_and_is_gemini():
    assert sites.listed(CHANNEL)
    assert sites.site_of(CHANNEL) == sites.site_of("gemini.google.com") == "Gemini"
    assert sites.channel(CHANNEL, SESSION_PATH)
    assert not sites.channel("gemini.google.com", SESSION_PATH)
    assert not sites.channel(CHANNEL, "/v1/other")


# ---------------------------------------------------------------- the message

def test_the_message_is_masked_and_googles_own_parts_are_untouched():
    body = form(start(), send())
    out, _ = _mask(body)
    assert out.refused is None and out.body is not None
    assert EMAIL.encode() not in b"".join(values(out.body))
    first, second = values(out.body)
    assert any(TOK in t for t in texts(first)) and any(TOK in t for t in texts(second))
    for own in (GUARD, DEVICE, "fd68cadce5574a27824c8d0778a563f1", "en"):
        assert own in texts(first), own[:20]
    assert out.body.startswith(b"count=2&ofs=0&req0___data__=")
    assert out.stats.pii >= 1


def test_what_google_gets_is_still_valid_base64_of_a_valid_body():
    """The live failure: "Unable to base64-decode request data"."""
    out, _ = _mask(form(start(), send()))
    for pair in out.body.split(b"&"):
        key, _, value = pair.partition(b"=")
        if b"___data__" in key:
            assert b"[" not in value and b"%5B" not in value          # no stand-in written into the base64
            assert protobuf.rewrite(base64.b64decode(unquote_to_bytes(value), validate=True), lambda s: s) is not None


@pytest.mark.parametrize("body", [b"count=0", form(f(4, f(1, 1)), ofs=2), form(start("what is the tallest mountain in Peru"))])
def test_a_body_with_nothing_to_mask_goes_exactly_as_it_came(body):
    out, _ = _mask(body)
    assert out.refused is None and out.body is None


@pytest.mark.parametrize("value", ["not base64 at all!", quote(base64.b64encode(b"\xff\xfe\x00 not the packed format"), safe="")])
def test_a_value_omna_cannot_read_is_refused_never_sent_unread(value):
    out, _ = _mask(f"count=1&ofs=0&req0___data__={value}".encode())
    assert out.refused == "unparseable"


def test_only_the_message_gets_the_smart_models(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin import smart
    monkeypatch.setattr(smart, "ready_models", lambda: [smart.COMPACT, smart.PRIVACY_FILTER])
    seen = {}
    real = smart.mask

    def spy(text, on, ruleset=None):
        seen[text] = smart._choice() if on else None
        return real(text, False, ruleset)

    monkeypatch.setattr(smart, "mask", spy)
    _mask(form(start(), send()), session=MaskingSession(smart=True))
    assert seen[MSG] is not None
    for own in (GUARD, DEVICE, "en"):
        assert seen.get(own) is None, own[:20]


def test_a_renamed_value_is_read_or_refused_never_passed_unread():
    renamed = form(send()).replace(b"req0___data__", b"req0_payload")
    out, _ = _mask(renamed)
    assert out.body is not None and EMAIL.encode() not in base64.b64decode(unquote_to_bytes(out.body.split(b"=")[-1]))
    out, _ = _mask(b"count=1&ofs=0&req0_text=" + quote(MSG).encode())
    assert out.refused == "unparseable"


# ---------------------------------------------------------------- the reply

def piece(n: int, packed: bytes | None = None, raw: str | None = None) -> bytes:
    js = raw if raw is not None else json.dumps([[n, [base64.b64encode(packed).decode()]]], separators=(",", ":"))
    return str(len(js)).encode() + b"\n" + js.encode()


def answer(text: str) -> bytes:
    return f(2, f(1, 3) + f(7, f(1, f(1, 0) + f(2, f(1, "r_58e2fbfe0406de4d")) + f(4, f(4, f(5, f(1, "rc_0ee11c06ffc841aa") + f(2, f(1, text))))))))


def _reply(text: str) -> bytes:
    return (piece(1, raw='[[1,["noop"]]]') + piece(2, b"\x0a\x00") + piece(3, answer(text[:20]))
            + piece(4, answer(text)) + piece(5, raw='[[5,["IgA="]]]'))


def _pieces(data: bytes) -> list:
    out, i = [], 0
    while i < len(data):
        nl = data.index(b"\n", i)
        size = int(data[i:nl])
        js = data[nl + 1:nl + 1 + size].decode()
        assert len(js) == size                       # the length says what follows
        out.append(json.loads(js))
        i = nl + 1 + size
    return out


def _pipe_that_knows_the_email():
    pipe = Pipeline(MaskingSession())
    with pipe.session.sending_to("Gemini"):
        masked, _ = pipe.mask_text(f"mail {EMAIL}")
    assert TOK in masked
    return pipe


@pytest.mark.parametrize("size", [1, 7, 64, 100000])
def test_the_streamed_reply_gets_the_real_values_back(size):
    pipe = _pipe_that_knows_the_email()
    data = _reply(f"The confirmation went to {TOK}, as you asked.")
    reader = pipe.channel_restorer(site="Gemini")
    out = b"".join(reader.feed(data[i:i + size]) for i in range(0, len(data), size)) + reader.flush()
    got = _pieces(out)
    assert [p[0][0] for p in got] == [1, 2, 3, 4, 5]
    assert got[0] == [[1, ["noop"]]]
    assert any(EMAIL in t for t in texts(base64.b64decode(got[3][0][1][0])))
    assert TOK.encode() not in base64.b64decode(got[3][0][1][0])


def test_a_reply_with_nothing_to_put_back_comes_out_byte_for_byte():
    data = _reply("Nothing private in here at all.") + b"8\n[1,2,7]\n"
    reader = _pipe_that_knows_the_email().channel_restorer(site="Gemini")
    assert reader.feed(data) + reader.flush() == data


def test_a_value_sent_to_another_site_is_not_put_back_here():
    pipe = Pipeline(MaskingSession())
    with pipe.session.sending_to("ChatGPT"):
        pipe.mask_text(f"mail {EMAIL}")
    data = _reply(f"The confirmation went to {TOK}.")
    reader = pipe.channel_restorer(site="Gemini")
    assert reader.feed(data) + reader.flush() == data


@pytest.mark.parametrize("data", [b"<html>Sign in</html>", b"12\nshort", b")]}'\n\n[1,2]", "9\n[\"héllo\"]".encode(), b"99999999999\n[]"])
def test_a_reply_that_is_not_this_shape_is_sent_on_exactly_as_it_came(data):
    reader = webchannel.ReplyReader(lambda packed: packed + b"!")
    assert reader.feed(data) + reader.flush() == data
    assert reader.feed(b"more") == b"more" or data == b"12\nshort"


def test_the_door_restores_the_websites_streamed_reply(tmp_path, monkeypatch):
    from mitmproxy.test import tflow
    from omna_plugin.policy import Policy
    from omna_plugin.system_door import OmnaAddon
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    addon = OmnaAddon(_pipe_that_knows_the_email(), Policy(), door="system", resolver=lambda peer: (1, "Google Chrome"))
    fl = tflow.tflow(resp=True)
    fl.request.host, fl.request.port, fl.request.scheme, fl.request.method = CHANNEL, 443, "https", "GET"
    fl.request.headers["host"] = CHANNEL
    fl.request.path = "/v1/processSession?gsessionid=gz&VER=8&RID=rpc&SID=jDom&AID=0&CI=0&TYPE=xmlhttp&t=1"
    fl.response.headers["content-type"] = "text/plain; charset=utf-8"
    addon.responseheaders(fl)
    assert callable(fl.response.stream)
    data = _reply(f"The confirmation went to {TOK}.")
    out = b"".join(x for i in range(0, len(data), 50) for x in [fl.response.stream(data[i:i + 50])] if x)
    out += fl.response.stream(b"")
    got = _pieces(out)
    assert f"The confirmation went to {EMAIL}." in texts(base64.b64decode(got[3][0][1][0]))


# ---------------------------------------------------------------- the page's own calls

def call(name: str, args: str) -> bytes:
    req = json.dumps([[[name, args, None, "generic"]]], separators=(",", ":"))
    return f"f.req={quote(req, safe='')}&at={quote(AT, safe='')}&".encode()


@pytest.mark.parametrize("name,args", [
    ("MaZiqc", "[13,null,[1,null,1]]"),
    ("K4WWud", '["r_63f03dcbac24ec00"]'),
    ("hNvQHb", '["c_79212f80b4f84e5a",10,null,1,[1],[4],null,1]'),
    ("aPya6c", "[]"),
    ("GPRiHf", "[]"),
])
def test_the_pages_own_calls_go_exactly_as_they_came(name, args):
    assert sites.batch("gemini.google.com", BATCH_PATH)
    out, _ = _mask(call(name, args), host="gemini.google.com", path=BATCH_PATH, ct=FORM)
    assert out.refused is None and out.body is None


def test_what_a_person_typed_into_a_call_is_still_masked():
    """A chat's new name, a saved instruction: text inside the arguments."""
    body = call("MUAZcd", json.dumps([None, [["c_79212f80b4f84e5a", f"Booking for {EMAIL}"]]], separators=(",", ":")))
    out, _ = _mask(body, host="gemini.google.com", path=BATCH_PATH, ct=FORM)
    assert out.body is not None and EMAIL.encode() not in unquote_plus(out.body.decode()).encode()
    pairs = dict(p.split("=", 1) for p in out.body.decode().split("&") if p)
    assert unquote_plus(pairs["at"]) == AT
    (name, args, _, kind), = json.loads(unquote_plus(pairs["f.req"]))[0]
    assert name == "MUAZcd" and kind == "generic"
    assert json.loads(args) == [None, [["c_79212f80b4f84e5a", f"Booking for {TOK}"]]]


def test_the_older_message_form_is_read_the_same_way():
    """Before 2026-11 the message went to …/StreamGenerate as f.req=[null,"<JSON>"]."""
    inner = json.dumps([[MSG, 0, None, None, None, None, 0], ["en"], ["", "", ""], GUARD], separators=(",", ":"))
    body = ("f.req=" + quote(json.dumps([None, inner], separators=(",", ":")), safe="") + "&at=" + quote(AT, safe="")).encode()
    path = "/_/BardChatUi/data/assistant.lamda.BardFrontendService/StreamGenerate?bl=x&rt=c"
    out, _ = _mask(body, host="gemini.google.com", path=path, ct=FORM)
    assert out.refused is None and out.body is not None
    pairs = dict(p.split("=", 1) for p in out.body.decode().split("&"))
    sent = json.loads(json.loads(unquote_plus(pairs["f.req"]))[1])
    assert TOK in sent[0][0] and EMAIL not in sent[0][0]
    assert sent[3] == GUARD and unquote_plus(pairs["at"]) == AT


def test_a_form_that_is_not_that_format_is_handled_as_before():
    assert batchexecute.rewrite_form(b"a=1&b=2", lambda s: s + "!") is None
    assert batchexecute.rewrite_form(b"f.req=%5Bnot+json&at=x", lambda s: s) is None
    same = call("aPya6c", "[]")
    assert batchexecute.rewrite_form(same, lambda s: s) is same
