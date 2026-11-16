"""grok.com: the message goes over a WebSocket; only the message is masked.

Found live 2026-11-16 (signed in, one typed message): the page sends the
message as a JSON WebSocket frame that also carries Grok's anti-abuse token
("castle_request_token"). Masked as one flat text, the token and the page's
own settings were edited and Grok answered "Connection lost — Grok couldn't
finish responding". The frames below have the recorded shape."""

import json

from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline

EMAIL = "rosalind.ob@quillharborlaw.com"
MSG = f"Write a note to our landlord. The tenant is Rosalind Okafor, the lease copy went to {EMAIL}."
TOK = "[EMAIL_" "1]"        # two pieces: see CLAUDE.md "Token literals"
CASTLE = "cNz8rPYH|JABFNDhUdnhQUEU2Y1R4eE92RTc4VGx4T1BFNGNUaHhPM0U1Yz0AAAitAAAIrCAuxkPKQXOpBXNfGN6J2nyisIk23L8CNE2QcKzdEWo+C7WpcKUeD5h7QeHFUouvFXC8GDNGfWkUgPG0pvh1JPliq/CEIPfGAtlPQpEyl+aGqko/sNKk1hjzHGQZ5i7YShynF7RRRx0kuNfcBwR6cf2fSlxV25K88IflV5HGgxfnW4Pj9V6dzAOhCgQGwRlqzodQ3wOiFMKq3lTWNMSY1JVfthffd+mSq43jiZAaTw=="
SESSION = "8ee9cd44-8294-4335-b70b-71827262fefc"

CREATE = {"event": {"type": "session.create", "event_id": "evt_init_45f1e98a-e509-4e0b-a530-f0f9ebcd07c2", "session": {
    "model": "fast", "x_grok": {"protocol_capabilities": ["conversation_attached", "custom_methods_v1", "workspace_servers_v1"],
                                "use_chunk": True, "client_side_toolsets": ["connectors-v3", "location"],
                                "enable_image_generation": True, "image_generation_count": 2, "force_concise": False}}}}


def message(text: str = MSG) -> dict:
    return {"session_id": SESSION, "event": {"type": "response.create", "event_id": "evt_resp_1794857214211", "item": {
        "type": "message", "role": "user", "x_grok": {"client_message_id": "41ce052b-0be3-46a0-9306-54fd6b0bef9a",
                                                      "input_chunks": [{"text": {"text": text}}]}},
        "castle_request_token": CASTLE}}


def _send(obj: dict, site: str = "Grok", session=None):
    pipe = Pipeline(session or MaskingSession())
    text = json.dumps(obj, separators=(",", ":"))
    with pipe.session.sending_to(site):
        masked, stats = pipe.mask_ws_message(text)
    return text, masked, stats


def test_the_message_is_masked_and_groks_own_parts_are_untouched():
    _, masked, stats = _send(message())
    got = json.loads(masked)
    sent = got["event"]["item"]["x_grok"]["input_chunks"][0]["text"]["text"]
    assert TOK in sent and EMAIL not in masked
    assert got["event"]["castle_request_token"] == CASTLE
    want = message(sent)
    assert got == want
    assert stats.pii >= 1


def test_the_pages_own_frames_go_exactly_as_they_came():
    for own in (CREATE, {"session_id": SESSION, "event": {"type": "presence.update", "visible": True}},
                {"event": {"type": "ping", "event_id": "evt_hb_1794857241018"}}, message("what is the tallest mountain in Peru")):
        text, masked, _ = _send(own)
        assert masked == text


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
    _send(message(), session=MaskingSession(smart=True))
    _send(CREATE, session=MaskingSession(smart=True))
    assert seen[MSG] is not None
    assert CASTLE not in seen                      # never even read
    for own in ("fast", "user", "connectors-v3", SESSION):
        assert seen.get(own) is None, own


def test_a_secret_typed_into_another_field_is_still_caught():
    """The tiebreaker: what is not the message still gets the fast rules."""
    gh = "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
    obj = message()
    obj["event"]["note"] = f"deploy with {gh}"
    _, masked, _ = _send(obj)
    assert gh not in masked


def test_a_site_without_a_table_is_checked_whole_as_before():
    text, masked, _ = _send({"q": f"mail {EMAIL}"}, site="DeepSeek")
    assert EMAIL not in masked


def test_the_token_field_is_left_alone_only_on_grok():
    _, masked, _ = _send({"model": "x", "castle_request_token": "hunter2-Secret-Horse-99", "parts": [f"mail {EMAIL}"]}, site="ChatGPT")
    assert EMAIL not in masked


# ---------------------------------------------------------------- the reply

def chunk(text: str, channel: str = "CHANNEL_ASSISTANT_RESPONSE") -> str:
    return json.dumps({"session_id": SESSION, "event": {"type": "response.chunk", "event_id": "evt_3be_24", "item_id": "dbd53317",
                                                        "chunk": {"metadata": {"step_id": 0, "phase_index": 2},
                                                                  "text": {"text": text, "channel": channel}}}}, separators=(",", ":"))


def _said(frames) -> str:
    return "".join(json.loads(f)["event"]["chunk"]["text"]["text"] for f in frames)


def _pipe_that_knows_the_email():
    pipe = Pipeline(MaskingSession())
    with pipe.session.sending_to("Grok"):
        masked, _ = pipe.mask_text(f"mail {EMAIL}")
    assert TOK in masked
    return pipe


def test_a_stand_in_cut_across_frames_gets_its_real_value_back():
    """Recorded: one stand-in arrived as "[", "PERSON", "_", "4", "],"."""
    reader = _pipe_that_knows_the_email().ws_chunk_restorer("Grok")
    pieces = ["Send it to", " [", "EMAIL", "_", "1", "],", " thanks", "."]
    out = [reader.feed(chunk(p)) for p in pieces]
    assert all(o is not None for o in out)
    assert _said(out) == f"Send it to {EMAIL}, thanks."
    assert reader.leftover() == []


def test_frames_with_nothing_to_put_back_come_out_exactly_as_they_came():
    reader = _pipe_that_knows_the_email().ws_chunk_restorer("Grok")
    for p in ["Reminder", " for", " the", " team."]:
        assert reader.feed(chunk(p)) == chunk(p)


def test_two_streams_in_one_connection_do_not_mix():
    reader = _pipe_that_knows_the_email().ws_chunk_restorer("Grok")
    a = [reader.feed(chunk(" [", "A")), reader.feed(chunk("Thinking", "B")), reader.feed(chunk("EMAIL_1]", "A"))]
    assert _said([a[0], a[2]]) == f" {EMAIL}" and _said([a[1]]) == "Thinking"


def test_other_frames_are_left_to_the_usual_restore():
    reader = _pipe_that_knows_the_email().ws_chunk_restorer("Grok")
    assert reader.feed(json.dumps({"event": {"type": "pong"}})) is None
    assert reader.feed(json.dumps({"event": {"type": "response.chunk", "chunk": {"phase_marker": {"kind": "KIND_RESPONSE_START"}}}})) is None
    assert reader.feed("not json response.chunk") is None


def test_text_that_only_looked_like_a_stand_in_is_delivered_not_lost():
    reader = _pipe_that_knows_the_email().ws_chunk_restorer("Grok")
    out = [reader.feed(chunk("see item")), reader.feed(chunk(" [EMA"))]
    late = reader.leftover()
    assert _said(out + late) == "see item [EMA"
    assert reader.leftover() == []


def test_a_value_sent_to_another_site_is_not_put_back_on_grok():
    pipe = Pipeline(MaskingSession())
    with pipe.session.sending_to("ChatGPT"):
        pipe.mask_text(f"mail {EMAIL}")
    reader = pipe.ws_chunk_restorer("Grok")
    out = [reader.feed(chunk(p)) for p in [" [", "EMAIL_1", "]"]]
    assert _said(out + reader.leftover()) == f" {TOK}"


def test_only_grok_has_this_reader():
    assert Pipeline(MaskingSession()).ws_chunk_restorer("ChatGPT") is None


def test_a_list_frame_of_a_site_with_a_table_keeps_its_key_names():
    """Recorded on ws.chatgpt.com the same day: "topic_id" was read as a person."""
    frame = [{"command": {"topic_id": "conversation_notifications", "type": "subscribe"}, "id": 2}]
    text, masked, _ = _send(frame, site="ChatGPT")
    assert masked == text
