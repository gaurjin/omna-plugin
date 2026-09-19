import json
from omna_plugin import receipts
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline, MaskStats

EMAIL = "jane.doe@example.com"
TOK = "[EMAIL_" "1]"          # two pieces on purpose, see the note at the top of this plan


def _pipe(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return Pipeline(MaskingSession())


def test_mask_json_returns_masked_copy_and_stats(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    obj = {"messages": [{"role": "user", "content": f"mail {EMAIL} now"}]}
    masked, stats = p.mask_json(obj)
    assert EMAIL not in json.dumps(masked)
    assert TOK in json.dumps(masked)
    assert isinstance(stats, MaskStats)
    assert stats.counts == {"EMAIL": 1} and stats.pii == 1 and stats.secrets == 0
    assert stats.tokens == ["EMAIL_1"]
    assert obj["messages"][0]["content"].startswith("mail jane")  # input untouched


def test_mask_bytes_json_and_refusal(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    out = p.mask_bytes(b'{"prompt": "call 415-555-0134"}', "application/json")
    assert out.refused is None
    assert b"[PHONE_" b"1]" in out.body
    bad = p.mask_bytes(b"\x00\x01 not json", "application/json")
    assert bad.refused == "unparseable"
    assert bad.body is None


def test_mask_bytes_valid_json_that_fails_to_mask_is_mask_failed_not_unparseable(tmp_path, monkeypatch):
    # A lone UTF-16 surrogate: valid JSON syntax (json.loads accepts \uXXXX
    # escapes for any code point, paired or not), but json.dumps(...,
    # ensure_ascii=False).encode("utf-8") raises UnicodeEncodeError on it.
    # This is the review finding: such bodies must be "mask-failed", never
    # collapsed into the same "unparseable" bucket used for bad JSON syntax
    # (a non-inference route treats the two differently downstream).
    p = _pipe(tmp_path, monkeypatch)
    body = '{"prompt": "\\ud800"}'.encode("ascii")
    out = p.mask_bytes(body, "application/json")
    assert out.refused == "mask-failed"
    assert out.body is None


def test_mask_bytes_form_urlencoded(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    out = p.mask_bytes(b"q=email+jane.doe%40example.com&page=1", "application/x-www-form-urlencoded")
    assert out.refused is None
    assert b"EMAIL_1" in out.body and b"page=1" in out.body


def test_restore_json_and_text(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    p.mask_json({"t": EMAIL})
    assert p.restore_json({"reply": "wrote to " + TOK}) == {"reply": "wrote to " + EMAIL}
    assert p.restore_text(TOK) == EMAIL


def test_text_restorer_json_escapes_and_holds_back(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    p.mask_json({"t": 'Ann "AJ" Jones <aj@example.com>'})   # a value with quotes around it
    r = p.text_restorer(json_escape=True)
    out = r.feed('{"delta":"[EMA') + r.feed('IL_1]"}')
    assert out == '{"delta":"aj@example.com"}'
    assert r.flush() == ""


def test_receipt_carries_door_host_and_app(tmp_path, monkeypatch):
    p = _pipe(tmp_path, monkeypatch)
    _, stats = p.mask_json({"t": EMAIL})
    p.receipt(door="system", route="/backend-api/conversation", host="chatgpt.com", status=200,
              stats=stats, nbytes=42, ms=17, stream=True, app="Google Chrome", note=None, session_id=None)
    rec = receipts.tail(1)[0]
    assert rec["door"] == "system" and rec["host"] == "chatgpt.com" and rec["app"] == "Google Chrome"
    assert rec["masked"] == {"EMAIL": 1} and rec["pii"] == 1 and rec["tokens"] == ["EMAIL_1"]
    assert "jane" not in json.dumps(rec)


def test_receipt_writes_nothing_when_reports_are_turned_off(tmp_path, monkeypatch):
    from omna_plugin.policy import Policy

    p = _pipe(tmp_path, monkeypatch)
    pol = Policy.load()
    pol.reports_enabled = False
    pol.save()
    _, stats = p.mask_json({"t": EMAIL})
    p.receipt(door="system", route="/x", host="chatgpt.com", status=200,
              stats=stats, nbytes=1, ms=1, stream=False, app=None, note=None, session_id=None)
    assert receipts.tail(10) == []


def test_a_refusal_is_still_receipted_when_reports_are_off(tmp_path, monkeypatch):
    # A refusal is "this app isn't working, here's why" diagnostic information
    # (surfaced by `omna status`), not usage tracking — it must stay visible
    # regardless of the Keep Local Reports toggle.
    from omna_plugin.policy import Policy

    p = _pipe(tmp_path, monkeypatch)
    pol = Policy.load()
    pol.reports_enabled = False
    pol.save()
    _, stats = p.mask_json({})
    p.receipt(door="system", route="/x", host="chatgpt.com", status=495,
               stats=stats, nbytes=1, ms=1, stream=False, app="Some App",
               note="tls-refused", session_id=None)
    recs = receipts.tail(10)
    assert len(recs) == 1 and recs[0]["note"] == "tls-refused"
