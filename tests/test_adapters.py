from omna_plugin.adapters import for_host
from omna_plugin.adapters.base import RequestView
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline


def _req(host, path, body, ct="application/json", method="POST"):
    return RequestView(host=host, method=method, path=path, content_type=ct, body=body, headers={})


def test_unknown_ai_host_gets_the_generic_adapter():
    assert for_host("api.some-new-ai.com").name == "generic"


def test_generic_prompt_detection_uses_the_extension_regex():
    a = for_host("example.com")
    assert a.is_prompt(_req("example.com", "/backend-api/conversation", b"{}"))
    assert a.is_prompt(_req("example.com", "/v1/chat/completions", b"{}"))
    assert not a.is_prompt(_req("example.com", "/assets/app.js", b"", ct="text/javascript", method="GET"))
    assert not a.is_prompt(_req("example.com", "/backend-api/conversation", b"", method="GET"))


def test_generic_masks_json_prompt_and_refuses_garbage(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    a = for_host("example.com")
    ok = a.mask(p, _req("example.com", "/api/chat", b'{"messages":[{"content":"hi jane.doe@example.com"}]}'))
    assert ok.refused is None and b"[EMAIL_" b"1]" in ok.body
    bad = a.mask(p, _req("example.com", "/api/chat", b"{broken"))
    assert bad.refused == "unparseable"


def test_generic_non_prompt_post_is_passthrough(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    a = for_host("example.com")
    out = a.mask(p, _req("example.com", "/telemetry", b"\x00binary", ct="application/octet-stream"))
    assert out.refused is None and out.body is None and out.passthrough


def test_generic_picks_restorer_by_response_type():
    a = for_host("example.com")
    assert a.response_mode("text/event-stream") == "stream-json"
    assert a.response_mode("application/json") == "json"
    assert a.response_mode("text/plain; charset=utf-8") == "stream-text"
    assert a.response_mode("image/png") == "passthrough"
