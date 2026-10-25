from omna_plugin.adapters import for_host
from omna_plugin.adapters.base import RequestView
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline


def _req(host, path, body, ct="application/json", method="POST"):
    return RequestView(host=host, method=method, path=path, content_type=ct, body=body, headers={})


def test_unknown_ai_host_gets_the_generic_adapter():
    assert for_host("api.some-new-ai.com").name == "generic"


def test_for_host_strips_the_port():
    assert for_host("example.com:443").name == "generic"
    assert for_host("api.some-new-ai.com:8443").name == "generic"


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


def test_grok_upload_at_attach_time_is_masked(tmp_path, monkeypatch):
    # Not a prompt path, but the file goes to grok.com the moment it is
    # attached, before Send (live test 2026-10-24, MASTER #157).
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    b = "----WebKitFormBoundaryL7MrdSdDYeZeeASz"
    body = (f'--{b}\r\nContent-Disposition: form-data; name="file"; filename="customer-notes.txt"\r\n'
            f"Content-Type: text/plain\r\n\r\nContact: jane.doe@example.com\r\n--{b}--\r\n").encode()
    out = for_host("grok.com").mask(p, _req("grok.com", "/http/upload-file-v2/direct", body,
                                            ct=f"multipart/form-data; boundary={b}"))
    assert out.refused is None and not out.passthrough
    assert b"jane.doe@example.com" not in out.body and b"[EMAIL_" b"1]" in out.body


# Copilot puts an attached file into the person's OneDrive the moment it is
# attached (live test 2026-10-24, MASTER #157): one PUT of the whole file to an
# upload address made for Copilot's app. Only THAT is masked — the rest of
# OneDrive (their own files and backups) must pass through untouched.
import base64
import json as _json

_OD = "my.microsoftpersonalcontent.com"
_NOTES = b"Contact: jane.doe@example.com\nAWS_ACCESS_KEY_ID=AKIA" b"Q7WZLMNOPS3XTUV2\n"


def _tempauth(app="M365ChatClient"):
    claims = base64.urlsafe_b64encode(_json.dumps({"app_displayname": app, "appid": "x"}).encode()).rstrip(b"=")
    return "v1e." + claims.decode() + ".sig"


def _od_put(body, referer="https://copilot.com/", app="M365ChatClient", rng=None):
    path = (f"/personal/58c0/_api/v2.0/drive/items/012PF/uploadSession?guid=%27b2fb%27&dc=0"
            f"&tempauth={_tempauth(app)}")
    headers = {"Content-Range": rng or f"bytes 0-{len(body) - 1}/{len(body)}", "Referer": referer}
    return RequestView(host=_OD, method="PUT", path=path, content_type="application/octet-stream",
                       body=body, headers=headers)


def _p(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return Pipeline(MaskingSession())


def test_copilot_upload_to_onedrive_is_masked_and_its_size_label_fixed(tmp_path, monkeypatch):
    out = for_host(_OD).mask(_p(tmp_path, monkeypatch), _od_put(_NOTES))
    assert out.refused is None and out.body is not None
    assert b"jane.doe@example.com" not in out.body and b"AKIAQ7WZ" not in out.body
    assert out.headers == {"Content-Range": f"bytes 0-{len(out.body) - 1}/{len(out.body)}"}


def test_copilot_is_recognised_by_its_upload_pass_even_without_a_referer(tmp_path, monkeypatch):
    out = for_host(_OD).mask(_p(tmp_path, monkeypatch), _od_put(_NOTES, referer=""))
    assert out.body is not None and b"jane.doe@example.com" not in out.body


def test_the_persons_own_onedrive_uploads_are_never_touched(tmp_path, monkeypatch):
    p = _p(tmp_path, monkeypatch)
    for req in (_od_put(_NOTES, referer="https://onedrive.live.com/", app="OneDrive"),
                RequestView(host=_OD, method="PUT", path="/personal/58c0/_api/v2.0/drive/items/x/content",
                            content_type="text/plain", body=_NOTES, headers={})):
        out = for_host(_OD).mask(p, req)
        assert out.body is None and out.passthrough and out.refused is None


def test_copilot_binary_upload_passes_as_is(tmp_path, monkeypatch):
    png = b"\x89PNG\r\n\x1a\n\x00\x00\xff"
    out = for_host(_OD).mask(_p(tmp_path, monkeypatch), _od_put(png))
    assert out.body is None and out.refused is None


def test_copilot_upload_in_pieces_with_something_to_mask_is_refused(tmp_path, monkeypatch):
    # Masking one piece of a big file changes its size, and the pieces no
    # longer add up — so a text piece that needs masking is refused, never sent.
    out = for_host(_OD).mask(_p(tmp_path, monkeypatch), _od_put(_NOTES, rng=f"bytes 0-{len(_NOTES) - 1}/999999"))
    assert out.refused == "unmaskable-chunk"
    clean = b"nothing private here\n"
    ok = for_host(_OD).mask(_p(tmp_path, monkeypatch), _od_put(clean, rng=f"bytes 0-{len(clean) - 1}/999999"))
    assert ok.refused is None


def test_onedrive_replies_are_never_restored():
    assert for_host(_OD).response_mode("application/json") == "passthrough"


# Gemini sends an attached file to Google's upload server the moment it is
# attached (live test 2026-10-24, MASTER #157): a "start" request that promises
# the size, then "upload, finalize" with the raw file — labelled as a web form,
# which it is not. Only Gemini's uploads (tenant bard-storage) are touched.
_GP = "push.clients6.google.com"


def _g(command, body, tenant="bard-storage", referer="https://gemini.google.com/", offset="0", extra=None):
    h = {"X-Goog-Upload-Command": command, "X-Goog-Upload-Protocol": "resumable", "Referer": referer,
         "X-Tenant-Id": tenant, "X-Goog-Upload-Offset": offset}
    h.update(extra or {})
    return RequestView(host=_GP, method="POST", path="/upload/?upload_id=x&upload_protocol=resumable",
                       content_type="application/x-www-form-urlencoded;charset=utf-8", body=body, headers=h)


def test_gemini_upload_start_drops_the_size_promise(tmp_path, monkeypatch):
    out = for_host(_GP).mask(_p(tmp_path, monkeypatch),
                             _g("start", b"File name: customer-notes.txt", extra={"X-Goog-Upload-Header-Content-Length": "127"}))
    assert out.refused is None and out.body is None
    assert out.headers == {"X-Goog-Upload-Header-Content-Length": None}


def test_gemini_upload_finalize_masks_the_raw_file_without_treating_it_as_a_form(tmp_path, monkeypatch):
    out = for_host(_GP).mask(_p(tmp_path, monkeypatch), _g("upload, finalize", _NOTES))
    assert out.refused is None and out.body is not None
    assert b"jane.doe@example.com" not in out.body and b"AKIAQ7WZ" not in out.body
    assert out.body.startswith(b"Contact: [EMAIL_" b"1]\n")        # still the file, not percent-encoded


def test_gemini_upload_in_pieces_with_something_to_mask_is_refused(tmp_path, monkeypatch):
    assert for_host(_GP).mask(_p(tmp_path, monkeypatch), _g("upload", _NOTES)).refused == "unmaskable-chunk"
    assert for_host(_GP).mask(_p(tmp_path, monkeypatch),
                              _g("upload, finalize", _NOTES, offset="262144")).refused == "unmaskable-chunk"


def test_other_google_uploads_on_the_same_server_are_never_touched(tmp_path, monkeypatch):
    p = _p(tmp_path, monkeypatch)
    for req in (_g("upload, finalize", _NOTES, tenant="photos", referer="https://photos.google.com/"),
                _g("start", b"x", tenant="drive", referer="https://drive.google.com/",
                   extra={"X-Goog-Upload-Header-Content-Length": "9"})):
        out = for_host(_GP).mask(p, req)
        assert out.body is None and out.headers is None and out.passthrough
    assert for_host(_GP).response_mode("application/json") == "passthrough"


# Meta AI uploads an attached file to rupload.meta.ai the moment it is attached
# (live test 2026-10-24, MASTER #157) — NOT encrypted, and labelled in Meta's own
# headers (x-entity-type / x-entity-length / Offset), with no Content-Type, so
# the generic adapter let it through.
_MR = "rupload.meta.ai"


def _meta(body, length=None, offset="0", etype="text/plain", path="/gen_ai_document_gen_ai_tenant/b995afc4"):
    h = {"Referer": "https://www.meta.ai/", "Offset": offset, "x-entity-length": str(len(body) if length is None else length),
         "x-entity-type": etype, "x-entity-name": "customer-notes.txt"}
    return RequestView(host=_MR, method="POST", path=path, content_type="", body=body, headers=h)


def test_meta_ai_upload_is_masked_and_its_size_header_fixed(tmp_path, monkeypatch):
    out = for_host(_MR).mask(_p(tmp_path, monkeypatch), _meta(_NOTES))
    assert out.refused is None and out.body is not None
    assert b"jane.doe@example.com" not in out.body and b"AKIAQ7WZ" not in out.body
    assert out.headers == {"x-entity-length": str(len(out.body))}


def test_meta_ai_binary_upload_passes_as_is(tmp_path, monkeypatch):
    out = for_host(_MR).mask(_p(tmp_path, monkeypatch), _meta(b"\x89PNG\r\n\x1a\n\x00\xff", etype="image/png"))
    assert out.body is None and out.refused is None


def test_meta_ai_upload_in_pieces_with_something_to_mask_is_refused(tmp_path, monkeypatch):
    p = _p(tmp_path, monkeypatch)
    assert for_host(_MR).mask(p, _meta(_NOTES, length=999999)).refused == "unmaskable-chunk"
    assert for_host(_MR).mask(p, _meta(_NOTES, offset="4096", length=4096 + len(_NOTES))).refused == "unmaskable-chunk"


def test_meta_ai_replies_are_never_restored():
    assert for_host(_MR).response_mode("application/json") == "passthrough"
