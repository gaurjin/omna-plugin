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
    # A piece where nothing was found is refused too (architecture review,
    # MASTER #177): the next piece may hold the rest of a value cut in two
    # ("jane.doe@ex" | "ample.com"), and the middle of a .docx is unreadable.
    clean = b"nothing private here, write to jane.doe@ex"
    no = for_host(_OD).mask(_p(tmp_path, monkeypatch), _od_put(clean, rng=f"bytes 0-{len(clean) - 1}/999999"))
    assert no.refused == "unmaskable-chunk"
    # A picture is never masked anyway, so its pieces go as a whole one would.
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
    ok = for_host(_OD).mask(_p(tmp_path, monkeypatch), _od_put(png, rng=f"bytes 0-{len(png) - 1}/999999"))
    assert ok.refused is None and ok.body is None and ok.stats.not_masked


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


# --- ChatGPT PUTs the raw file to its storage, labelled by file type (MASTER #160) ---

def _office_and_env():
    import sys
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).parent))
    import test_office
    env = ("GITHUB_TOKEN=ghp_" + "fgYFNmLOZlhOWtmhi0EwWcTCEsLvKQdOrH3k\nADMIN_EMAIL=jane.doe@example.com\n").encode()
    return test_office.docx(), test_office.xlsx(), env


def test_a_word_file_put_raw_to_chatgpt_storage_is_masked(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin import office
    docx, xlsx, _ = _office_and_env()
    p = Pipeline(MaskingSession())
    for body, ct in ((docx, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
                     (xlsx, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")):
        r = _req("files.example-ai.com", "/file-abc?se=2026", body, ct, "PUT")
        out = for_host(r.host).mask(p, r)
        assert out.body is not None and out.refused is None
        assert office.kind(out.body) == office.kind(body)
        assert b"jane.doe@example.com" not in out.body
        assert out.stats.pii >= 1


def test_an_env_file_labelled_unknown_type_is_masked(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    _, _, env = _office_and_env()
    p = Pipeline(MaskingSession())
    for ct in ("application/octet-stream", ""):
        r = _req("files.example-ai.com", "/file-abc", env, ct, "PUT")
        out = for_host(r.host).mask(p, r)
        assert out.body is not None, ct
        assert b"ghp_" not in out.body and b"jane.doe@" not in out.body
        assert out.body.startswith(b"GITHUB_TOKEN=")


def test_other_binary_labels_are_never_touched(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    _, _, env = _office_and_env()
    p = Pipeline(MaskingSession())
    for ct in ("application/x-protobuf", "application/grpc-web+proto", "image/png", "audio/webm"):
        r = _req("files.example-ai.com", "/x", env, ct, "PUT")
        out = for_host(r.host).mask(p, r)
        assert out.body is None and out.passthrough, ct


# --- ChatGPT announces the file's size first, then refuses a different size:
# "file_size_mismatch" (live, 2026-10-25). The masked file keeps the size. ---

def _chatgpt_put(body, ct):
    return _req("sdmntprcentralus.oaiusercontent.com", "/files/00000000-c3a4-81f5-9738-6fe60a76087e/raw?se=x&sig=y", body, ct, "PUT")


def test_chatgpt_storage_gets_a_masked_file_of_the_very_same_size(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin import office
    docx, xlsx, env = _office_and_env()
    text = b"Customer record (test only, fake values)\nEmail: jane.doe@example.com\nPhone: 555-123-4567\n"
    p = Pipeline(MaskingSession())
    cases = ((text, "text/plain"), (env, "application/octet-stream"), (env, ""),
             (docx, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
             (xlsx, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
    for body, ct in cases:
        out = for_host("sdmntprcentralus.oaiusercontent.com").mask(p, _chatgpt_put(body, ct))
        assert out.refused is None and out.body is not None, ct
        assert len(out.body) == len(body), (ct, len(out.body), len(body))
        assert b"jane.doe@example.com" not in out.body and b"jane.doe@" not in out.body
        if office.kind(body):
            assert office.kind(out.body) == office.kind(body)
            assert office.mask_office(out.body, lambda t: t) == out.body   # still a readable zip
    # text padding is spaces at the very end, nothing else moves
    out = for_host("x.oaiusercontent.com").mask(p, _chatgpt_put(text, "text/plain")).body
    assert out.rstrip(b" ").endswith(b"\n") and out.startswith(b"Customer record")


def test_chatgpt_storage_refuses_a_masked_file_that_would_grow(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    # short secrets whose stand-ins are longer than the values, nothing to pad with
    body = ("password=" + "Xq7#kL9z\n") .encode() * 3
    masked, _ = p.mask_file(body, "text/plain")
    if len(masked) <= len(body):
        return  # this engine masks it shorter; the refusal path is covered below
    out = for_host("x.oaiusercontent.com").mask(p, _chatgpt_put(body, "text/plain"))
    assert out.refused == "unmaskable-size" and out.body is None


def test_a_file_that_grows_is_refused_never_sent_unmasked(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    monkeypatch.setattr(p, "mask_text", lambda t, style="tokens": (t.replace("jane.doe@example.com", "X" * 200), __import__("omna_plugin.pipeline", fromlist=["MaskStats"]).MaskStats(pii=1)))
    body = b"Email: jane.doe@example.com\n"
    out = for_host("x.oaiusercontent.com").mask(p, _chatgpt_put(body, "text/plain"))
    assert out.refused == "unmaskable-size" and out.body is None


def test_chatgpt_storage_clean_file_and_other_requests_pass_untouched(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = Pipeline(MaskingSession())
    clean = b"Shopping list\nApples\n"
    out = for_host("x.oaiusercontent.com").mask(p, _chatgpt_put(clean, "text/plain"))
    assert out.body is None and out.refused is None
    get = _req("x.oaiusercontent.com", "/files/abc/raw", b"", "", "GET")
    assert for_host(get.host).mask(p, get).passthrough


# Perplexity puts an attached file in its own Amazon S3 bucket through a signed
# upload form (live 2026-10-25, MASTER #176): the host was not on the list, so
# the file went out unmasked. Only the file part may change — the signature
# parts must arrive exactly as Amazon signed them.
_PX = "ppl-ai-file-upload.s3.amazonaws.com"


def _s3_form(file_body, filename="notes.txt"):
    b = "omnaS3boundary"
    sig = b"X7fGQ2kz9pL4mN8rT1vW3yB6cD0eH5jA2sF9gK4lP7qR"   # looks like a key: must stay
    parts = [
        b'Content-Disposition: form-data; name="key"\r\n\r\nuploads/abc/' + filename.encode(),
        b'Content-Disposition: form-data; name="x-amz-signature"\r\n\r\n' + sig,
        b'Content-Disposition: form-data; name="file"; filename="' + filename.encode()
        + b'"\r\nContent-Type: text/plain\r\n\r\n' + file_body,
    ]
    body = b"".join(b"--" + b.encode() + b"\r\n" + p + b"\r\n" for p in parts) + b"--" + b.encode() + b"--\r\n"
    return RequestView(host=_PX, method="POST", path="/", content_type=f"multipart/form-data; boundary={b}",
                       body=body, headers={"Origin": "https://www.perplexity.ai"}), sig


def test_perplexity_upload_masks_only_the_file_part(tmp_path, monkeypatch):
    req, sig = _s3_form(_NOTES)
    assert for_host(_PX).name == "perplexity-upload"
    out = for_host(_PX).mask(_p(tmp_path, monkeypatch), req)
    assert out.refused is None and out.body is not None
    assert b"jane.doe@example.com" not in out.body and b"AKIAQ7WZ" not in out.body
    assert sig in out.body and b"uploads/abc/notes.txt" in out.body


def test_perplexity_upload_with_nothing_to_mask_goes_as_it_is(tmp_path, monkeypatch):
    req, _ = _s3_form(b"just a shopping list: milk, eggs\n")
    out = for_host(_PX).mask(_p(tmp_path, monkeypatch), req)
    assert out.body is None and out.refused is None


def test_perplexity_bucket_is_opened_by_the_system_door(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    from omna_plugin.policy import Policy
    assert Policy.load().is_ai_host(_PX)
    assert not Policy.load().is_ai_host("someone-else.s3.amazonaws.com")
