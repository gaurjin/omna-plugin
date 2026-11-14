"""Whatever Omna could not read still goes out — and the receipt names it.

Security review 2026-11-11, finding 7. Owner decision: never block, always
leave a report line. Before this, a zip, an unknown file type, the hidden
places of a Word / Excel file, a scanned PDF and the pictures and PDFs inside
an agent's request all went out with nothing in the receipt at all.

All values are fake.
"""

from __future__ import annotations

import asyncio
import base64
import gzip
import io
import json
import zipfile

import httpx
import pytest
from mitmproxy.test import tflow

from omna_plugin import receipts, report, smart
from omna_plugin.adapters import for_host
from omna_plugin.adapters.base import RequestView
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline
from omna_plugin.policy import Policy
from omna_plugin.proxy import create_app
from omna_plugin.system_door import OmnaAddon
from tests.test_office import SHARED, docx, zip_of
from tests.test_proxy import Upstream

EMAIL = "jane.doe@example.com"
TOKEN = "ghp_" + "fgYFNmLOZlhOWtmhi0EwWcTCEsLvKQdOrH3k"


@pytest.fixture
def pipe(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return Pipeline(MaskingSession())


def _zip(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for name, data in members.items():
            z.writestr(name, data)
    return buf.getvalue()


# ------------------------------------------------------------------- files
@pytest.mark.parametrize("data, word", [
    (_zip({"notes.txt": f"key {TOKEN}".encode()}), "zip"),
    (gzip.compress(f"key {TOKEN}".encode()), "compressed"),
    (b"\x00\x01binary " + TOKEN.encode(), "unknown"),
    (f"caf\xe9 {TOKEN}".encode("latin-1"), "unknown"),
    (f"key {TOKEN}".encode("utf-16"), "unknown"),
])
def test_a_file_omna_cannot_read_goes_as_it_is_and_is_named(pipe, data, word):
    out, st = pipe.mask_file(data, "application/octet-stream")
    assert out == data                      # never blocked, never changed
    assert st.not_masked == word            # ...and never silent


def test_plain_text_is_still_masked_with_no_note(pipe):
    out, st = pipe.mask_file(f"key {TOKEN}".encode(), "text/plain")
    assert TOKEN.encode() not in out and st.not_masked == ""


def test_a_clean_word_file_carries_only_the_pictures_note(pipe):
    out, st = pipe.mask_file(docx(), "")
    assert EMAIL.encode() not in zipfile.ZipFile(io.BytesIO(out)).read("word/document.xml")
    # test_office's docx holds one picture; nothing else in it is unread.
    assert st.not_masked == "office-pictures"


def test_a_word_file_without_pictures_has_no_note(pipe):
    parts = {n: zipfile.ZipFile(io.BytesIO(docx())).read(n) for n in zipfile.ZipFile(io.BytesIO(docx())).namelist()
             if "media" not in n}
    _, st = pipe.mask_file(zip_of(parts), "")
    assert st.not_masked == ""


def _xlsx(sheet_extra: str = "", workbook_extra: str = "") -> bytes:
    ns = 'xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
    sheet = (f'<?xml version="1.0" encoding="UTF-8"?><worksheet {ns}><sheetData>'
             f'<row r="1"><c r="A1" t="s"><v>1</v></c>{sheet_extra}</row></sheetData></worksheet>')
    return zip_of({
        "[Content_Types].xml": '<?xml version="1.0"?><Types/>',
        "xl/workbook.xml": f'<?xml version="1.0"?><workbook {ns}><sheets><sheet name="Sheet1" sheetId="1"/></sheets>{workbook_extra}</workbook>',
        "xl/sharedStrings.xml": SHARED,
        "xl/worksheets/sheet1.xml": sheet,
    })


def test_an_excel_file_with_nothing_hidden_has_no_note(pipe):
    out, st = pipe.mask_file(_xlsx(), "")
    assert EMAIL.encode() not in zipfile.ZipFile(io.BytesIO(out)).read("xl/sharedStrings.xml")
    assert st.not_masked == ""


@pytest.mark.parametrize("where, xlsx", [
    ("formula", lambda: _xlsx(sheet_extra=f'<c r="B1"><f>CONCAT("{TOKEN}","")</f><v>0</v></c>')),
    ("named range", lambda: _xlsx(workbook_extra=f'<definedNames><definedName name="owner">"{EMAIL}"</definedName></definedNames>')),
    ("sheet name", lambda: zip_of({
        "[Content_Types].xml": '<?xml version="1.0"?><Types/>',
        "xl/workbook.xml": f'<?xml version="1.0"?><workbook><sheets><sheet name="{EMAIL}" sheetId="1"/></sheets></workbook>',
        "xl/sharedStrings.xml": SHARED})),
])
def test_a_value_in_a_hidden_place_of_an_excel_file_is_named(pipe, where, xlsx):
    _, st = pipe.mask_file(xlsx(), "")
    assert "office-hidden" in st.not_masked.split(","), where


def test_a_word_file_that_cannot_be_opened_is_named(pipe):
    # One entry flagged as encrypted: mask_office refuses the whole file.
    data = bytearray(docx())
    i = data.find(b"PK\x03\x04")
    data[i + 6] |= 0x01
    j = data.find(b"PK\x01\x02")
    data[j + 8] |= 0x01
    out, st = pipe.mask_file(bytes(data), "")
    assert out == bytes(data) and st.not_masked == "docx"


def test_a_piece_of_an_unknown_file_is_still_refused(pipe):
    # "unknown" names a WHOLE file that went as it is. A piece of a file sent
    # in parts must not ride on that word: it is refused as before (#177).
    from tests.test_adapters import _OD, _od_put

    middle = b"\x00\x01\x02 middle of a word file"
    out = for_host(_OD).mask(pipe, _od_put(middle, rng=f"bytes 100-{100 + len(middle) - 1}/999999"))
    assert out.refused == "unmaskable-chunk"


# ---------------------------------------------------- inside an agent request
PNG = base64.b64encode(b"\x89PNG\r\n\x1a\n" + bytes(300)).decode()
PDF = base64.b64encode(b"%PDF-1.4 " + TOKEN.encode() + bytes(300)).decode()


def test_pictures_and_pdfs_in_an_agent_request_are_named(pipe):
    body = {"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": PNG}},
        {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": PDF}},
        {"type": "text", "text": "what is in these?"}]}]}
    masked, st = pipe.mask_json(body)
    assert masked == body                                 # the bytes stay exact (gateway contract)
    assert st.not_masked == "image,pdf"


def test_openai_shapes_are_named_too(pipe):
    body = {"model": "m", "input": [{"role": "user", "content": [
        {"type": "input_image", "image_url": "data:image/png;base64," + PNG},
        {"type": "input_file", "filename": "x.pdf", "file_data": "data:application/pdf;base64," + PDF}]}]}
    masked, st = pipe.mask_json(body)
    assert masked == body and st.not_masked == "image,pdf"


def test_a_text_file_sent_as_base64_is_masked_not_just_named(pipe):
    text = f"plain text file: {TOKEN} {EMAIL}"
    b64 = base64.b64encode(text.encode()).decode()
    body = {"model": "m", "messages": [{"role": "user", "content": [
        {"type": "document", "source": {"type": "base64", "media_type": "text/plain", "data": b64}},
        {"type": "input_file", "file_data": "data:text/plain;base64," + b64}]}]}
    masked, st = pipe.mask_json(body)
    one = base64.b64decode(masked["messages"][0]["content"][0]["source"]["data"]).decode()
    two = base64.b64decode(masked["messages"][0]["content"][1]["file_data"].split(",", 1)[1]).decode()
    for sent in (one, two):
        assert TOKEN not in sent and EMAIL not in sent and sent.startswith("plain text file: ")
    assert st.not_masked == "" and st.secrets >= 1


def test_a_request_with_no_media_has_no_note(pipe):
    _, st = pipe.mask_json({"model": "m", "messages": [{"role": "user", "content": f"mail {EMAIL}"}]})
    assert st.not_masked == ""


# ------------------------------------------------------------- the API door
@pytest.fixture
def api(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    up = Upstream()
    from starlette.routing import Route
    up.app.router.routes.append(Route("/{p:path}", up.files, methods=["GET", "POST", "DELETE"]))
    upc = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app))
    app = create_app(MaskingSession(), anthropic_upstream="http://anthropic.test", openai_upstream="http://openai.test", client=upc)
    return up, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")


@pytest.mark.anyio
async def test_the_receipt_names_a_picture_an_agent_sent(api):
    up, client = api
    body = {"model": "m", "max_tokens": 5, "messages": [{"role": "user", "content": [
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": PNG}}]}]}
    r = await client.post("/v1/messages", json=body, headers={"x-api-key": "k", "anthropic-version": "2023-06-01"})
    assert r.status_code == 200
    assert receipts.tail(1)[0]["note"] == "file-not-masked:image"


@pytest.mark.anyio
@pytest.mark.parametrize("method", ["GET", "DELETE"])
async def test_a_body_on_get_or_delete_is_masked_like_any_other(api, method):
    up, client = api
    body = json.dumps({"reason": f"mail {EMAIL} key {TOKEN}"}).encode()
    r = await client.request(method, "/v1/things/x", content=body, headers={"content-type": "application/json", "authorization": "Bearer k"})
    assert r.status_code == 200
    assert EMAIL not in up.calls[-1]["raw"] and TOKEN not in up.calls[-1]["raw"]


@pytest.mark.anyio
async def test_a_text_field_of_an_upload_form_is_masked(api):
    up, client = api
    form = (f'--B\r\nContent-Disposition: form-data; name="prompt"\r\n\r\nkey {TOKEN} mail {EMAIL}\r\n'
            f'--B\r\nContent-Disposition: form-data; name="file"; filename="a.txt"\r\nContent-Type: text/plain\r\n\r\nhello\r\n--B--\r\n').encode()
    r = await client.post("/v1/audio/transcriptions", content=form,
                          headers={"content-type": "multipart/form-data; boundary=B", "authorization": "Bearer k"})
    assert r.status_code == 200
    assert EMAIL not in up.calls[-1]["raw"] and TOKEN not in up.calls[-1]["raw"]


@pytest.mark.anyio
async def test_a_compressed_body_on_a_non_prompt_route_says_why_it_was_not_read(api):
    up, client = api
    r = await client.post("/v1/things", content=gzip.compress(b'{"a": 1}'),
                          headers={"content-type": "application/json", "content-encoding": "gzip", "authorization": "Bearer k"})
    assert r.status_code == 200
    assert receipts.tail(1)[0]["note"] == "passthrough:compressed"


# ---------------------------------------------------------- the system door
def _flow(host: str, path: str, ctype: str, body: bytes):
    f = tflow.tflow()
    f.request.host, f.request.port, f.request.scheme = host, 443, "https"
    f.request.headers["host"] = host
    f.request.path, f.request.method = path, "POST"
    f.request.headers["content-type"] = ctype
    f.request.set_content(body)
    return f


def test_an_engine_failure_on_a_non_prompt_request_is_named_not_silent(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    addon = OmnaAddon(Pipeline(MaskingSession()), Policy(), door="system", resolver=lambda peer: (1, "Google Chrome"))

    def boom(*a, **k):
        raise smart.EngineCrashed("masking engine crashed")
    monkeypatch.setattr(MaskingSession, "mask_text", boom)
    f = _flow("claude.ai", "/api/account/settings", "application/json", json.dumps({"note": f"mail {EMAIL}"}).encode())
    asyncio.run(addon.request(f))
    assert f.response is None                       # owner decision: not a prompt, never blocked
    assert f.metadata["omna_note"] == "file-not-masked:engine-error"


def test_a_zip_upload_is_receipted_at_the_system_door(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    addon = OmnaAddon(Pipeline(MaskingSession()), Policy(), door="system", resolver=lambda peer: (1, "Google Chrome"))
    z = _zip({"notes.txt": f"key {TOKEN}".encode()})
    form = (b'--B\r\nContent-Disposition: form-data; name="file"; filename="a.zip"\r\nContent-Type: application/zip\r\n\r\n'
            + z + b"\r\n--B--\r\n")
    f = _flow("claude.ai", "/api/organizations/0f1e/upload", "multipart/form-data; boundary=B", form)
    asyncio.run(addon.request(f))
    assert f.response is None and f.metadata["omna_note"] == "file-not-masked:zip"


# ------------------------------------------------------- the report and log
def test_the_report_counts_what_was_sent_unread(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    base = {"door": "system", "route": "/upload", "host": "claude.ai", "status": 200, "masked": {}, "ms": 5}
    receipts.append({**base, "note": "file-not-masked:zip"})
    receipts.append({**base, "note": "file-not-masked:image,pdf"})
    receipts.append({**base, "note": "passthrough-nonprompt"})
    receipts.append(base)
    d = report.build(7)
    assert d["requests_not_masked"] == 3
    assert d["not_masked"] == {"zip": 1, "image": 1, "pdf": 1, "not-a-prompt": 1}
    text = report.render_text(d)
    assert "SENT UNREAD: 3 request(s)" in text and "a zip file ×1" in text and "a picture ×1" in text
    assert "SENT UNREAD" in report.render_html(d)


def test_the_report_says_so_when_nothing_was_sent_unread(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    receipts.append({"door": "api", "route": "/v1/messages", "host": "x", "status": 200, "masked": {}, "ms": 5})
    assert "nothing was sent unread" in report.render_text(report.build(7))


def test_every_word_a_receipt_can_carry_has_plain_words():
    for word in ("zip", "compressed", "unknown", "docx", "xlsx", "office-hidden", "office-pictures", "office-embedded",
                 "office-unchecked", "pdf", "pdf-hidden", "pdf-scanned-pages", "pdf-unchecked", "image", "pptx",
                 "old-office", "audio", "video", "encoded-data", "engine-error"):
        assert word in receipts.NOT_MASKED_WORDS, word
    assert receipts.not_masked_words("file-not-masked:zip,image") == "a zip file, a picture"


def test_plain_text_behind_a_data_address_is_masked(pipe):
    # Row 19 re-run: {"url": "data:text/plain,<a Slack token>"} went out as it was.
    masked, st = pipe.mask_json({"model": "m", "messages": [{"role": "user", "content": [
        {"type": "image_url", "image_url": {"url": f"data:text/plain,key {TOKEN} mail {EMAIL}"}}]}]})
    url = masked["messages"][0]["content"][0]["image_url"]["url"]
    assert url.startswith("data:text/plain,key ") and TOKEN not in url and EMAIL not in url
    assert st.not_masked == ""
