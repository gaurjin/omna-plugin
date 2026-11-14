"""A file's NAME is masked like its contents (security review 2026-11-11, finding 12).

"Jane Doe SSN 402-99-1234.txt" had its contents masked and its name sent as
it was — in an upload form, in a raw upload's own headers and in the JSON
that describes the file. All values are fake.
"""

from __future__ import annotations

import asyncio
import json

import httpx
import pytest
from mitmproxy.test import tflow

from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline, split_file_name
from omna_plugin.policy import Policy
from omna_plugin.proxy import create_app
from omna_plugin.system_door import OmnaAddon
from tests.test_proxy import Upstream

EMAIL = "priya.raman@northwind-traders.co"
SSN = "536-22-8841"
NAME = f"payroll {EMAIL} SSN {SSN}.txt"


@pytest.fixture
def pipe(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return Pipeline(MaskingSession())


def test_split_keeps_the_type():
    assert split_file_name("report.final.pdf") == ("report.final", ".pdf")
    assert split_file_name(".env") == (".env", "")
    assert split_file_name("README") == ("README", "")
    assert split_file_name("notes.a-very-long-tail") == ("notes.a-very-long-tail", "")


def test_a_file_name_is_masked_and_keeps_its_extension(pipe):
    out, st = pipe.mask_file_name(NAME)
    assert EMAIL not in out and SSN not in out and out.endswith(".txt") and out.startswith("payroll ")
    assert st.pii >= 2
    assert pipe.session.restore_text(out) == NAME           # and it can be put back in a reply
    assert pipe.mask_file_name("quarterly plan.docx")[0] == "quarterly plan.docx"
    assert pipe.mask_file_name("a.txt")[0] == "a.txt"


def test_a_masked_name_is_never_a_path(pipe, monkeypatch):
    from omna_plugin.pipeline import MaskStats

    monkeypatch.setattr(pipe, "mask_text", lambda text, style="tokens", only=None: ("../x/y\x00z", MaskStats(pii=1)))
    assert pipe.mask_file_name("whatever name.txt")[0] == ".._x_y_z.txt"


def _form(filename_param: bytes) -> bytes:
    return (b'--B\r\nContent-Disposition: form-data; name="purpose"\r\n\r\nchat\r\n'
            b'--B\r\nContent-Disposition: form-data; name="file"; ' + filename_param +
            b'\r\nContent-Type: text/plain\r\n\r\nhello world\r\n--B--\r\n')


@pytest.mark.parametrize("param", [
    f'filename="{NAME}"'.encode(),
    ("filename*=UTF-8''" + NAME.replace(" ", "%20").replace("@", "%40")).encode(),
])
def test_the_file_name_in_an_upload_form_is_masked(pipe, param):
    out = pipe.mask_bytes(_form(param), "multipart/form-data; boundary=B")
    assert out.refused is None
    assert EMAIL.encode() not in out.body and SSN.encode() not in out.body
    assert b"priya.raman%40" not in out.body
    assert b"hello world" in out.body and b'name="purpose"\r\n\r\nchat' in out.body
    assert out.stats.counts.get("EMAIL") == 1


def test_a_signed_upload_form_gets_its_file_name_masked_and_nothing_else_touched(pipe):
    form = _form(f'filename="{NAME}"'.encode())
    out = pipe.mask_upload_form(form, "multipart/form-data; boundary=B")
    assert EMAIL.encode() not in out.body
    assert out.body.split(b'name="file"')[0] == form.split(b'name="file"')[0]      # the signature parts: byte for byte


def test_a_clean_form_is_byte_identical(pipe):
    form = _form(b'filename="quarterly plan.txt"')
    assert pipe.mask_bytes(form, "multipart/form-data; boundary=B").body == form


def test_a_quote_in_the_name_cannot_break_out_of_the_header(pipe):
    out, _ = pipe.mask_content_disposition(f'form-data; name="file"; filename="a%22; x=%22{EMAIL}.txt"'.encode())
    assert EMAIL.encode() not in out
    assert out.count(b'"') == 4, "the masked name is still ONE quoted value"


# --------------------------------------------------- JSON that names a file
@pytest.mark.parametrize("body", [
    {"attachments": [{"file_name": NAME, "file_type": "text/plain"}]},
    {"files": [{"name": NAME, "size": 12}]},
    {"name": NAME},                                                   # a rename
    {"messages": [{"role": "user", "content": [{"type": "file", "file": {"filename": NAME}}]}]},
])
def test_a_file_name_in_json_is_masked(pipe, body):
    masked, _ = pipe.mask_json(body)
    assert EMAIL not in json.dumps(masked) and SSN not in json.dumps(masked)


@pytest.mark.parametrize("body, path", [
    ({"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "t", "name": "Jordan_Lee_lookup", "input": {}}]}]},
     lambda m: m["messages"][0]["content"][0]["name"]),
    ({"messages": [{"role": "assistant", "tool_calls": [{"id": "c", "type": "function", "function": {"name": "Jordan_Lee_lookup", "arguments": "{}"}}]}]},
     lambda m: m["messages"][0]["tool_calls"][0]["function"]["name"]),
    ({"contents": [{"parts": [{"functionCall": {"name": "Jordan_Lee_lookup", "args": {}}}]}]},
     lambda m: m["contents"][0]["parts"][0]["functionCall"]["name"]),
    ({"contents": [{"parts": [{"functionResponse": {"name": "Jordan_Lee_lookup", "response": {"ok": True}}}]}]},
     lambda m: m["contents"][0]["parts"][0]["functionResponse"]["name"]),
    ({"tools": [{"name": "Jordan_Lee_lookup", "description": "x", "input_schema": {"type": "object"}}]},
     lambda m: m["tools"][0]["name"]),
])
def test_a_tools_name_is_still_never_touched(pipe, body, path):
    masked, _ = pipe.mask_json(body)
    assert path(masked) == "Jordan_Lee_lookup"


# ------------------------------------------------------------- the two doors
def test_the_system_door_masks_the_name_in_a_form_and_in_a_raw_uploads_header(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    addon = OmnaAddon(Pipeline(MaskingSession()), Policy(), door="system", resolver=lambda peer: (1, "Google Chrome"))

    def flow(path, ctype, body, headers=None, method="POST"):
        f = tflow.tflow()
        f.request.host, f.request.port, f.request.scheme = "claude.ai", 443, "https"
        f.request.headers["host"] = "claude.ai"
        f.request.path, f.request.method = path, method
        f.request.headers["content-type"] = ctype
        for k, v in (headers or {}).items():
            f.request.headers[k] = v
        f.request.set_content(body)
        asyncio.run(addon.request(f))
        return f

    f = flow("/api/organizations/0f1e/upload", "multipart/form-data; boundary=B", _form(f'filename="{NAME}"'.encode()))
    sent = f.request.get_content()
    assert f.response is None and EMAIL.encode() not in sent and SSN.encode() not in sent
    f = flow("/api/files/raw", "application/octet-stream", b"hello world\n", method="PUT",
             headers={"Content-Disposition": f'attachment; filename="{NAME}"'})
    assert f.response is None and EMAIL not in f.request.headers["content-disposition"]
    assert f.request.headers["content-disposition"].endswith('.txt"')
    assert f.metadata["omna_stats"].counts.get("EMAIL") == 1        # and it is on the receipt


@pytest.mark.anyio
async def test_the_api_door_masks_the_name_in_a_files_upload(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    up = Upstream()
    upc = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app))
    app = create_app(MaskingSession(), anthropic_upstream="http://anthropic.test", openai_upstream="http://openai.test", client=upc)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")
    r = await client.post("/v1/files", content=_form(f'filename="{NAME}"'.encode()),
                          headers={"content-type": "multipart/form-data; boundary=B", "x-api-key": "k", "anthropic-version": "2023-06-01"})
    assert r.status_code == 200
    assert EMAIL not in up.calls[-1]["raw"] and SSN not in up.calls[-1]["raw"] and "hello world" in up.calls[-1]["raw"]
