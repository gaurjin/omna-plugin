"""Reading pictures for Omna for Chrome (ocr.py + /omna/ocr).

The curl command only READS the picture (text + line boxes); the extension
masks with its own stand-ins. No real Vision here: ocr.recognize is faked.
"""

from __future__ import annotations

import base64

import httpx
import pytest

from omna_plugin import ocr
from omna_plugin.engine import MaskingSession
from omna_plugin.proxy import create_app

HDR = {"x-omna-extension": "1"}
PNG = b"\x89PNG\r\n\x1a\nfake"


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    app = create_app(MaskingSession())
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")


@pytest.mark.anyio
async def test_health_says_whether_pictures_can_be_read(client, monkeypatch):
    monkeypatch.setattr(ocr, "available", lambda: True)
    assert (await client.get("/omna/health")).json()["ocr"] is True
    monkeypatch.setattr(ocr, "available", lambda: False)
    assert (await client.get("/omna/health")).json()["ocr"] is False


@pytest.mark.anyio
async def test_only_the_extension_may_ask(client):
    r = await client.post("/omna/ocr", json={"content_b64": base64.b64encode(PNG).decode()})
    assert r.status_code == 403


@pytest.mark.anyio
async def test_reads_lines_and_returns_them_unmasked(client, monkeypatch):
    seen = {}
    monkeypatch.setattr(ocr, "available", lambda: True)

    def fake(data):
        seen["data"] = data
        return {"width": 800.0, "height": 330.0,
                "lines": [{"text": "Email: maria@acme-test.com", "x": 30.0, "y": 100.0, "w": 542.0, "h": 28.0}]}

    monkeypatch.setattr(ocr, "recognize", fake)
    r = await client.post("/omna/ocr", json={"content_b64": base64.b64encode(PNG).decode()}, headers=HDR)
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is True
    assert body["width"] == 800.0 and body["lines"][0]["text"] == "Email: maria@acme-test.com"
    assert seen["data"] == PNG


@pytest.mark.anyio
async def test_not_on_a_mac_says_unavailable(client, monkeypatch):
    monkeypatch.setattr(ocr, "available", lambda: False)
    r = await client.post("/omna/ocr", json={"content_b64": base64.b64encode(PNG).decode()}, headers=HDR)
    assert r.json() == {"available": False}


@pytest.mark.anyio
@pytest.mark.parametrize("body", [b"nope", b"[1]", b'{"content_b64": 5}', b'{"content_b64": "!!!not base64!!!"}'])
async def test_bad_bodies_are_refused(client, monkeypatch, body):
    monkeypatch.setattr(ocr, "available", lambda: True)
    r = await client.post("/omna/ocr", content=body, headers={**HDR, "content-type": "application/json"})
    assert r.status_code == 400


@pytest.mark.anyio
async def test_unreadable_picture_is_a_400_not_a_crash(client, monkeypatch):
    monkeypatch.setattr(ocr, "available", lambda: True)

    def bad(data):
        raise ValueError("not a picture")

    monkeypatch.setattr(ocr, "recognize", bad)
    r = await client.post("/omna/ocr", json={"content_b64": base64.b64encode(b"zzz").decode()}, headers=HDR)
    assert r.status_code == 400
