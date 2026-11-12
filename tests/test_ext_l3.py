"""Smart masking for Omna for Chrome, served by the curl command (ext_l3.py).

The reply must match the Mac app's L3 reply exactly (UTF-16 offsets, model
labels, model spans only), because the extension merges both the same way.
No real model here: the engine's detect() is replaced by a fake.
"""

from __future__ import annotations

import httpx
import pytest

from omna_plugin import ext_l3
from omna_plugin.engine import MaskingSession
from omna_plugin.proxy import create_app

from tests.ext_helpers import ext_hdr


def test_byte_offsets_become_utf16_offsets():
    text = "é — 😀 Jane Doe"
    raw = text.encode("utf-8")
    start = raw.index("Jane".encode())
    end = start + len("Jane Doe".encode())
    s, e = ext_l3.byte_to_utf16(text, start), ext_l3.byte_to_utf16(text, end)
    # JavaScript counts the emoji as 2 units; slicing the JS-style string must give the name.
    js = text.encode("utf-16-le")
    assert js[s * 2:e * 2].decode("utf-16-le") == "Jane Doe"


def test_model_spans_keeps_only_model_finds_and_uses_model_labels():
    text = "Call Marcus Whitfield at 212-555-0199, born 14 March 1985."
    b = text.encode()

    def fake_detect(t, model=False, ruleset=None):
        assert model is True
        return [
            {"start": b.index(b"Marcus"), "end": b.index(b"Marcus") + len(b"Marcus Whitfield"), "entity": "PERSON", "layer": "L3", "confidence": 0.99},
            {"start": b.index(b"212"), "end": b.index(b"212") + 12, "entity": "PHONE", "layer": "L1", "confidence": 0.6},
            {"start": b.index(b"born"), "end": len(b) - 1, "entity": "DATE_OF_BIRTH", "layer": "L3", "confidence": 0.9},
            {"start": 0, "end": 4, "entity": "SOMETHING_NEW", "layer": "L3", "confidence": 0.9},
        ]

    spans = ext_l3.model_spans(text, fake_detect)
    assert [s["label"] for s in spans] == ["private_person", "private_date"]
    assert text[spans[0]["start"]:spans[0]["end"]] == "Marcus Whitfield"
    assert spans[0]["score"] == pytest.approx(0.99)


def test_compact_model_id_finds_reach_the_extension_with_their_labels():
    # The compact model finds ID kinds the privacy filter has no label for; the
    # extension's merge step accepts its labels, so they must be passed
    # through, not dropped (core/src/detection/l3.rs).
    text = "SSN 123-45-6789, passport X1234567, licence D123-456-789, ID 87654321."
    b = text.encode()

    def at(v: bytes, entity: str) -> dict:
        i = b.index(v)
        return {"start": i, "end": i + len(v), "entity": entity, "layer": "L3", "confidence": 0.9}

    def fake_detect(t, model=False, ruleset=None):
        return [at(b"123-45-6789", "SSN"), at(b"X1234567", "PASSPORT"),
                at(b"D123-456-789", "DRIVER_LICENSE"), at(b"87654321", "NATIONAL_ID")]

    labels = [s["label"] for s in ext_l3.model_spans(text, fake_detect)]
    assert labels == ["SSN", "PASSPORTID", "DRIVERLICENSENUM", "NATIONALID"]


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    session = MaskingSession()
    app = create_app(session)
    c = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")
    return session, c


@pytest.mark.anyio
async def test_only_the_extension_may_ask(client):
    _, c = client
    r = await c.post("/omna/detect-l3", json={"text": "Marcus Whitfield"})
    assert r.status_code == 403


@pytest.mark.anyio
async def test_fast_mode_says_smart_is_off(client):
    session, c = client
    assert session.smart is False
    r = await c.post("/omna/detect-l3", json={"text": "Marcus Whitfield"}, headers=ext_hdr())
    assert r.status_code == 200
    assert r.json() == {"smart": False, "spans": []}


@pytest.mark.anyio
async def test_smart_mode_returns_model_spans(client, monkeypatch):
    session, c = client
    monkeypatch.setattr(session, "smart", True)
    seen = {}

    def fake_detect(t, model=False, ruleset=None):
        seen["text"] = t
        return [{"start": 0, "end": 16, "entity": "PERSON", "layer": "L3", "confidence": 0.98}]

    monkeypatch.setattr("omna_plugin.proxy._engine_detect", fake_detect)
    r = await c.post("/omna/detect-l3", json={"text": "Marcus Whitfield called"}, headers=ext_hdr())
    assert r.status_code == 200
    body = r.json()
    assert body["smart"] is True
    assert body["spans"] == [{"start": 0, "end": 16, "label": "private_person", "score": 0.98}]
    assert seen["text"] == "Marcus Whitfield called"


@pytest.mark.anyio
async def test_too_long_is_refused_without_running_the_model(client, monkeypatch):
    session, c = client
    monkeypatch.setattr(session, "smart", True)

    def boom(*a, **k):
        raise AssertionError("the model must not run on an over-long text")

    monkeypatch.setattr("omna_plugin.proxy._engine_detect", boom)
    r = await c.post("/omna/detect-l3", json={"text": "x" * (ext_l3.MAX_CHARS + 1)}, headers=ext_hdr())
    assert r.status_code == 200
    assert r.json() == {"smart": True, "spans": [], "too_long": True}


@pytest.mark.anyio
@pytest.mark.parametrize("body", [b"not json", b"[1,2]", b'{"text": 5}'])
async def test_bad_bodies_are_refused_not_crashed(client, body):
    _, c = client
    r = await c.post("/omna/detect-l3", content=body, headers={**ext_hdr(), "content-type": "application/json"})
    assert r.status_code == 400
