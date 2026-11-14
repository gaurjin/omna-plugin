"""Tests for the Mappings Review screen (#144): the registry/receipts join,
query (search/filter/sort/paginate), and disclosure-on-demand rules."""

from __future__ import annotations

import json as _json

import httpx
import pytest
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route

from omna_plugin import config, mappings, receipts
from omna_plugin.engine import MaskingSession
from omna_plugin.proxy import create_app
from omna_plugin.style import REALISTIC, TOKENS


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def test_snapshot_joins_times_sent_last_sent_providers_and_apps(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    receipts.append({"tokens": ["EMAIL_1"], "upstream": "api.anthropic.com", "app": "Claude Code",
                      "ts": "2026-09-20T10:00:00+0000"})
    receipts.append({"tokens": ["EMAIL_1"], "upstream": "api.openai.com", "app": "aider",
                      "ts": "2026-09-20T11:00:00+0000"})
    mappings.invalidate_cache()
    rows = mappings.snapshot(s)["rows"]
    assert len(rows) == 1
    r = rows[0]
    assert r["label"] == "EMAIL_1"
    assert r["times_sent"] == 2
    assert r["last_sent"] == "2026-09-20T11:00:00+0000"
    assert r["providers"] == ["api.anthropic.com", "api.openai.com"]
    assert r["apps"] == ["Claude Code", "aider"]


def test_snapshot_row_with_no_receipts_yet_shows_zero_not_missing(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    mappings.invalidate_cache()
    r = mappings.snapshot(s)["rows"][0]
    assert r["times_sent"] == 0
    assert r["last_sent"] is None
    assert r["providers"] == []
    assert r["apps"] == []


def test_reveal_is_off_by_default(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s)
    assert d["rows"][0]["value"] is None


def test_reveal_one_label_discloses_only_that_row(home):
    s = MaskingSession()
    s.mask_text("email a@x.com", style=TOKENS)
    s.mask_text("email b@x.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, reveal="EMAIL_1")
    by_label = {r["label"]: r for r in d["rows"]}
    assert by_label["EMAIL_1"]["value"] == "a@x.com"
    assert by_label["EMAIL_2"]["value"] is None


def test_reveal_all_is_gone_one_row_at_a_time_only(home):
    # Security review 2026-11-11, delete list: one request used to hand over
    # every real value on the page.
    s = MaskingSession()
    s.mask_text("email a@x.com", style=TOKENS)
    s.mask_text("email b@x.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, reveal="all")
    assert all(r["value"] is None for r in d["rows"])
    assert "revealAll" not in mappings.render(mappings.snapshot(s))


def test_the_page_escapes_every_value_it_shows(home):
    # Finding 18: rows were built by pasting values into HTML as they were.
    page = mappings.render(mappings.snapshot(MaskingSession()))
    assert "const esc = " in page
    row = page[page.index("tr.innerHTML = `"):page.index("return tr;")]
    import re
    bare = [m for m in re.findall(r"\$\{([^}]*)\}", row) if not m.startswith("esc(") and "? 'yes' : 'no'" not in m]
    assert bare == [], f"not escaped: {bare}"


def test_the_token_is_never_put_in_an_address(home):
    page = mappings.render(mappings.snapshot(MaskingSession()))
    assert "?k=" not in page and "location.search" not in page and "authorization: 'Bearer '" in page


def test_filter_by_kind(home):
    s = MaskingSession()
    s.mask_text("email a@x.com and key AKIAIOSFODNN7EXAMPLE", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, kind="EMAIL")
    assert all(r["kind"] == "EMAIL" for r in d["rows"])
    assert "EMAIL" in d["kinds"]


def test_search_by_label(home):
    s = MaskingSession()
    s.mask_text("email a@x.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, q="email_1")
    assert len(d["rows"]) == 1


def test_pagination(home):
    s = MaskingSession()
    for i in range(5):
        s.mask_text(f"email person{i}@x.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s, per_page=2, page=1)
    assert len(d["rows"]) == 2 and d["total"] == 5
    d2 = mappings.snapshot(s, per_page=2, page=3)
    assert len(d2["rows"]) == 1


def test_render_page_never_embeds_a_real_value(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s)
    page = mappings.render(d)
    assert "john.smith@acme.com" not in page
    for bad in ("http://", "https://", "cdn.", "<script src"):
        assert bad not in page


def test_render_page_explains_the_empty_state(home):
    s = MaskingSession()
    d = mappings.snapshot(s)
    page = mappings.render(d)
    assert "hasn" in page.lower() or "no" in page.lower()


def test_render_page_explains_secrets_are_never_shown_here(home):
    s = MaskingSession()
    d = mappings.snapshot(s)
    page = mappings.render(d)
    assert "secret" in page.lower()


def test_render_json_round_trips(home):
    s = MaskingSession()
    s.mask_text("email john.smith@acme.com", style=TOKENS)
    mappings.invalidate_cache()
    d = mappings.snapshot(s)
    parsed = _json.loads(mappings.render_json(d))
    assert parsed["total"] == 1


# ------------------------------------------------------------ routes (proxy)
class _Upstream:
    def __init__(self):
        self.app = Starlette(routes=[Route("/v1/messages", self._ok, methods=["POST"])])

    async def _ok(self, request: Request):
        return JSONResponse({"id": "m1", "content": []})


@pytest.fixture
def app_env(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    up = _Upstream()
    session = MaskingSession()
    up_client = httpx.AsyncClient(transport=httpx.ASGITransport(app=up.app))
    app = create_app(session, anthropic_upstream="http://anthropic.test",
                      openai_upstream="http://openai.test", client=up_client)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://omna.local")
    return session, client


@pytest.mark.anyio
async def test_mappings_page_and_json_require_the_dashboard_token(app_env):
    session, client = app_env
    session.mask_text("email secret.person@x.com", style=TOKENS)
    mappings.invalidate_cache()
    r = await client.get("/omna/mappings.json")
    assert r.status_code == 401
    r = await client.get("/omna/mappings", headers={"authorization": "Bearer wrong"})
    assert r.status_code == 401
    # A browser opening the address gets the first page: no row, no value, no token.
    r = await client.get("/omna/mappings")
    assert r.status_code == 200 and "EMAIL_1" not in r.text and "secret.person" not in r.text
    assert config.dashboard_token(create=True) not in r.text


@pytest.mark.anyio
async def test_mappings_page_and_json_open_with_the_dashboard_token(app_env):
    session, client = app_env
    session.mask_text("email john.smith@acme.com", style=TOKENS)
    k = config.dashboard_token(create=True)
    r = await client.get("/omna/mappings", headers={"authorization": f"Bearer {k}"})
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    j = await client.get("/omna/mappings.json", headers={"authorization": f"Bearer {k}"})
    assert j.status_code == 200
    body = j.json()
    assert body["total"] == 1 and body["rows"][0]["value"] is None


@pytest.mark.anyio
async def test_mappings_routes_send_no_store_cache_headers(app_env):
    session, client = app_env
    k = config.dashboard_token(create=True)
    for path in ("/omna/mappings", "/omna/mappings.json"):
        r = await client.get(path, headers={"authorization": f"Bearer {k}"})
        assert "no-store" in r.headers.get("cache-control", "")


@pytest.mark.anyio
async def test_mappings_delete_requires_token_and_removes_the_row(app_env):
    session, client = app_env
    session.mask_text("email john.smith@acme.com", style=TOKENS)
    r = await client.post("/omna/mappings/delete", json={"label": "EMAIL_1"})
    assert r.status_code == 401
    k = config.dashboard_token(create=True)
    r = await client.post("/omna/mappings/delete", headers={"authorization": f"Bearer {k}"}, json={"label": "EMAIL_1"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert session.registry_rows() == []


@pytest.mark.anyio
async def test_mappings_clear_wipes_everything(app_env):
    session, client = app_env
    session.mask_text("email john.smith@acme.com", style=TOKENS)
    k = config.dashboard_token(create=True)
    r = await client.post("/omna/mappings/clear", headers={"authorization": f"Bearer {k}"})
    assert r.status_code == 200 and r.json()["ok"] is True
    assert session.registry_rows() == []
