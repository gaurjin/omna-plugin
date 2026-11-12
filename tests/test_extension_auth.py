"""Security review 2026-11-11, finding 6 (owner's choice "A").

Port 7788 had no password: any local program could call the endpoints only
Omna for Chrome should use, and a program squatting the port when the curl
command was not running received the person's typed text and could answer
"nothing found". `omna ensure` accepted such a stranger as Omna.

Now a secret in ~/.omna is handed only to Omna for Chrome, by Chrome itself
(native messaging); every extension-only call carries it; and the curl command
proves it holds the secret before the extension sends anything.
"""

import io
import json
import struct
import threading
import http.server

import httpx
import pytest

from omna_plugin import cli, config, extension_auth
from omna_plugin.engine import MaskingSession
from omna_plugin.proxy import create_app

STORE = extension_auth.STORE_EXTENSION_ID
DEV = "gmfmilplfpfcaialookihafbfjaaeaig"


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path / "omna"))
    return tmp_path


@pytest.fixture
def client(home):
    app = create_app(MaskingSession(), client=httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200))))
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://127.0.0.1:7788")


ENDPOINTS = [
    ("/omna/detect-l3", {"text": "mail jane.doe@example.com"}),
    ("/omna/ocr", {"content_b64": ""}),
    ("/omna/record", {"kind": "typed", "site": "claude.ai", "finds": []}),
    ("/omna/extension-checkin", {"version": "9"}),
]


def _signed(path: str, raw: bytes, **kw) -> dict:
    return {"x-omna-extension": "1", "content-type": "application/json", **extension_auth.sign("POST", path, raw, **kw)}


@pytest.mark.anyio
@pytest.mark.parametrize("path,body", ENDPOINTS)
async def test_extension_endpoints_refuse_any_program_without_a_valid_signature(client, path, body):
    token = extension_auth.ensure_token()
    raw = json.dumps(body).encode()
    other = json.dumps({**body, "x": 1}).encode()
    for headers in (
        {},
        {"x-omna-extension": "1"},                                          # the old tag alone no longer opens it
        {"x-omna-extension": "1", "x-omna-token": token},                   # the raw secret is not accepted at all
        _signed(path, raw, token="0" * 64),                                  # signed with the wrong secret
        _signed(path, other),                                                # a signature for a DIFFERENT message
        _signed(path, raw, now=__import__("time").time() - 600),             # an old signature, caught and replayed
        {k: v for k, v in _signed(path, raw).items() if k != "x-omna-extension"},
    ):
        r = await client.post(path, content=raw, headers={"content-type": "application/json", **headers})
        assert r.status_code == 403, (path, headers)
    r = await client.post(path, content=raw, headers=_signed(path, raw))
    assert r.status_code != 403


@pytest.mark.anyio
async def test_no_secret_on_the_machine_means_nobody_gets_in(client):
    raw = b'{"text": "x"}'
    hdr = _signed("/omna/detect-l3", raw, token="ab" * 32)
    extension_auth.token_path().unlink(missing_ok=True)     # no secret on this machine
    r = await client.post("/omna/detect-l3", content=raw, headers=hdr)
    assert r.status_code == 403


@pytest.mark.anyio
async def test_health_proves_it_holds_the_secret(client):
    token = extension_auth.ensure_token()
    nonce = "0123abcd" * 4
    h = (await client.get("/omna/health", params={"nonce": nonce})).json()
    assert h["proof"] == extension_auth.proof(token, nonce)
    assert (await client.get("/omna/health")).json()["proof"] is None              # no nonce, no proof
    assert (await client.get("/omna/health", params={"nonce": "not-hex!"})).json()["proof"] is None


def test_the_secret_is_private_and_stable(home):
    t = extension_auth.ensure_token()
    assert len(t) == 64 and extension_auth.ensure_token() == t
    assert oct(extension_auth.token_path().stat().st_mode & 0o777) == "0o600"


def _frame(obj) -> bytes:
    data = json.dumps(obj).encode()
    return struct.pack("=I", len(data)) + data


def _read(out: bytes) -> dict:
    (n,) = struct.unpack("=I", out[:4])
    return json.loads(out[4:4 + n])


def test_chrome_hands_the_secret_only_to_omna_for_chrome(home):
    token = extension_auth.ensure_token()
    out = io.BytesIO()
    assert extension_auth.native_host_main([f"chrome-extension://{STORE}/"], io.BytesIO(_frame({"get": "token"})), out) == 0
    assert _read(out.getvalue()) == {"token": token}
    out = io.BytesIO()
    assert extension_auth.native_host_main(["chrome-extension://" + "a" * 32 + "/"], io.BytesIO(_frame({"get": "token"})), out) == 1
    assert "token" not in _read(out.getvalue())
    out = io.BytesIO()
    assert extension_auth.native_host_main([f"chrome-extension://{STORE}/"], io.BytesIO(_frame({"get": "other"})), out) == 1


def test_a_dev_build_is_allowed_only_when_listed(home):
    assert extension_auth.allowed_extension_ids() == [STORE]
    config.ensure_home()
    (config.home() / "dev_extension_ids").write_text(DEV + "\nnot-an-id\n")
    assert extension_auth.allowed_extension_ids() == [STORE, DEV]


def test_register_writes_one_manifest_per_browser_and_uninstall_removes_it(home, monkeypatch):
    chrome = home / "Chrome"
    chrome.mkdir()
    monkeypatch.setattr(extension_auth, "_browser_roots", lambda: [chrome])
    written = extension_auth.register()
    m = chrome / "NativeMessagingHosts" / f"{extension_auth.HOST_NAME}.json"
    assert written == [str(m)]
    doc = json.loads(m.read_text())
    assert doc["allowed_origins"] == [f"chrome-extension://{STORE}/"] and doc["type"] == "stdio"
    launcher = doc["path"]
    text = open(launcher).read()
    assert "native-host" in text and str(config.home()) in text          # this install's own secret
    assert extension_auth.register() == []                                # idempotent: nothing rewritten
    assert extension_auth.unregister() == [str(m)] and not m.exists()


def _squatter(port_holder: list):
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            b = b'{"ok": true, "plugin": "squatter", "engine": "x", "smart": true, "proof": "f00d"}'
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    port_holder.append(srv.server_address[1])
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def test_omna_ensure_refuses_a_stranger_on_the_port(home, monkeypatch, capsys):
    """The review's 10g case: a stranger answered /omna/health and `omna
    ensure` said 0 without starting the real one."""
    extension_auth.ensure_token()
    spawned = []
    monkeypatch.setattr(cli, "_spawn", lambda *a, **k: spawned.append(a) or 0)
    port = []
    srv = _squatter(port)
    try:
        class A:
            pass
        a = A()
        a.port, a.smart = port[0], False
        assert cli.cmd_ensure(a) == 1
        assert "NOT Omna" in capsys.readouterr().err
        assert spawned == []
    finally:
        srv.shutdown()


def test_a_fresh_machine_without_a_secret_still_refuses_a_stranger(home, monkeypatch, capsys):
    """No secret yet must not mean "trust whoever answers": the secret is made
    first, and the stranger cannot prove it."""
    assert extension_auth.read_token() is None
    spawned = []
    monkeypatch.setattr(cli, "_spawn", lambda *a, **k: spawned.append(a) or 0)
    port = []
    srv = _squatter(port)
    try:
        class A:
            pass
        a = A()
        a.port, a.smart = port[0], False
        assert cli.cmd_ensure(a) == 1 and spawned == []
    finally:
        srv.shutdown()
