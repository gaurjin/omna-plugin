"""The local masking proxy.

Listens on 127.0.0.1 only. Any tool that speaks the Anthropic Messages API or
the OpenAI API is pointed at it (``ANTHROPIC_BASE_URL`` / ``OPENAI_BASE_URL``).
For every request: mask the JSON body, forward it with the caller's own
credentials and headers, restore tokens in the reply (streamed or not), write
one receipt. Nothing is sent anywhere except the upstream the tool was
already talking to.

Gateway rules from code.claude.com/docs/en/llm-gateway-protocol that this file
honours: forward ``anthropic-beta`` and ``anthropic-version`` verbatim, keep
the ``system`` array shape, forward ``cache_control``, relay SSE without
buffering (pings included), forward error bodies unmodified, answer
``HEAD /api/hello``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import os
import time
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from urllib.parse import urlsplit

import httpx
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from . import config, crashlog, ext_l3, extension_auth, mappings, ocr, receipts
from .engine import MaskingSession, engine_version
from .pipeline import MaskStats, Pipeline
from .pipeline import _merge as _merge_ws_stats
from .policy import Policy, live_policy
from . import ruleset as ruleset_file
from .smart import mode as smart_mode
from .style import style_for_door, style_for_extension
from .system_door import EXT_HEADER, _is_json
from .ws_upstream import UpstreamRefused, UpstreamSocket

# What Omna for Chrome may record (#184): text it hid in a box, a file it
# masked, a picture it blacked out — and a file it could NOT read, which went
# as it is ("not_read", security review finding 7: always a report line).
CHROME_RECORD_KINDS = ("typed", "file", "file_name", "picture", "not_read")
_SITE_RE = re.compile(r"[a-z0-9][a-z0-9.-]{0,252}")


def _engine_detect(text: str, model: bool = False, ruleset: str | None = None) -> list[dict]:
    """The engine's detect(), behind a name the tests can replace (no model in tests).
    Only Omna for Chrome's /omna/detect-l3 uses it: the Chrome size rule
    applies (smart.py — both models up to 8 KB, the compact model alone above)."""
    from . import smart as smart_models

    return smart_models.detect(text, model, ruleset, for_chrome=True)

try:
    # Read from the installed package's own metadata (pyproject.toml's `version`)
    # so this can never drift from a release the way a second hardcoded string did.
    __version__ = _pkg_version("omna-plugin")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

# Paths that carry prompts. A POST here whose body we cannot parse is refused
# (fail closed) instead of being forwarded unmasked.
INFERENCE_PREFIXES = ("/v1/messages", "/v1/complete", "/v1/chat/completions", "/v1/responses", "/v1/completions", "/v1/embeddings")

# The WebSocket the API door takes (Codex opens it before every session;
# refused, it retried seven times — about eight seconds — before using HTTPS).
WS_ROUTES = frozenset({"/v1/responses"})
log = logging.getLogger("omna")

# Developer aid: OMNA_DEBUG_DUMP=<dir> writes each MASKED request body there.
_DUMP_DIR = os.environ.get("OMNA_DEBUG_DUMP")

# Hop-by-hop or connection-specific headers we never forward in either direction.
_DROP_REQ = {"host", "content-length", "connection", "keep-alive", "transfer-encoding",
             "te", "trailer", "upgrade", "proxy-connection", "accept-encoding"}
_DROP_RESP = {"content-length", "content-encoding", "connection", "keep-alive",
              "transfer-encoding", "te", "trailer", "upgrade"}


# A web app running on the developer's own machine, pointed at the plugin as
# its base URL, is blocked by the browser unless the preflight is answered
# (#137a). We answer it — but ONLY for origins that are themselves local.
#
# Reflecting any origin would be the wrong trade in the same session that
# added a token to the dashboard (#134): a page on the public internet can
# make your browser send a request to 127.0.0.1, and approving its origin is
# what turns your machine into an open relay for it. A public page's origin is
# `https://something`, which never matches this, so the browser blocks it at
# the preflight. A page already served from your own localhost could do this
# anyway, with or without us.
_LOCAL_ORIGIN_RE = __import__("re").compile(r"^https?://(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$", __import__("re").I)


# The first page of the dashboard and the mappings screen. It holds no data.
# It takes the token from after the "#" (never sent to any server), removes
# it from the address bar and the history entry, keeps it for this tab only,
# and asks for the real page with the token in a header.
_BOOT_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Omna</title>
<meta name="referrer" content="no-referrer"></head>
<body style="font:15px -apple-system,Helvetica,Arial,sans-serif;margin:40px">
<p id="m">Opening…</p>
<script>
(async () => {
  const say = (t) => { document.getElementById('m').textContent = t; };
  let k = new URLSearchParams(location.hash.slice(1)).get('k');
  if (k) {
    try { sessionStorage.setItem('omna_k', k); } catch (e) {}
    history.replaceState(null, '', location.pathname);
  } else {
    try { k = sessionStorage.getItem('omna_k'); } catch (e) {}
  }
  if (!k) { say('This page needs its local token. Run `omna dashboard` (or `omna mappings`) in a terminal to open it.'); return; }
  try {
    const r = await fetch(location.pathname, {headers: {authorization: 'Bearer ' + k}, cache: 'no-store'});
    if (!r.ok) { say('That token is not valid any more. Run `omna dashboard` (or `omna mappings`) again.'); return; }
    const html = await r.text();
    document.open(); document.write(html); document.close();
  } catch (e) { say('Omna is not running. Start it with `omna start -d`.'); }
})();
</script></body></html>"""


def _note(passthrough: bool | str, mstats: MaskStats) -> str | None:
    """What the receipt says about a request that was not (fully) masked.
    ``passthrough``: True, or the reason as a word ("compressed",
    "unparseable") — written as ``passthrough:<reason>``."""
    if mstats.not_masked:
        return f"file-not-masked:{mstats.not_masked}"
    if isinstance(passthrough, str):
        return f"passthrough:{passthrough}"
    return "passthrough" if passthrough else None


def _local_host(host: str) -> bool:
    """True for a Host header naming this machine (any port)."""
    h = host.strip().lower()
    if h.startswith("["):
        h = h[1:h.find("]")] if "]" in h else h
    else:
        h = h.rsplit(":", 1)[0]
    return h in ("127.0.0.1", "localhost", "::1")


def cors_origin_allowed(origin: str, extra: list[str] | None = None) -> bool:
    if not origin:
        return False
    if _LOCAL_ORIGIN_RE.match(origin.strip()):
        return True
    return origin.strip() in (extra or [])


def pick_upstream(request: Request, anthropic: str, openai: str) -> str:
    h = request.headers
    p = request.url.path
    if "anthropic-version" in h or "x-api-key" in h or p.startswith("/v1/messages") or p.startswith("/api/") or p.startswith("/v1/complete"):
        return anthropic
    return openai


def chatgpt_sign_in(request: Request) -> bool:
    """Codex signed in with a ChatGPT account (recorded live 2026-11-16, Codex
    0.169): every request carries this header, and belongs at
    chatgpt.com/backend-api/codex/… — api.openai.com refuses its sign-in
    ("Missing scopes")."""
    return "chatgpt-account-id" in request.headers


# Compressed request bodies the API door opens to mask (Codex sends zstd).
_READABLE_ENCODINGS = frozenset({"gzip", "deflate", "br", "zstd"})
# The opened body may not be larger than this: a small compressed body can
# open into gigabytes.
_MAX_OPENED = 64 * 1024 * 1024


def _asked_to_stream(body: bytes) -> bool:
    """Did this (masked, JSON) request ask for a streamed reply?"""
    try:
        obj = json.loads(body)
    except ValueError:
        return False
    return isinstance(obj, dict) and obj.get("stream") is True


def _open_compressed(body: bytes, enc: str) -> bytes | None:
    """The body uncompressed, or None when omna cannot read it."""
    if enc not in _READABLE_ENCODINGS:
        return None
    try:
        from mitmproxy.net import encoding

        out = encoding.decode(body, enc)
    except Exception:  # noqa: BLE001 — unreadable is unreadable, whatever the decoder raised
        return None
    return out if isinstance(out, bytes) and len(out) <= _MAX_OPENED else None


def _smart_models_failed() -> dict[str, str]:
    from . import smart as smart_models

    return smart_models.failed_models()


def _smart_models_ready() -> list[str]:
    from . import smart as smart_models

    return [smart_models.SHOWN_AS[m] for m in smart_models.ready_models()]


def create_app(
    session: MaskingSession | None = None,
    *,
    anthropic_upstream: str = config.ANTHROPIC_UPSTREAM,
    openai_upstream: str = config.OPENAI_UPSTREAM,
    chatgpt_upstream: str = config.CHATGPT_CODEX_UPSTREAM,
    client: httpx.AsyncClient | None = None,
    pipeline: Pipeline | None = None,
    policy: Policy | None = None,
    doors_state: dict[str, bool] | None = None,
    system_port: int = config.SYSTEM_PORT,
) -> Starlette:
    # When a Pipeline is given, its MaskingSession is the one source of truth
    # (registry, /omna/health counters, etc.) — a separately-passed `session`
    # that wraps a DIFFERENT MaskingSession is ignored rather than silently
    # reporting on the wrong registry.
    session = pipeline.session if pipeline is not None else (session or MaskingSession())
    pipeline = pipeline or Pipeline(session)
    # Outbound TLS. Omna opens the request, so verifying the provider on the way
    # out is our responsibility, not the caller's (#137/security menu). Default
    # is unchanged (the machine's trust store); `omna tls strict` swaps in a
    # fixed certifi bundle so the CA `omna init` added for the INBOUND side
    # cannot vouch for Anthropic on the outbound side.
    if client is None:
        from .upstream_tls import ssl_context

        client = httpx.AsyncClient(
            timeout=httpx.Timeout(None, connect=30.0),
            verify=ssl_context(policy),
        )
    # This door's style is decided once, by the one function that owns the rule
    # (style.py). Every tool behind this door WRITES FILES, so a realistic fake
    # value is refused here — and the refusal is printed into the proxy log
    # rather than applied quietly, because a silent downgrade is exactly the
    # failure this whole feature is trying to avoid.
    pol = policy or Policy.load()
    api_style = style_for_door("api", pol.style)
    if api_style.refused:
        print(api_style.line(), flush=True)

    stats = {
        "requests": 0,
        "started": time.time(),
        "distinct_secrets": set(),
        "distinct_pii": set(),
        "mask_ms_total": 0,
        "mask_ms_count": 0,
        "extension_last_seen": None,
        "extension_version": None,
        "sent_as_is": 0,
    }

    def _live_style() -> str:
        """The style to tell the browser about, from the policy on disk.

        Re-read rather than captured, because the menu bar writes policy.json
        from a different process — the same staleness that made the menu-bar
        restore toggle do nothing (fixed 2026-09-21). No file on disk means the
        caller handed the policy in directly, which is how the tests do it.
        """
        try:
            config.policy_path().stat()
        except OSError:
            return pol.style
        return Policy.load().style

    async def _extension_ok(request: Request) -> bool:
        """Omna for Chrome, and only it (finding 6): EXT_HEADER (a web page
        cannot add it to a cross-site request) AND a recent signature made
        with the secret Chrome hands only to the extension (extension_auth).
        Any other local program that reaches the port is refused."""
        if not request.headers.get(EXT_HEADER):
            return False
        return extension_auth.request_ok(
            request.headers.get(extension_auth.TS_HEADER), request.headers.get(extension_auth.SIG_HEADER),
            request.method, request.url.path, await request.body())

    async def health(request: Request) -> Response:
        ok, n, _msg = receipts.verify()
        # Proof that THIS is the curl command (finding 6): only the holder of
        # the secret can answer the extension's nonce. A program squatting the
        # port cannot, so the extension sends it nothing.
        nonce = request.query_params.get("nonce")
        token = extension_auth.read_token()
        proof = extension_auth.proof(token, nonce) if token and extension_auth.valid_nonce(nonce) else None
        doors = doors_state or {"api": True, "system": False, "deep": False}
        return JSONResponse(
            {
                "ok": True,
                "plugin": __version__,
                "engine": engine_version(),
                "proof": proof,
                "smart": session.smart,
                # What a request gets RIGHT NOW: smart / fast / fast-smart-not-ready.
                "masking": smart_mode(session.smart),
                # Which smart models have arrived and passed their hash check.
                "smart_models": _smart_models_ready() if session.smart else [],
                # Models whose download failed (shown name → reason): status
                # says FAILED instead of "on" (Muse QA B4, 2026-11-17).
                "smart_failed": _smart_models_failed() if session.smart else {},
                # Can this machine read text in pictures (Apple Vision, macOS)?
                # Omna for Chrome sends screenshots to /omna/ocr only when true.
                "ocr": ocr.available(),
                "restore_secrets": session.restore_secrets,
                # What is NOT masked is decided by one file (finding 15): its
                # fingerprint, sizes, and any allowlist entry the engine refused.
                "ruleset": ruleset_file.summary(),
                # What goes back into an agent's tool calls (finding 2).
                "tool_calls": dict(live_policy().tool_calls),
                "secrets_held_in_memory": session.secrets_held,
                "requests_this_run": stats["requests"],
                "distinct_secrets_this_run": len(stats["distinct_secrets"]),
                "distinct_pii_this_run": len(stats["distinct_pii"]),
                "avg_mask_ms_this_run": int(stats["mask_ms_total"] / stats["mask_ms_count"]) if stats["mask_ms_count"] else 0,
                "receipts": n,
                "chain_intact": ok,
                "registry_entries": session.registry_size,
                "registry_at_rest": session.at_rest,  # encrypted | plaintext | locked (#131)
                "doors": doors,
                # The style the BROWSER may write (#143). The Chrome extension
                # masks inside the browser, before the plugin sees anything, so
                # it has to be told — and `style.py` is the only thing allowed
                # to decide. The extension reads this one field and reasons
                # about nothing else.
                "style": style_for_extension(_live_style(), bool(doors.get("system"))).style,
                "extension_last_seen": stats["extension_last_seen"],
                "extension_version": stats["extension_version"],
            }
        )

    async def extension_checkin(request: Request) -> Response:
        # The body is untrusted (localhost, but still someone else's process).
        # Two distinct ways it can be unusable: unparseable (bad JSON syntax —
        # surfaces as ValueError/JSONDecodeError, a ValueError subclass, from
        # Request.json()) and wrong-shaped (valid JSON that isn't an object,
        # e.g. `null` or `[1,2,3]`, which parses fine but has no `.get`). Both
        # land on the same soft-fail fallback rather than a 500.
        if not await _extension_ok(request):
            return JSONResponse({"error": "extension only"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        if not isinstance(body, dict):
            body = {}
        stats["extension_last_seen"] = time.time()
        # The extension owns this counter (it is the only door with a UI that
        # can offer the choice), so it reports it here rather than the plugin
        # trying to infer it. Counts only, like everything else in a receipt.
        n = body.get("sent_as_is")
        if isinstance(n, int) and n >= 0:
            stats["sent_as_is"] = n
        version = body.get("version")
        stats["extension_version"] = version if isinstance(version, str) else None
        return JSONResponse({"ok": True})

    async def detect_l3(request: Request) -> Response:
        """Smart masking for Omna for Chrome (ext_l3.py): the model's finds in a
        short text, in the same shape the Mac app answers with.

        Only the extension may ask: it sends EXT_HEADER, which a web page
        cannot add to a cross-site request without a CORS preflight this
        server never approves — so a page can't make this machine run the
        model. Untrusted body, same soft handling as extension_checkin."""
        if not await _extension_ok(request):
            return JSONResponse({"error": "extension only"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = None
        text = body.get("text") if isinstance(body, dict) else None
        if not isinstance(text, str):
            return JSONResponse({"error": "expected {\"text\": string}"}, status_code=400)
        if not session.smart:
            return JSONResponse({"smart": False, "spans": []})
        if len(text) > ext_l3.MAX_CHARS:
            return JSONResponse({"smart": True, "spans": [], "too_long": True})
        spans = await run_in_threadpool(
            ext_l3.model_spans, text, _engine_detect, session._ruleset_arg(),
        )
        return JSONResponse({"smart": True, "spans": spans})

    async def chrome_record(request: Request) -> Response:
        """One record from Omna for Chrome (#184): it joins this computer's
        chain as product "chrome", door "chrome", so `omna report` covers
        both products. Same format as every receipt (receipts.py), built from
        the masking engine's L6 finds — never a value. Extension only
        (EXT_HEADER); the body is untrusted, so every field is checked
        exactly and anything else is refused, never half-written."""
        if not await _extension_ok(request):
            return JSONResponse({"error": "extension only"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = None
        if not isinstance(body, dict):
            return JSONResponse({"error": "expected a record"}, status_code=400)
        kind, site, engine = body.get("kind"), body.get("site"), body.get("engine", "")
        finds = receipts.valid_finds(body.get("finds"))
        unlisted = body.get("unlisted", 0)
        not_read = body.get("not_read")
        if (kind == "not_read") != (not_read is not None) or (
                not_read is not None and not (isinstance(not_read, str) and not_read in receipts.NOT_MASKED_WORDS)):
            return JSONResponse({"error": "not a valid record"}, status_code=400)
        if (kind not in CHROME_RECORD_KINDS or finds is None
                or not isinstance(site, str) or not _SITE_RE.fullmatch(site)
                or not isinstance(engine, str) or len(engine) > 64
                or not isinstance(unlisted, int) or isinstance(unlisted, bool) or not 0 <= unlisted <= 1_000_000):
            return JSONResponse({"error": "not a valid record"}, status_code=400)
        if not Policy.load().reports_enabled:
            return JSONResponse({"ok": True, "kept": False})
        rec = {
            "v": receipts.FORMAT, "product": "chrome", "engine": engine, "kind": kind,
            "door": "chrome", "route": kind, "host": site, "upstream": site, "status": 200,
            "finds": finds, **receipts.totals_of(finds),
        }
        if unlisted:
            # Found by the Mac app, which reports a count but no L6 list.
            rec["unlisted"] = unlisted
        if body.get("masking") in ("fast", "smart"):
            rec["masking"] = body["masking"]     # which masking Omna for Chrome really used
        if not_read:
            # Same note the curl command's own doors write, so the report
            # counts both products' unread files in one line.
            rec["note"] = f"file-not-masked:{not_read}"
        try:
            await run_in_threadpool(receipts.append, rec)
        except OSError:
            return JSONResponse({"error": "could not write"}, status_code=500)
        return JSONResponse({"ok": True, "kept": True})

    async def read_picture(request: Request) -> Response:
        """Read the text in a picture for Omna for Chrome (ocr.py): lines and
        their boxes, NOT masked — the extension masks with its own stand-ins so
        one conversation never has two lists. Extension only (EXT_HEADER),
        untrusted body handled softly, like detect_l3."""
        if not await _extension_ok(request):
            return JSONResponse({"error": "extension only"}, status_code=403)
        try:
            body = await request.json()
        except ValueError:
            body = None
        b64 = body.get("content_b64") if isinstance(body, dict) else None
        if not isinstance(b64, str):
            return JSONResponse({"error": "expected {\"content_b64\": string}"}, status_code=400)
        if not ocr.available():
            return JSONResponse({"available": False})
        import base64 as _b64
        import binascii

        try:
            data = _b64.b64decode(b64, validate=True)
        except (binascii.Error, ValueError):
            return JSONResponse({"error": "content_b64 is not base64"}, status_code=400)
        try:
            result = await run_in_threadpool(ocr.recognize, data)
        except (ValueError, RuntimeError) as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        return JSONResponse({"available": True, **result})

    def _dashboard_ok(request: Request) -> bool:
        """The dashboard needs the token from ~/.omna/dashboard.token (#134).

        Accepted ONLY as `Authorization: Bearer`. It used to be accepted as
        `?k=` in the address too, which put the token into the browser's
        history, into any page linked from there (Referer) and into anything
        that logs addresses (security review 2026-11-11, delete list).
        `omna dashboard` now opens the page with the token after a `#`,
        which a browser never sends anywhere; a small first page (`_BOOT_PAGE`)
        takes it out of the address at once and asks again with the header.
        Compared in constant time so a local process cannot narrow it down.
        """
        import secrets as _secrets

        want = config.dashboard_token(create=True)
        got = ""
        auth = request.headers.get("authorization", "")
        if auth.lower().startswith("bearer "):
            got = auth[7:].strip()
        return bool(want) and _secrets.compare_digest(got, want)

    def _page_or_401(request: Request) -> Response:
        """A browser opening the page has no way to send a header: it gets
        the first page (no data in it), which then asks properly."""
        if "authorization" not in request.headers:
            return Response(_BOOT_PAGE, media_type="text/html; charset=utf-8", headers={"cache-control": "no-store"})
        return _unauthorised()

    def _unauthorised() -> Response:
        return JSONResponse(
            {"error": "omna: the dashboard needs its local token. Run `omna dashboard` "
                      "to open it, or read ~/.omna/dashboard.token and send it as `Authorization: Bearer <token>`."},
            status_code=401,
        )

    async def dashboard(request: Request) -> Response:
        from . import dashboard as dash

        if not _dashboard_ok(request):
            return _page_or_401(request)
        d = dash.snapshot(days=7, sent_as_is=stats.get("sent_as_is", 0))
        return Response(dash.render(d), media_type="text/html; charset=utf-8", headers={"cache-control": "no-store"})

    async def dashboard_json(request: Request) -> Response:
        from . import dashboard as dash

        if not _dashboard_ok(request):
            return _unauthorised()
        return JSONResponse(dash.snapshot(days=7, sent_as_is=stats.get("sent_as_is", 0)))

    _NO_STORE = {"cache-control": "no-store"}

    async def mappings_page(request: Request) -> Response:
        if not _dashboard_ok(request):
            return _page_or_401(request)
        return Response(mappings.render(mappings.snapshot(session)), media_type="text/html; charset=utf-8",
                         headers=_NO_STORE)

    async def mappings_json(request: Request) -> Response:
        if not _dashboard_ok(request):
            return _unauthorised()
        q = request.query_params
        d = mappings.snapshot(
            session,
            q=q.get("q", ""), kind=q.get("kind", ""),
            sort=q.get("sort", "created"), dir=q.get("dir", "desc"),
            page=int(q.get("page", "1") or "1"), per_page=int(q.get("per_page", "50") or "50"),
            reveal=q.get("reveal", ""),
        )
        return JSONResponse(d, headers=_NO_STORE)

    async def mappings_delete(request: Request) -> Response:
        if not _dashboard_ok(request):
            return _unauthorised()
        try:
            body = await request.json()
        except ValueError:
            body = {}
        label = str((body or {}).get("label") or "")
        ok = bool(label) and session.delete_mapping(label)
        return JSONResponse({"ok": ok}, headers=_NO_STORE)

    async def mappings_clear(request: Request) -> Response:
        if not _dashboard_ok(request):
            return _unauthorised()
        session.forget()
        mappings.invalidate_cache()
        return JSONResponse({"ok": True}, headers=_NO_STORE)

    async def pac(_: Request) -> Response:
        return Response(
            (policy or Policy.load()).pac(system_port=system_port),
            media_type="application/x-ns-proxy-autoconfig",
        )

    def _cors_headers(request: Request) -> dict:
        """Headers that let a LOCAL web app read the reply (#137a). Empty for
        anything else, which is what keeps a public page from using us."""
        origin = request.headers.get("origin", "")
        allowed = (policy or Policy.load()).cors_origins if policy is not None else Policy.load().cors_origins
        if not cors_origin_allowed(origin, allowed):
            return {}
        return {
            "access-control-allow-origin": origin,
            "access-control-allow-credentials": "true",
            "access-control-expose-headers": "*",
            "vary": "Origin",
        }

    def _upstream_for(conn, path: str) -> tuple[str, str]:
        """(host, address) this request or WebSocket goes to."""
        upstream = pick_upstream(conn, anthropic_upstream, openai_upstream)
        if upstream == openai_upstream and chatgpt_sign_in(conn):
            # "/v1/responses" here is "/responses" there; `path` stays what
            # the tool asked for (the receipt's route, the prompt-route check).
            return (urlsplit(chatgpt_upstream).netloc,
                    chatgpt_upstream.rstrip("/") + (path[len("/v1"):] if path.startswith("/v1/") else path))
        return urlsplit(upstream).netloc, upstream.rstrip("/") + path

    async def ws_relay(websocket: WebSocket) -> None:
        """A tool's WebSocket to the provider: every message it sends is
        masked (an agent's request by the conversation-only rule), every
        reply restored by the tool-call rule — what the system door does for
        the same socket. Refused before anything is read: a name that is not
        this machine, a web page's socket, any path but the one recorded."""
        path = websocket.url.path
        if (not _local_host(websocket.headers.get("host", "")) or path not in WS_ROUTES
                or (websocket.headers.get("origin") and not _cors_headers(websocket))):
            await websocket.close(code=1008)
            return
        upstream_host, url = _upstream_for(websocket, path)
        if websocket.url.query:
            url += "?" + websocket.url.query
        t0 = time.time()
        mstats = MaskStats()
        try:
            from .upstream_tls import ensure_pinned, ssl_context

            await run_in_threadpool(ensure_pinned, upstream_host.split(":")[0], policy)
            up = await UpstreamSocket.open(url, dict(websocket.headers), verify=ssl_context(policy),
                                           subprotocols=websocket.scope.get("subprotocols"))
        except (UpstreamRefused, OSError, asyncio.TimeoutError) as e:
            # The provider said no (or could not be reached): so do we, and the
            # tool falls back to its ordinary requests, masked as always.
            _receipt(websocket, path, upstream_host, getattr(e, "status", 502), mstats, 0, t0, stream=True, note="websocket-refused")
            await websocket.close(code=1011)
            return
        await websocket.accept(subprotocol=up.subprotocol)
        stats["requests"] += 1

        async def outbound() -> None:
            while True:
                msg = await websocket.receive()
                if msg["type"] != "websocket.receive":
                    return
                text = msg.get("text")
                if text is None:
                    try:
                        text = (msg.get("bytes") or b"").decode("utf-8")
                    except UnicodeDecodeError:
                        return        # not readable, so not maskable: never sent on
                # Masking that fails ends the socket here; nothing goes unmasked.
                masked, st = await run_in_threadpool(pipeline.mask_ws_message, text, api_style.style, True)
                _merge_ws_stats(mstats, st)
                await up.send(masked)

        async def inbound() -> None:
            while True:
                m = await up.recv()
                if m is None:
                    return
                if isinstance(m, bytes):
                    await websocket.send_bytes(m)
                else:
                    await websocket.send_text(pipeline.restore_text(m, json_escape=_is_json(m), tools_only=True))

        tasks = [asyncio.create_task(outbound()), asyncio.create_task(inbound())]
        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for t in pending:
                t.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
            for t in done:
                if not t.cancelled() and t.exception() is not None and not isinstance(t.exception(), WebSocketDisconnect):
                    log.error("omna: a WebSocket to %s ended on an error (%s)", upstream_host, type(t.exception()).__name__)
        finally:
            # The receipt first: closing can be cut short when the tool hangs up.
            _receipt(websocket, path, upstream_host, 101, mstats, 0, t0, stream=True, note="websocket")
            for t in tasks:
                t.cancel()
            await up.close()
            try:
                await websocket.close()
            except (RuntimeError, WebSocketDisconnect, OSError):
                pass          # the tool closed it first

    async def relay(request: Request) -> Response:
        path = request.url.path
        # Only this machine, by name: a page that re-points its own domain at
        # 127.0.0.1 (DNS rebinding) arrives with ITS name in Host. Refused
        # before anything is masked, forwarded or restored (MASTER #177).
        if not _local_host(request.headers.get("host", "")):
            return JSONResponse({"type": "error", "error": {"type": "omna_forbidden_host",
                                 "message": "omna answers only requests addressed to 127.0.0.1 or localhost"}}, status_code=403)
        if request.method == "HEAD" and path == "/api/hello":
            return Response(status_code=200)

        cors = _cors_headers(request)
        if request.method == "OPTIONS" and request.headers.get("origin"):
            # The browser's preflight. Answer it here: forwarding it upstream
            # gets an answer for api.anthropic.com's origin rules, not ours.
            if not cors:
                return Response(status_code=403)
            return Response(status_code=204, headers={
                **cors,
                "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
                # Echo what was asked for rather than guessing: tools send
                # x-api-key, anthropic-version, anthropic-beta, authorization...
                "access-control-allow-headers": request.headers.get("access-control-request-headers", "*"),
                "access-control-max-age": "600",
            })
        upstream_host, url = _upstream_for(request, path)
        if request.url.query:
            url += "?" + request.url.query

        body = await request.body()
        mstats = MaskStats()
        passthrough = False
        ctype = request.headers.get("content-type", "")
        is_inference = any(path.startswith(pfx) for pfx in INFERENCE_PREFIXES)
        opened = False
        enc = request.headers.get("content-encoding", "").strip().lower()
        if body and enc and is_inference and "json" in ctype:
            # A compressed prompt (Codex: zstd) is opened, masked and sent on
            # plain. One omna cannot open is refused below, as before.
            plain = await run_in_threadpool(_open_compressed, body, enc)
            if plain is not None:
                body, opened = plain, True
        # Any method: a GET or DELETE can carry a body too, and it used to go
        # out unread with nothing in the receipt (security review, finding 7).
        if body:
            if "json" in ctype and (opened or not request.headers.get("content-encoding")):
                out = await run_in_threadpool(pipeline.mask_bytes, body, ctype, api_style.style)
                if out.refused is None:
                    body = out.body
                    mstats = out.stats
                    if _DUMP_DIR:
                        try:
                            os.makedirs(_DUMP_DIR, exist_ok=True)
                            with open(os.path.join(_DUMP_DIR, f"{int(time.time()*1000)}-{path.strip('/').replace('/', '_')}.json"), "wb") as f:
                                f.write(body)
                        except OSError:
                            pass
                elif out.refused == "mask-failed":
                    # The body parsed as JSON fine, but masking it blew up. Never
                    # forward that unmasked, on ANY route (inference or not).
                    _receipt(request, path, upstream_host, 400, MaskStats(), len(body), time.time(), stream=False, note=out.refused)
                    return JSONResponse({"type": "error", "error": {"type": "omna_refused", "message": "omna could not mask this request; refused rather than sent unmasked"}}, status_code=400)
                elif is_inference:
                    _receipt(request, path, upstream_host, 400, MaskStats(), len(body), time.time(), stream=False, note=out.refused)
                    return JSONResponse({"type": "error", "error": {"type": "omna_refused", "message": "omna could not parse this request as JSON; refused rather than sent unmasked"}}, status_code=400)
                else:
                    passthrough = "unparseable"   # not a prompt route, not readable as JSON: sent as it is
            elif is_inference:
                _receipt(request, path, upstream_host, 400, MaskStats(), len(body), time.time(), stream=False, note="unparseable")
                return JSONResponse({"type": "error", "error": {"type": "omna_refused", "message": f"omna only forwards JSON to {path} (got content-type {ctype!r}, content-encoding {request.headers.get('content-encoding')!r}); refused rather than sent unmasked"}}, status_code=400)
            elif request.headers.get("content-encoding"):
                passthrough = "compressed"  # compressed and not a prompt route: forwarded as-is, marked in the receipt
            elif "multipart/form-data" in ctype.lower():
                # An upload form (/v1/files): its file parts are masked like an
                # attached file at the system door; the other parts stay
                # byte-for-byte. Used to go out exactly as it came in
                # (architecture review, MASTER #178). Unreadable: refused.
                # Every part, not only the files: a text field of the form
                # (a transcription's "prompt") is yours too (finding 7).
                out = await run_in_threadpool(pipeline.mask_bytes, body, ctype, api_style.style)
                if out.body is None:
                    _receipt(request, path, upstream_host, 400, MaskStats(), len(body), time.time(), stream=False, note=out.refused)
                    return JSONResponse({"type": "error", "error": {"type": "omna_refused", "message": "omna could not read this upload form; refused rather than sent unmasked"}}, status_code=400)
                body, mstats = out.body, out.stats
            else:
                # A raw file (text, code, .env, Word, Excel) is masked; a
                # picture, audio or PDF goes as it is and the receipt says so.
                masked, mstats = await run_in_threadpool(pipeline.mask_file, body, ctype, api_style.style)
                passthrough = masked == body and not mstats.counts
                body = masked

        headers = {k: v for k, v in request.headers.items()
                   if k.lower() not in _DROP_REQ and not (opened and k.lower() == "content-encoding")}
        if headers.get("content-disposition"):
            # A raw upload names its file in its own headers (finding 12).
            cd, cd_stats = pipeline.mask_content_disposition(headers["content-disposition"].encode("utf-8", "surrogateescape"), api_style.style)
            if cd_stats.counts:
                headers["content-disposition"] = cd.decode("utf-8", "surrogateescape")
                from .pipeline import _merge as _merge_stats
                _merge_stats(mstats, cd_stats)
        headers["host"] = upstream_host
        headers["accept-encoding"] = "identity"

        # If this host is pinned, check it BEFORE anything is forwarded — the
        # whole point is to not hand a masked prompt and a real API key to an
        # impostor. No pins configured (the default) means this returns at once.
        try:
            from .upstream_tls import PinnedVerificationError, ensure_pinned

            await run_in_threadpool(ensure_pinned, upstream_host.split(":")[0], policy)
        except PinnedVerificationError as e:
            _receipt(request, path, upstream_host, 526, mstats, len(body), time.time(),
                     stream=False, note="pin-mismatch")
            return JSONResponse(
                {"type": "error", "error": {"type": "omna_pin_mismatch", "message": str(e)}},
                status_code=526, headers=cors,
            )

        t0 = time.time()
        stats["requests"] += 1
        req = client.build_request(request.method, url, headers=headers, content=body)
        try:
            resp = await client.send(req, stream=True)
        except httpx.HTTPError as e:
            _receipt(request, path, upstream_host, 502, mstats, len(body), t0, stream=False)
            return JSONResponse({"type": "error", "error": {"type": "omna_upstream_error", "message": str(e)}}, status_code=502, headers=cors)

        resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _DROP_RESP}
        # Upstream answered for ITS origin rules, not ours: a local web app
        # talking to the plugin needs ours (#137a). Ours win on conflict.
        resp_headers.update(cors)
        is_sse = "text/event-stream" in resp.headers.get("content-type", "")
        if (not resp.headers.get("content-type") and is_inference and resp.status_code < 400
                and _asked_to_stream(body)):
            # chatgpt.com answers Codex's turn with an event stream and NO
            # content-type (recorded live 2026-11-16): read as a plain reply,
            # it reached Codex with the stand-ins still in it.
            is_sse = True

        if is_sse:
            async def gen():
                restorer = pipeline.sse_restorer(minted=mstats.tokens)
                try:
                    async for chunk in resp.aiter_bytes():
                        out = restorer.feed(chunk)
                        if out:
                            yield out
                    tail = restorer.flush()
                    if tail:
                        yield tail
                finally:
                    await resp.aclose()
                    _receipt(request, path, upstream_host, resp.status_code, mstats, len(body), t0, stream=True, note=_note(passthrough, mstats))

            return StreamingResponse(gen(), status_code=resp.status_code, headers=resp_headers)

        data = await resp.aread()
        await resp.aclose()
        if resp.status_code < 400 and "json" in resp.headers.get("content-type", ""):
            try:
                data = json.dumps(pipeline.restore_json(json.loads(data), minted=mstats.tokens), ensure_ascii=False).encode("utf-8")
            except ValueError:
                pass
        _receipt(request, path, upstream_host, resp.status_code, mstats, len(body), t0, stream=False, note=_note(passthrough, mstats))
        return Response(data, status_code=resp.status_code, headers=resp_headers)

    def _receipt(request: Request, path: str, upstream_host: str, status: int, mstats: MaskStats, nbytes: int, t0: float, stream: bool, note: str | None = None):
        for tok in mstats.tokens:
            (stats["distinct_secrets"] if str(tok).startswith("SECRET_") else stats["distinct_pii"]).add(tok)
        if mstats.mask_ms > 0:  # masking actually ran (not a refusal/passthrough/no-body request)
            stats["mask_ms_total"] += mstats.mask_ms
            stats["mask_ms_count"] += 1
        pipeline.receipt(
            door="api",
            route=path,
            host=upstream_host,
            status=status,
            stats=mstats,
            nbytes=nbytes,
            ms=int((time.time() - t0) * 1000),
            stream=stream,
            app=None,
            note=note,
            session_id=request.headers.get("x-claude-code-session-id"),
            style=api_style.style,
        )

    async def on_error(request: Request, exc: Exception) -> Response:
        """A crash inside the proxy is the one nobody ever sees — it happens in
        a background process, so the person just gets a 500 from a tool. Record
        it locally (masked, never sent) so `omna crash` can show it (#132)."""
        crashlog.record(exc, where="proxy", extra={"route": request.url.path})
        return JSONResponse(
            {"type": "error", "error": {"type": "omna_internal_error",
                                        "message": "omna hit an internal error; run `omna crash` to see it"}},
            status_code=500,
        )

    app = Starlette(
        exception_handlers={Exception: on_error},
        routes=[
            Route("/omna/health", health, methods=["GET"]),
            Route("/omna/proxy.pac", pac, methods=["GET"]),
            Route("/omna/extension-checkin", extension_checkin, methods=["POST"]),
            Route("/omna/detect-l3", detect_l3, methods=["POST"]),
            Route("/omna/ocr", read_picture, methods=["POST"]),
            Route("/omna/record", chrome_record, methods=["POST"]),
            Route("/omna/dashboard", dashboard, methods=["GET"]),
            Route("/omna/dashboard.json", dashboard_json, methods=["GET"]),
            Route("/omna/mappings", mappings_page, methods=["GET"]),
            Route("/omna/mappings.json", mappings_json, methods=["GET"]),
            Route("/omna/mappings/delete", mappings_delete, methods=["POST"]),
            Route("/omna/mappings/clear", mappings_clear, methods=["POST"]),
            Route("/{path:path}", relay, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]),
            WebSocketRoute("/{path:path}", ws_relay),
        ]
    )
    app.state.session = session
    app.state.client = client
    return app
