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

import json
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
from starlette.routing import Route

from . import config, receipts
from .engine import MaskingSession, engine_version
from .pipeline import MaskStats, Pipeline
from .policy import Policy

try:
    # Read from the installed package's own metadata (pyproject.toml's `version`)
    # so this can never drift from a release the way a second hardcoded string did.
    __version__ = _pkg_version("omna-plugin")
except PackageNotFoundError:
    __version__ = "0.0.0+unknown"

# Paths that carry prompts. A POST here whose body we cannot parse is refused
# (fail closed) instead of being forwarded unmasked.
INFERENCE_PREFIXES = ("/v1/messages", "/v1/complete", "/v1/chat/completions", "/v1/responses", "/v1/completions", "/v1/embeddings")

# Developer aid: OMNA_DEBUG_DUMP=<dir> writes each MASKED request body there.
_DUMP_DIR = os.environ.get("OMNA_DEBUG_DUMP")

# Hop-by-hop or connection-specific headers we never forward in either direction.
_DROP_REQ = {"host", "content-length", "connection", "keep-alive", "transfer-encoding",
             "te", "trailer", "upgrade", "proxy-connection", "accept-encoding"}
_DROP_RESP = {"content-length", "content-encoding", "connection", "keep-alive",
              "transfer-encoding", "te", "trailer", "upgrade"}


def pick_upstream(request: Request, anthropic: str, openai: str) -> str:
    h = request.headers
    p = request.url.path
    if "anthropic-version" in h or "x-api-key" in h or p.startswith("/v1/messages") or p.startswith("/api/") or p.startswith("/v1/complete"):
        return anthropic
    return openai


def create_app(
    session: MaskingSession | None = None,
    *,
    anthropic_upstream: str = config.ANTHROPIC_UPSTREAM,
    openai_upstream: str = config.OPENAI_UPSTREAM,
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
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(None, connect=30.0))
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

    async def health(_: Request) -> Response:
        ok, n, _msg = receipts.verify()
        return JSONResponse(
            {
                "ok": True,
                "plugin": __version__,
                "engine": engine_version(),
                "smart": session.smart,
                "restore_secrets": session.restore_secrets,
                "secrets_held_in_memory": session.secrets_held,
                "requests_this_run": stats["requests"],
                "distinct_secrets_this_run": len(stats["distinct_secrets"]),
                "distinct_pii_this_run": len(stats["distinct_pii"]),
                "avg_mask_ms_this_run": int(stats["mask_ms_total"] / stats["mask_ms_count"]) if stats["mask_ms_count"] else 0,
                "receipts": n,
                "chain_intact": ok,
                "registry_entries": session.registry_size,
                "doors": doors_state or {"api": True, "system": False, "deep": False},
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

    async def dashboard(_: Request) -> Response:
        from . import dashboard as dash

        d = dash.snapshot(days=7, sent_as_is=stats.get("sent_as_is", 0))
        return Response(dash.render(d), media_type="text/html; charset=utf-8")

    async def dashboard_json(_: Request) -> Response:
        from . import dashboard as dash

        return JSONResponse(dash.snapshot(days=7, sent_as_is=stats.get("sent_as_is", 0)))

    async def pac(_: Request) -> Response:
        return Response(
            (policy or Policy.load()).pac(system_port=system_port),
            media_type="application/x-ns-proxy-autoconfig",
        )

    async def relay(request: Request) -> Response:
        path = request.url.path
        if request.method == "HEAD" and path == "/api/hello":
            return Response(status_code=200)
        upstream = pick_upstream(request, anthropic_upstream, openai_upstream)
        upstream_host = urlsplit(upstream).netloc
        url = upstream.rstrip("/") + path
        if request.url.query:
            url += "?" + request.url.query

        body = await request.body()
        mstats = MaskStats()
        passthrough = False
        ctype = request.headers.get("content-type", "")
        is_inference = any(path.startswith(pfx) for pfx in INFERENCE_PREFIXES)
        if body and request.method in ("POST", "PUT", "PATCH"):
            if "json" in ctype and not request.headers.get("content-encoding"):
                out = await run_in_threadpool(pipeline.mask_bytes, body, ctype)
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
                    passthrough = True
            elif is_inference:
                _receipt(request, path, upstream_host, 400, MaskStats(), len(body), time.time(), stream=False, note="unparseable")
                return JSONResponse({"type": "error", "error": {"type": "omna_refused", "message": f"omna only forwards JSON to {path} (got content-type {ctype!r}, content-encoding {request.headers.get('content-encoding')!r}); refused rather than sent unmasked"}}, status_code=400)
            else:
                passthrough = True  # e.g. file/audio uploads: forwarded as-is, marked in the receipt

        headers = {k: v for k, v in request.headers.items() if k.lower() not in _DROP_REQ}
        headers["host"] = upstream_host
        headers["accept-encoding"] = "identity"

        t0 = time.time()
        stats["requests"] += 1
        req = client.build_request(request.method, url, headers=headers, content=body)
        try:
            resp = await client.send(req, stream=True)
        except httpx.HTTPError as e:
            _receipt(request, path, upstream_host, 502, mstats, len(body), t0, stream=False)
            return JSONResponse({"type": "error", "error": {"type": "omna_upstream_error", "message": str(e)}}, status_code=502)

        resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _DROP_RESP}
        is_sse = "text/event-stream" in resp.headers.get("content-type", "")

        if is_sse:
            async def gen():
                restorer = pipeline.sse_restorer()
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
                    _receipt(request, path, upstream_host, resp.status_code, mstats, len(body), t0, stream=True, note="passthrough" if passthrough else None)

            return StreamingResponse(gen(), status_code=resp.status_code, headers=resp_headers)

        data = await resp.aread()
        await resp.aclose()
        if resp.status_code < 400 and "json" in resp.headers.get("content-type", ""):
            try:
                data = json.dumps(pipeline.restore_json(json.loads(data)), ensure_ascii=False).encode("utf-8")
            except ValueError:
                pass
        _receipt(request, path, upstream_host, resp.status_code, mstats, len(body), t0, stream=False, note="passthrough" if passthrough else None)
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
        )

    app = Starlette(
        routes=[
            Route("/omna/health", health, methods=["GET"]),
            Route("/omna/proxy.pac", pac, methods=["GET"]),
            Route("/omna/extension-checkin", extension_checkin, methods=["POST"]),
            Route("/omna/dashboard", dashboard, methods=["GET"]),
            Route("/omna/dashboard.json", dashboard_json, methods=["GET"]),
            Route("/{path:path}", relay, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]),
        ]
    )
    app.state.session = session
    app.state.client = client
    return app
