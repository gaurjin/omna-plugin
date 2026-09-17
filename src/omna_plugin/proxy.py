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
import time
from urllib.parse import urlsplit

import httpx
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from . import config, receipts
from .body import mask_body, restore_body
from .engine import MaskingSession, engine_version
from .stream import StreamRestorer

__version__ = "0.1.0"

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
) -> Starlette:
    session = session or MaskingSession()
    client = client or httpx.AsyncClient(timeout=httpx.Timeout(None, connect=30.0))
    stats = {"requests": 0, "started": time.time()}

    async def health(_: Request) -> Response:
        ok, n, _msg = receipts.verify()
        return JSONResponse(
            {
                "ok": True,
                "plugin": __version__,
                "engine": engine_version(),
                "smart": session.smart,
                "requests_this_run": stats["requests"],
                "receipts": n,
                "chain_intact": ok,
                "registry_entries": session.registry_size,
            }
        )

    async def relay(request: Request) -> Response:
        path = request.url.path
        if request.method == "HEAD" and path == "/api/hello":
            return Response(status_code=200)
        upstream = pick_upstream(request, anthropic_upstream, openai_upstream)
        url = upstream.rstrip("/") + path
        if request.url.query:
            url += "?" + request.url.query

        body = await request.body()
        counts: dict[str, int] = {}
        ctype = request.headers.get("content-type", "")
        if body and "json" in ctype:
            try:
                obj = json.loads(body)
            except ValueError:
                obj = None
            if obj is not None:
                masked, counts = mask_body(session, obj)
                body = json.dumps(masked, ensure_ascii=False).encode("utf-8")

        headers = {k: v for k, v in request.headers.items() if k.lower() not in _DROP_REQ}
        headers["host"] = urlsplit(upstream).netloc
        headers["accept-encoding"] = "identity"

        t0 = time.time()
        stats["requests"] += 1
        req = client.build_request(request.method, url, headers=headers, content=body)
        try:
            resp = await client.send(req, stream=True)
        except httpx.HTTPError as e:
            _receipt(request, path, upstream, 502, counts, len(body), t0, stream=False)
            return JSONResponse({"type": "error", "error": {"type": "omna_upstream_error", "message": str(e)}}, status_code=502)

        resp_headers = {k: v for k, v in resp.headers.items() if k.lower() not in _DROP_RESP}
        is_sse = "text/event-stream" in resp.headers.get("content-type", "")

        if is_sse:
            async def gen():
                restorer = StreamRestorer(session)
                try:
                    async for chunk in resp.aiter_raw():
                        out = restorer.feed(chunk)
                        if out:
                            yield out
                    tail = restorer.flush()
                    if tail:
                        yield tail
                finally:
                    await resp.aclose()
                    _receipt(request, path, upstream, resp.status_code, counts, len(body), t0, stream=True)

            return StreamingResponse(gen(), status_code=resp.status_code, headers=resp_headers)

        data = await resp.aread()
        await resp.aclose()
        if resp.status_code < 400 and "json" in resp.headers.get("content-type", ""):
            try:
                data = json.dumps(restore_body(session, json.loads(data)), ensure_ascii=False).encode("utf-8")
            except ValueError:
                pass
        _receipt(request, path, upstream, resp.status_code, counts, len(body), t0, stream=False)
        return Response(data, status_code=resp.status_code, headers=resp_headers)

    def _receipt(request: Request, path: str, upstream: str, status: int, counts: dict, nbytes: int, t0: float, stream: bool):
        rec = {
            "route": path,
            "upstream": urlsplit(upstream).netloc,
            "status": status,
            "stream": stream,
            "masked": counts,
            "bytes_in": nbytes,
            "ms": int((time.time() - t0) * 1000),
        }
        sid = request.headers.get("x-claude-code-session-id")
        if sid:
            rec["session"] = sid
        try:
            receipts.append(rec)
        except OSError:
            pass

    app = Starlette(
        routes=[
            Route("/omna/health", health, methods=["GET"]),
            Route("/{path:path}", relay, methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"]),
        ]
    )
    app.state.session = session
    app.state.client = client
    return app


def run(port: int = config.DEFAULT_PORT, smart: bool = False, log_level: str = "warning") -> None:
    """Start the proxy in the foreground (``omna start``)."""
    import uvicorn

    session = MaskingSession(smart=smart)
    if smart:
        import omna_pii_mask

        print("omna: preparing the on-device Contextual model (first run downloads ~809 MB)...", flush=True)
        omna_pii_mask.download_model()
    app = create_app(session)
    print(f"omna: masking proxy on {config.base_url(port)}  (engine {engine_version()}, smart={'on' if smart else 'off'})", flush=True)
    uvicorn.run(app, host=config.DEFAULT_HOST, port=port, log_level=log_level, access_log=False)
