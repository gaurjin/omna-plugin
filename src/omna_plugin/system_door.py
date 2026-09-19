"""The system door and the deep door: one mitmproxy addon in front of the mail room.

Only hostnames on the policy list are ever decrypted (mitmproxy ``allow_hosts``;
everything else is tunnelled encrypted). For those: mask the request through the
site adapter, forward with ``accept-encoding: identity`` so replies arrive
uncompressed, restore streamed / JSON / websocket replies chunk by chunk, write one
receipt. A bypassed app is tunnelled untouched and receipted as such. An app that
refuses our certificate (pinned) is receipted as ``tls-refused`` and never forwarded.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from pathlib import Path
from typing import Callable

from mitmproxy import http, tls
from mitmproxy.certs import CertStore
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from .adapters import for_host
from .adapters.base import RequestView
from .pipeline import MaskStats, Pipeline
from .policy import Policy

CA_ORG = "Omna"
CA_CN = "Omna Local Certificate Authority"
REFUSED_BODY = (b'{"type":"error","error":{"type":"omna_refused",'
                b'"message":"omna could not mask this request; refused rather than sent unmasked"}}')

# `mitmdump --mode local:...` (the deep door) extracts this Apple-signed bundle to
# /Applications on first use of `omna capture app NAME`. The bundle file itself is
# an ordinary file we can delete; the *system extension registration* it triggers
# is not — macOS refuses `systemextensionsctl uninstall` outright while System
# Integrity Protection is on (verified 2026-09-19), so only the person, by hand in
# System Settings → General → Login Items & Extensions → Network Extensions, can
# fully remove that part. It finishes disappearing on the next reboot once they do.
DEEP_REDIRECTOR_APP = Path("/Applications/Mitmproxy Redirector.app")


def remove_deep_redirector_app() -> None:
    shutil.rmtree(DEEP_REDIRECTOR_APP, ignore_errors=True)

Resolver = Callable[[tuple[str, int] | None], tuple[int, str] | None]


def ensure_ca(ca_dir: Path) -> Path:
    """Create the local CA once (private key 0600). Returns the public cert path."""
    ca_dir.mkdir(parents=True, exist_ok=True)
    ca_dir.chmod(0o700)
    if not (ca_dir / "mitmproxy-ca.pem").exists():
        CertStore.create_store(ca_dir, "mitmproxy", 2048, organization=CA_ORG, cn=CA_CN)
    (ca_dir / "mitmproxy-ca.pem").chmod(0o600)
    return ca_dir / "mitmproxy-ca-cert.pem"


def _utf8_split(buf: bytearray) -> tuple[str, bytes]:
    """Decode all complete UTF-8 characters; keep an incomplete trailing sequence for the next chunk."""
    cut = len(buf)
    back = 0
    while cut > 0 and back < 3 and (buf[cut - 1] & 0xC0) == 0x80:
        cut -= 1
        back += 1
    if cut > 0 and (buf[cut - 1] & 0xC0) == 0xC0:
        cut -= 1
    elif back:
        cut = len(buf)  # the trailing continuation bytes complete a char that already started
    return bytes(buf[:cut]).decode("utf-8", "replace"), bytes(buf[cut:])


class OmnaAddon:
    def __init__(self, pipeline: Pipeline, policy: Policy, door: str, resolver: Resolver):
        self.pipeline = pipeline
        self.policy = policy
        self.door = door
        self.resolver = resolver
        self.refusals: dict[str, int] = {}     # "App → host" -> count this run (also receipted)
        self.seen_apps: dict[str, int] = {}

    # ---------------------------------------------------------------- helpers
    async def _app_of(self, client) -> str | None:
        # self.resolver (ProcessResolver.resolve) can shell out to lsof/ps and block for
        # up to ~2.5s on a cache miss. mitmproxy runs each hook invocation as its own
        # asyncio Task (proxy/server.py's StartHook handling), so awaiting an executor
        # future here only delays THIS flow — it does not stall other connections or the
        # rest of the event loop, unlike calling self.resolver(...) directly would.
        loop = asyncio.get_running_loop()
        got = await loop.run_in_executor(None, self.resolver, getattr(client, "peername", None))
        return got[1] if got else None

    def _door_for_client(self, client) -> str:
        """Deep vs system, from a raw ``connection.Client`` (works at both TLS-clienthello
        time and HTTP-flow time: ``flow.client_conn`` and ``data.context.client`` are the
        same ``connection.Client`` object, and ``proxy_mode`` is fixed once the connection
        lands on a given listener, before TLS even starts)."""
        return "deep" if type(client.proxy_mode).__name__ == "LocalMode" else self.door

    def _door_for(self, flow: http.HTTPFlow) -> str:
        return self._door_for_client(flow.client_conn)

    def _receipt(self, flow: http.HTTPFlow, status: int, stream: bool) -> None:
        if flow.metadata.get("omna_receipted"):
            return  # already wrote one for this flow (normal completion or abort) — never double-receipt
        flow.metadata["omna_receipted"] = True
        t0 = flow.metadata.get("omna_t0") or time.time()
        self.pipeline.receipt(
            door=self._door_for(flow), route=flow.request.path.split("?")[0][:80], host=flow.request.pretty_host,
            status=status, stats=flow.metadata.get("omna_stats") or MaskStats(),
            nbytes=flow.metadata.get("omna_nbytes", 0), ms=int((time.time() - t0) * 1000),
            stream=stream, app=flow.metadata.get("omna_app"), note=flow.metadata.get("omna_note"), session_id=None)

    # ---------------------------------------------------------------- TLS
    async def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        app = await self._app_of(data.context.client)
        if self.policy.app_action(app) == "bypass":
            data.ignore_connection = True
            self.pipeline.receipt(door=self._door_for_client(data.context.client), route="CONNECT",
                                  host=data.client_hello.sni or "?", status=0,
                                  stats=MaskStats(), nbytes=0, ms=0, stream=False, app=app,
                                  note="bypassed-by-policy", session_id=None)

    async def tls_failed_client(self, data: tls.TlsData) -> None:
        app = await self._app_of(data.context.client) or "unknown app"
        host = data.context.client.sni or "?"
        key = f"{app} → {host}"
        self.refusals[key] = self.refusals.get(key, 0) + 1
        self.pipeline.receipt(door=self._door_for_client(data.context.client), route="TLS", host=host,
                              status=0, stats=MaskStats(), nbytes=0, ms=0, stream=False, app=app,
                              note="tls-refused", session_id=None)

    # ---------------------------------------------------------------- HTTP
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        flow.request.headers["accept-encoding"] = "identity"
        flow.metadata["omna_t0"] = time.time()

    async def request(self, flow: http.HTTPFlow) -> None:
        app = await self._app_of(flow.client_conn)
        if app:
            self.seen_apps[app] = self.seen_apps.get(app, 0) + 1
        adapter = for_host(flow.request.pretty_host)
        req = RequestView(host=flow.request.pretty_host, method=flow.request.method, path=flow.request.path,
                          content_type=flow.request.headers.get("content-type", ""),
                          body=flow.request.get_content() or b"", headers=dict(flow.request.headers))
        out = adapter.mask(self.pipeline, req)
        flow.metadata.update(omna_app=app, omna_adapter=adapter, omna_stats=out.stats, omna_nbytes=len(req.body),
                             omna_note="passthrough-nonprompt" if out.passthrough else None)
        if out.refused:
            # Fail closed: answer locally, never forward a body we could not mask.
            flow.metadata["omna_note"] = out.refused
            flow.metadata["omna_refused"] = True
            flow.response = http.Response.make(400, REFUSED_BODY, {"content-type": "application/json"})
            self._receipt(flow, 400, stream=False)
            return
        if out.body is not None:
            flow.request.set_content(out.body)

    def responseheaders(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.metadata.get("omna_refused"):
            return
        adapter = flow.metadata.get("omna_adapter") or for_host(flow.request.pretty_host)
        mode = adapter.response_mode(flow.response.headers.get("content-type", ""))
        if mode not in ("stream-json", "stream-text"):
            return
        restorer = self.pipeline.text_restorer(json_escape=(mode == "stream-json"))
        buf = bytearray()

        def cb(chunk: bytes) -> bytes | list[bytes]:
            if chunk == b"":
                # mitmproxy's real end-of-message signal (ResponseEndOfMessage) — genuinely
                # ends the stream, so a `bytes` return (even empty) is correct here.
                tail = restorer.feed(bytes(buf).decode("utf-8", "replace")) + restorer.flush() if buf else restorer.flush()
                self._receipt(flow, flow.response.status_code if flow.response else 0, stream=True)
                return tail.encode("utf-8")
            buf.extend(chunk)
            text, rest = _utf8_split(buf)
            buf.clear()
            buf.extend(rest)
            out = restorer.feed(text).encode("utf-8")
            # A mid-stream chunk with nothing to flush yet (partial token / partial UTF-8
            # sequence held back) MUST NOT return b"". mitmproxy's HTTP/1 writer serializes
            # a zero-length ResponseData chunk as b"0\r\n\r\n" under chunked transfer-encoding
            # — byte-identical to the real terminating chunk — which ends the client's stream
            # early and silently drops everything after it. An empty list means "nothing to
            # send yet, stream continues": http/__init__.py's state_stream_response_body just
            # iterates the returned chunks, so an empty list sends nothing and yields no
            # ResponseData event at all. (Verified against the installed mitmproxy 12.2.3
            # source: proxy/layers/http/__init__.py `state_stream_response_body`, and
            # proxy/layers/http/_http1.py `Http1Server.send`'s ResponseData branch.)
            return out if out else []

        flow.response.stream = cb
        flow.metadata["omna_streamed"] = True

    def response(self, flow: http.HTTPFlow) -> None:
        if flow.response is None or flow.metadata.get("omna_streamed") or flow.metadata.get("omna_refused"):
            return
        adapter = flow.metadata.get("omna_adapter") or for_host(flow.request.pretty_host)
        if adapter.response_mode(flow.response.headers.get("content-type", "")) == "json" and flow.response.status_code < 400:
            try:
                obj = json.loads(flow.response.get_content() or b"null")
                flow.response.set_content(json.dumps(self.pipeline.restore_json(obj), ensure_ascii=False).encode("utf-8"))
            except ValueError:
                pass
        self._receipt(flow, flow.response.status_code, stream=False)

    def error(self, flow: http.HTTPFlow) -> None:
        """Client disconnect / upstream error mid-stream: `cb`'s `chunk == b""` branch (the
        only other place a streamed response gets receipted) never runs on an abnormal
        termination, so the audit trail would otherwise get no entry at all for this
        request. `_receipt`'s own `omna_receipted` guard makes this a no-op if a receipt
        was already written (normal completion raced the abort, or vice versa)."""
        if flow.metadata.get("omna_streamed") and not flow.metadata.get("omna_receipted"):
            flow.metadata["omna_note"] = "stream-aborted"
            self._receipt(flow, flow.response.status_code if flow.response else 0, stream=True)

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        assert flow.websocket
        msg = flow.websocket.messages[-1]
        if not msg.is_text:
            return
        if msg.from_client:
            masked, stats = self.pipeline.mask_text(msg.text)
            msg.content = masked.encode("utf-8")
            st: MaskStats = flow.metadata.setdefault("omna_stats", MaskStats())
            for k, v in stats.counts.items():
                st.counts[k] = st.counts.get(k, 0) + v
            st.secrets += stats.secrets
            st.pii += stats.pii
        else:
            msg.content = self.pipeline.restore_text(msg.text).encode("utf-8")


def build_master(policy: Policy, addon: OmnaAddon, *, port: int, ca_dir: Path,
                 upstream_ca: str | None = None, deep_apps: list[str] | None = None) -> DumpMaster:
    ensure_ca(ca_dir)
    modes = [f"regular@{port}"]
    if deep_apps:
        modes.append("local:" + ",".join(deep_apps))
    opts = Options(listen_host="127.0.0.1", mode=modes, confdir=str(ca_dir),
                   allow_hosts=policy.allow_hosts(), websocket=True, http2=True)
    if upstream_ca:
        opts.update(ssl_verify_upstream_trusted_ca=upstream_ca)
    master = DumpMaster(opts, loop=asyncio.get_running_loop(), with_termlog=False, with_dumper=False)
    # Registered by the proxyserver addon, so it can only be set once the addons are loaded.
    master.options.update(store_streamed_bodies=False)
    master.addons.add(addon)
    return master
