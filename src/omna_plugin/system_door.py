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
    def _app_of(self, client) -> str | None:
        got = self.resolver(getattr(client, "peername", None))
        return got[1] if got else None

    def _door_for(self, flow: http.HTTPFlow) -> str:
        mode = flow.client_conn.proxy_mode
        return "deep" if type(mode).__name__ == "LocalMode" else self.door

    def _receipt(self, flow: http.HTTPFlow, status: int, stream: bool) -> None:
        t0 = flow.metadata.get("omna_t0") or time.time()
        self.pipeline.receipt(
            door=self._door_for(flow), route=flow.request.path.split("?")[0][:80], host=flow.request.pretty_host,
            status=status, stats=flow.metadata.get("omna_stats") or MaskStats(),
            nbytes=flow.metadata.get("omna_nbytes", 0), ms=int((time.time() - t0) * 1000),
            stream=stream, app=flow.metadata.get("omna_app"), note=flow.metadata.get("omna_note"), session_id=None)

    # ---------------------------------------------------------------- TLS
    def tls_clienthello(self, data: tls.ClientHelloData) -> None:
        app = self._app_of(data.context.client)
        if self.policy.app_action(app) == "bypass":
            data.ignore_connection = True
            self.pipeline.receipt(door=self.door, route="CONNECT", host=data.client_hello.sni or "?", status=0,
                                  stats=MaskStats(), nbytes=0, ms=0, stream=False, app=app,
                                  note="bypassed-by-policy", session_id=None)

    def tls_failed_client(self, data: tls.TlsData) -> None:
        app = self._app_of(data.context.client) or "unknown app"
        host = data.context.client.sni or "?"
        key = f"{app} → {host}"
        self.refusals[key] = self.refusals.get(key, 0) + 1
        self.pipeline.receipt(door=self.door, route="TLS", host=host, status=0, stats=MaskStats(),
                              nbytes=0, ms=0, stream=False, app=app, note="tls-refused", session_id=None)

    # ---------------------------------------------------------------- HTTP
    def requestheaders(self, flow: http.HTTPFlow) -> None:
        flow.request.headers["accept-encoding"] = "identity"
        flow.metadata["omna_t0"] = time.time()

    def request(self, flow: http.HTTPFlow) -> None:
        app = self._app_of(flow.client_conn)
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

        def cb(chunk: bytes) -> bytes:
            if chunk == b"":
                tail = restorer.feed(bytes(buf).decode("utf-8", "replace")) + restorer.flush() if buf else restorer.flush()
                self._receipt(flow, flow.response.status_code if flow.response else 0, stream=True)
                return tail.encode("utf-8")
            buf.extend(chunk)
            text, rest = _utf8_split(buf)
            buf.clear()
            buf.extend(rest)
            return restorer.feed(text).encode("utf-8")

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
