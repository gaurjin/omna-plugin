"""The far side of a WebSocket the API door relays: a small client.

Codex (0.169, recorded live 2026-11-16) opens a WebSocket to its base URL's
``/v1/responses`` before every session and only falls back to HTTPS after
seven refused tries — about eight seconds, every time it starts. The API door
now takes that WebSocket (proxy.py) and this module holds the connection to
the provider. ``wsproto`` does the protocol; it is already what the system
door's proxy uses. No compression is offered: every message is opened and
masked here anyway.
"""

from __future__ import annotations

import asyncio
import ssl
from collections import deque
from urllib.parse import urlsplit

from wsproto import ConnectionType, WSConnection
from wsproto.connection import ConnectionState
from wsproto.events import (AcceptConnection, BytesMessage, CloseConnection, Ping, RejectConnection, RejectData,
                            Request, TextMessage)
from wsproto.utilities import LocalProtocolError

# Never forwarded: the connection's own headers (wsproto writes fresh ones)
# and the page that opened the socket.
_DROP = frozenset({"host", "connection", "upgrade", "sec-websocket-key", "sec-websocket-version",
                   "sec-websocket-extensions", "sec-websocket-accept", "sec-websocket-protocol",
                   "content-length", "transfer-encoding", "keep-alive", "te", "trailer",
                   "proxy-connection", "accept-encoding", "origin"})
# One message may not grow past this (a turn with a long chat is a few MB).
MAX_MESSAGE = 64 * 1024 * 1024


class UpstreamRefused(Exception):
    """The provider did not accept the WebSocket (``status`` is its answer)."""

    def __init__(self, status: int):
        super().__init__(f"upstream refused the WebSocket ({status})")
        self.status = status


def tls_context(verify) -> ssl.SSLContext:
    """httpx's ``verify=`` value (upstream_tls.ssl_context) as an SSLContext."""
    if isinstance(verify, ssl.SSLContext):
        return verify
    if isinstance(verify, str):
        return ssl.create_default_context(cafile=verify)
    return ssl.create_default_context()


class UpstreamSocket:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, ws: WSConnection):
        self._r, self._w, self._ws = reader, writer, ws
        self._ready: deque = deque()       # complete messages (str / bytes), None = closed
        self._part: list = []
        self._size = 0
        self.headers: list[tuple[str, str]] = []
        self.subprotocol: str | None = None

    @classmethod
    async def open(cls, url: str, headers: dict[str, str], verify=True, subprotocols: list[str] | None = None,
                   timeout: float = 30.0) -> "UpstreamSocket":
        u = urlsplit(url)
        secure = u.scheme in ("wss", "https")
        port = u.port or (443 if secure else 80)
        reader, writer = await asyncio.wait_for(asyncio.open_connection(
            u.hostname, port, ssl=tls_context(verify) if secure else None,
            server_hostname=u.hostname if secure else None), timeout)
        self = cls(reader, writer, WSConnection(ConnectionType.CLIENT))
        try:
            target = (u.path or "/") + ("?" + u.query if u.query else "")
            extra = [(k.encode("latin-1"), v.encode("latin-1")) for k, v in headers.items() if k.lower() not in _DROP]
            await self._write(self._ws.send(Request(host=u.netloc, target=target, extra_headers=extra,
                                                    subprotocols=list(subprotocols or []))))
            await asyncio.wait_for(self._handshake(), timeout)
        except BaseException:
            writer.close()
            raise
        return self

    async def _write(self, data: bytes) -> None:
        if data:
            self._w.write(data)
            await self._w.drain()

    async def _handshake(self) -> None:
        while True:
            data = await self._r.read(65536)
            if not data:
                raise UpstreamRefused(502)
            self._ws.receive_data(data)
            done = False
            for ev in self._ws.events():
                if isinstance(ev, AcceptConnection):
                    self.headers = [(k.decode("latin-1"), v.decode("latin-1")) for k, v in ev.extra_headers]
                    self.subprotocol = ev.subprotocol
                    done = True
                elif isinstance(ev, RejectConnection):
                    raise UpstreamRefused(ev.status_code)
                elif isinstance(ev, RejectData):
                    continue
                elif done:
                    await self._take(ev)       # a message that arrived with the handshake
            if done:
                return

    async def _take(self, ev) -> None:
        if isinstance(ev, (TextMessage, BytesMessage)):
            self._size += len(ev.data)
            if self._size > MAX_MESSAGE:
                raise UpstreamRefused(1009)
            self._part.append(ev.data)
            if ev.message_finished:
                joined = "".join(self._part) if isinstance(ev, TextMessage) else b"".join(self._part)
                self._part, self._size = [], 0
                self._ready.append(joined)
        elif isinstance(ev, Ping):
            await self._write(self._ws.send(ev.response()))
        elif isinstance(ev, CloseConnection):
            try:
                await self._write(self._ws.send(ev.response()))
            except (LocalProtocolError, OSError):
                pass
            self._ready.append(None)

    async def recv(self) -> str | bytes | None:
        """The next whole message, or None once the provider has closed."""
        while not self._ready:
            data = await self._r.read(65536)
            if not data:
                return None
            self._ws.receive_data(data)
            for ev in self._ws.events():
                await self._take(ev)
        return self._ready.popleft()

    async def send(self, text: str) -> None:
        await self._write(self._ws.send(TextMessage(data=text)))

    async def close(self, code: int = 1000) -> None:
        try:
            if self._ws.state is ConnectionState.OPEN:
                await self._write(self._ws.send(CloseConnection(code=code)))
        except (LocalProtocolError, OSError):
            pass
        finally:
            self._w.close()
