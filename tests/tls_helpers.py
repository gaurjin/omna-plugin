"""A throwaway CA + a leaf cert for 127.0.0.1, and a tiny HTTPS server that speaks
enough HTTP/1.1 to echo the request body it received and stream a canned SSE reply."""
from __future__ import annotations

import asyncio
import datetime as dt
import ipaddress
import ssl
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


def make_ca_and_leaf(tmp: Path) -> tuple[Path, Path, Path]:
    ca_key = rsa.generate_private_key(65537, 2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "omna-test-ca")])
    now = dt.datetime.now(dt.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
          .not_valid_after(now + dt.timedelta(days=30))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf_key = rsa.generate_private_key(65537, 2048)
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")]))
            .issuer_name(ca_name).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_pem = tmp / "test-ca.pem"
    ca_pem.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf_pem = tmp / "leaf.pem"
    leaf_pem.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    leaf_keyf = tmp / "leaf-key.pem"
    leaf_keyf.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    return ca_pem, leaf_pem, leaf_keyf


# The canned SSE reply: a known token split across two chunks (the hold-back case),
# plus an unknown token that must pass through untouched.
SSE_FRAMES = (
    b'data: {"delta":"Hello [PER',
    b'SON_1], your mail [EMAIL_' b'1] is set"}\n\n',
    b"data: [DONE]\n\n",
)


class FakeUpstream:
    """Records the last request; replies with SSE if the path ends in /stream, else a JSON echo."""

    def __init__(self):
        self.last_body: bytes | None = None
        self.last_headers: dict[str, str] = {}
        self.port = 0
        self._srv = None

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        head = await r.readuntil(b"\r\n\r\n")
        lines = head.decode().split("\r\n")
        _method, path, _ = lines[0].split(" ", 2)
        hdrs = {k.lower(): v for k, v in (l.split(": ", 1) for l in lines[1:] if ": " in l)}
        self.last_headers = hdrs
        n = int(hdrs.get("content-length", "0"))
        self.last_body = await r.readexactly(n) if n else b""
        if path.endswith("/stream"):
            w.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\ntransfer-encoding: chunked\r\n\r\n")
            for frame in SSE_FRAMES:
                w.write(f"{len(frame):x}\r\n".encode() + frame + b"\r\n")
                await w.drain()
                await asyncio.sleep(0.01)
            w.write(b"0\r\n\r\n")
        else:
            body = b'{"echo": ' + (self.last_body or b"null") + b', "reply": "hi [EMAIL_' b'1]"}'
            w.write(b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
        await w.drain()
        w.close()

    async def start(self, leaf_pem: Path, leaf_key: Path):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(leaf_pem), str(leaf_key))
        self._srv = await asyncio.start_server(self._handle, "127.0.0.1", 0, ssl=ctx)
        self.port = self._srv.sockets[0].getsockname()[1]

    async def stop(self):
        self._srv.close()
        await self._srv.wait_closed()
