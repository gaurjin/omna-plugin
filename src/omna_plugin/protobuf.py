"""Read a request body in the packed binary format (protobuf) without its
schema, hand every piece of text in it to a masker, and write it back with
every length around a changed text corrected.

Why: the Claude desktop app 5.x sends the person's message this way
(``application/proto`` to ``/claudeai-rpc/…``; found live 2026-11-15 — until
then the message went out unmasked and the reply channel was refused).

The format, in one paragraph: a body is a run of fields; each starts with a
number that names the field and says how its value is stored — a plain number
(0), 8 raw bytes (1), 4 raw bytes (5), or "a length, then that many bytes"
(2). Only the last kind can hold text; it also holds nested bodies and raw
bytes (signatures, hashes), and nothing in the bytes says which. So each such
value is tried as a nested body first, then as text; raw bytes are neither
and are never touched. Whatever was not changed is copied byte for byte.
"""

from __future__ import annotations

import re

import gzip
import struct
from typing import Callable

Visit = Callable[[str], str]

_MAX_DEPTH = 48


def _varint(data: bytes, i: int) -> tuple[int, int]:
    value = shift = 0
    for n in range(10):
        if i >= len(data):
            raise ValueError("cut short")
        b = data[i]
        i += 1
        value |= (b & 0x7F) << shift
        if not b & 0x80:
            return value, i
        shift += 7
    raise ValueError("number too long")


def _encode_varint(n: int) -> bytes:
    out = bytearray()
    while True:
        b, n = n & 0x7F, n >> 7
        out.append(b | (0x80 if n else 0))
        if not n:
            return bytes(out)


def _fields(data: bytes) -> list[tuple[int, int, int, int]] | None:
    """Every field as (tag start, kind, value start, value end), or None when
    the bytes are not a body in this format."""
    out, i, n = [], 0, len(data)
    try:
        while i < n:
            start = i
            tag, i = _varint(data, i)
            number, kind = tag >> 3, tag & 7
            if number < 1:
                return None
            if kind == 0:
                v0 = i
                _, i = _varint(data, i)
            elif kind == 1:
                v0, i = i, i + 8
            elif kind == 5:
                v0, i = i, i + 4
            elif kind == 2:
                size, v0 = _varint(data, i)
                i = v0 + size
            else:
                return None            # groups (3, 4) are long retired; 6 and 7 never existed
            if i > n:
                return None
            out.append((start, kind, v0, i))
    except ValueError:
        return None
    return out


def _text(raw: bytes) -> str | None:
    """The bytes as text a person could have written, or None: strict UTF-8
    and no control characters but tab and line breaks."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if any((ch < " " and ch not in "\t\n\r") or ch == "\x7f" for ch in s):
        return None
    return s


_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]+")


def _mask_around_controls(raw: bytes, visit: Visit) -> bytes | None:
    """Readable UTF-8 that holds a control character (a pasted log with
    colour codes, a form-feed page break) was copied out unread: a real key or
    email in it reached the provider (security review 2026-11-16). The text
    between the control characters is masked; the control characters stay.
    None when nothing changed or the bytes are not UTF-8 (raw bytes are never
    touched)."""
    try:
        s = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    pieces = _CONTROLS.split(s)
    if not any(p.strip() for p in pieces):
        return None
    controls = _CONTROLS.findall(s)
    out = []
    for i, piece in enumerate(pieces):
        out.append(visit(piece) if piece.strip() else piece)
        if i < len(controls):
            out.append(controls[i])
    joined = "".join(out)
    return None if joined == s else joined.encode("utf-8")


def _rewrite(data: bytes, visit: Visit, depth: int) -> bytes | None:
    fields = _fields(data)
    if fields is None:
        return None
    out: list[bytes] = []
    copied = 0                       # everything before this index is already in ``out``
    for start, kind, v0, v1 in fields:
        if kind != 2 or v1 == v0:
            continue
        value = data[v0:v1]
        new = None
        nested = _rewrite(value, visit, depth + 1) if depth < _MAX_DEPTH else None
        if nested is not None and nested != value:
            new = nested
        else:
            text = _text(value)
            if text is not None:
                masked = visit(text)
                if masked != text:
                    new = masked.encode("utf-8")
            else:
                masked = _mask_around_controls(value, visit)
                if masked is not None:
                    new = masked
        if new is None:
            continue
        tag_end = start
        _, tag_end = _varint(data, start)
        out.append(data[copied:tag_end])
        out.append(_encode_varint(len(new)))
        out.append(new)
        copied = v1
    if not out:
        return data
    out.append(data[copied:])
    return b"".join(out)


def rewrite(data: bytes, visit: Visit) -> bytes | None:
    """``data`` with every text in it passed through ``visit``. The very same
    object when nothing changed; None when ``data`` is not in this format
    (the caller must not send it as if it had been read)."""
    if not data:
        return None
    return _rewrite(data, visit, 0)


_COMPRESSED, _END_OF_STREAM = 0x01, 0x02

# The content types of this format, plain or framed as a stream.
_PACKED = ("application/proto", "application/x-protobuf", "application/protobuf", "application/connect+proto",
           "application/grpc-web+proto", "application/grpc-web", "application/grpc+proto", "application/grpc")


def is_packed(content_type: str) -> bool:
    return (content_type or "").lower().split(";")[0].strip() in _PACKED


def is_framed(content_type: str) -> bool:
    ct = (content_type or "").lower()
    return "connect+proto" in ct or "grpc" in ct


def _frame(flags: int, body: bytes, visit: Visit) -> bytes | None:
    """One frame's replacement, the empty bytes for "send it as it came", or
    None when the frame cannot be read. A compressed frame is opened (gzip)
    and packed again; the end-of-stream frame is the transport's own note."""
    if flags & _END_OF_STREAM or not body:
        return b""
    if flags & _COMPRESSED:
        try:
            plain = gzip.decompress(body)
        except (OSError, EOFError, ValueError):
            return None
    else:
        plain = body
    new = rewrite(plain, visit)
    if new is None:
        return None
    if new is plain or new == plain:
        return b""
    packed = gzip.compress(new) if flags & _COMPRESSED else new
    return bytes([flags]) + struct.pack(">I", len(packed)) + packed


def rewrite_frames(data: bytes, visit: Visit) -> bytes | None:
    """The same for a framed stream (``application/connect+proto``, gRPC-web):
    each frame is one flag byte, a 4-byte length, then a body. None when the
    frames do not add up or a frame cannot be read."""
    if not data:
        return None
    out, i, changed = [], 0, False
    while i < len(data):
        if i + 5 > len(data):
            return None
        flags, size = data[i], struct.unpack(">I", data[i + 1:i + 5])[0]
        body = data[i + 5:i + 5 + size]
        if len(body) != size:
            return None
        new = _frame(flags, body, visit)
        if new is None:
            return None
        changed = changed or bool(new)
        out.append(new or data[i:i + 5 + size])
        i += 5 + size
    return b"".join(out) if changed else data


class FrameReader:
    """A framed REPLY, as it streams in: pieces of any size go in, whole
    frames come out with their text passed through ``visit`` (real values put
    back). A frame that cannot be read is sent on exactly as it came — a
    reply is never held back or broken."""

    def __init__(self, visit: Visit):
        self._visit = visit
        self._buf = bytearray()

    def feed(self, chunk: bytes) -> bytes:
        self._buf.extend(chunk)
        out = []
        while len(self._buf) >= 5:
            size = struct.unpack(">I", bytes(self._buf[1:5]))[0]
            if len(self._buf) < 5 + size:
                break
            frame = bytes(self._buf[:5 + size])
            del self._buf[:5 + size]
            try:
                new = _frame(frame[0], frame[5:], self._visit)
            except Exception:  # noqa: BLE001 — the person's reply must arrive
                new = None
            out.append(new or frame)
        return b"".join(out)

    def flush(self) -> bytes:
        rest = bytes(self._buf)
        self._buf.clear()
        return rest
