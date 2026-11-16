"""Read the channel Google's Gemini website sends a message through, and the
replies that come back on it.

Why: found live 2026-11-16 — gemini.google.com no longer posts the message to
its own address. It opens a channel to ``geminiweb-pa.clients6.google.com
/v1/processSession`` and sends the message there as a form whose values are
the packed binary format (``protobuf.py``) written in base64. Until then that
address was not on Omna's list (the message went out unmasked), and once it
was listed the fast rules damaged the base64 and Google refused the message
("Unable to base64-decode request data").

The format, both ways:

* going out — a form: ``count=2&ofs=0&req0___data__=<base64>&req1___data__=…``.
  Only the ``req<N>___data__`` values are opened; every other pair is the
  channel's own counter and is copied byte for byte.
* coming back — pieces, each ``<length>\\n<JSON>``, the JSON being
  ``[[<number>, ["<base64>"]], …]``. The length counts the JSON's characters,
  so it is written again whenever a value inside changed.

This module only opens and closes the wrapping; what happens to the text
inside is the caller's ``rewrite`` (packed bytes in, packed bytes out, None
when they cannot be read).
"""

from __future__ import annotations

import base64
import binascii
import json
import re
from typing import Callable
from urllib.parse import quote, unquote_to_bytes

Rewrite = Callable[[bytes], "bytes | None"]

# Recorded: ``req<N>___data__``. Any other ``req<N>_…`` pair is read the same
# way — and refused when it cannot be — so a renamed value is never sent unread.
_DATA_KEY = re.compile(rb"^req\d+_")
_MAX_LENGTH_DIGITS = 9


def _b64decode(text: bytes) -> bytes | None:
    try:
        return base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return None


def rewrite_form(body: bytes, rewrite: Rewrite) -> bytes | None:
    """The form with every ``req<N>___data__`` value passed through
    ``rewrite``. The very same object when nothing changed; None when a data
    value cannot be read (the caller must not send it as if it had been)."""
    pairs = body.split(b"&")
    changed = False
    for i, pair in enumerate(pairs):
        key, eq, value = pair.partition(b"=")
        if not eq or not _DATA_KEY.match(key):
            continue
        packed = _b64decode(unquote_to_bytes(value))
        if packed is None:
            return None
        if not packed:
            continue
        new = rewrite(packed)
        if new is None:
            return None
        if new is packed or new == packed:
            continue
        pairs[i] = key + b"=" + quote(base64.b64encode(new), safe="").encode("ascii")
        changed = True
    return b"&".join(pairs) if changed else body


def _rewrite_piece(text: str, rewrite: Rewrite) -> str | None:
    """One piece's JSON with its base64 values rewritten, or None for "send
    it as it came" (nothing changed, or not the shape described above)."""
    try:
        obj = json.loads(text)
    except ValueError:
        return None
    if not isinstance(obj, list):
        return None
    changed = False
    for item in obj:
        if not (isinstance(item, list) and len(item) == 2 and isinstance(item[1], list)):
            continue
        for j, value in enumerate(item[1]):
            if not isinstance(value, str) or len(value) < 8:
                continue
            packed = _b64decode(value.encode("ascii", "ignore")) if value.isascii() else None
            if not packed:
                continue
            new = rewrite(packed)
            if new is None or new is packed or new == packed:
                continue
            item[1][j] = base64.b64encode(new).decode("ascii")
            changed = True
    if not changed:
        return None
    tail = text[len(text.rstrip()):]            # a piece can end in a line break that its length counts
    return json.dumps(obj, ensure_ascii=False, separators=(",", ":")) + tail


class ReplyReader:
    """The channel's replies, as they stream in: pieces of any size go in,
    whole ``<length>\\n<JSON>`` pieces come out with their values rewritten
    (real values put back). Anything that is not this shape — and everything
    after it — is sent on exactly as it came: a reply is never held back or
    broken."""

    def __init__(self, rewrite: Rewrite):
        self._rewrite = rewrite
        self._buf = bytearray()
        self._as_is = False

    def _give_up(self) -> bytes:
        self._as_is = True
        rest = bytes(self._buf)
        self._buf.clear()
        return rest

    def feed(self, chunk: bytes) -> bytes:
        if self._as_is:
            return chunk
        self._buf.extend(chunk)
        out = []
        while self._buf:
            nl = self._buf.find(b"\n")
            head = bytes(self._buf[:nl if nl >= 0 else len(self._buf)])
            if not head.isdigit() or len(head) > _MAX_LENGTH_DIGITS:
                out.append(self._give_up())
                break
            if nl < 0:
                break                           # the length itself is still arriving
            size = int(head)
            piece = bytes(self._buf[nl + 1:nl + 1 + size])
            if len(piece) < size:
                break
            if not piece.isascii():
                # The length counts characters, not bytes; Google's pieces are
                # plain ASCII (base64 inside JSON). One that is not is some
                # other shape — stop reading rather than cut it in the wrong place.
                out.append(self._give_up())
                break
            del self._buf[:nl + 1 + size]
            try:
                new = _rewrite_piece(piece.decode("ascii"), self._rewrite)
            except Exception:  # noqa: BLE001 — the person's reply must arrive
                new = None
            if new is None:
                out.append(head + b"\n" + piece)
            else:
                raw = new.encode("utf-8")
                out.append(str(len(new)).encode("ascii") + b"\n" + raw)
        return b"".join(out)

    def flush(self) -> bytes:
        rest = bytes(self._buf)
        self._buf.clear()
        return rest
