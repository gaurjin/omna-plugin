"""Values written in a disguise: one character at a time, backwards, as hex.

Found 2026-11-15 (Claude Code 2.1.325 through the curl command 0.6.21): the
agent saw an email's stand-in in a file, decided something was hiding it, and read
the file again with ``od -c`` — one character at a time::

    0000000   C   U   S   T   O   M   E   R   _   E   M   A   I   L   =   j
    0000020   a   n   e   .   d   o   e   @   e   x   a   m   p   l   e   .

Masking reads words, so ``j a n e . d o e @ …`` was not an email, and the
real email and password went to the AI. An agent can be talked into the same
thing by a poisoned file. Two steps close it:

1. **Learn.** Text that looks like a character dump or a hex dump is turned
   back into plain text and masked (``views``), so whatever it hides becomes a
   value Omna knows.
2. **Find.** Every value Omna knows is looked for in the text in each
   disguise — spread out (spaces, line breaks, dump offsets between its
   characters), backwards, as hex, web-encoded — and replaced by its stand-in
   (``find``).

What this does NOT catch: a disguise Omna has no reader for (a cipher, a
value split by the agent's own code in some other way), base64 shorter than
the blob size ``body.py`` already opens, and ``od -x`` (bytes printed in
swapped pairs: the values it hides are learned, but that form is not
rewritten). That limit is stated in the
README, not hidden.
"""

from __future__ import annotations

import binascii
import functools
import re
from urllib.parse import quote

MIN_LEN = 6   # shorter values ("Ann", "212") would match by chance

# Between two characters of a spread-out value: spaces, a line break, and the
# offset a dump prints at the start of each line ("0000020", "00000010:").
# The gap is required: a value written normally is the masking engine's
# business, and it may have been left on purpose (``omna allow``, a category
# switched off).
_SEP = r"(?:[ \t]*\r?\n[ \t]*(?:[0-9a-fA-F]{6,8}:?)?[ \t]*|[ \t]+)"
# Between two hex pairs of a hex dump: the same, plus the text column xxd and
# hexdump -C print at the end of each line ("  # Settings for t", "|he bil|").
_HEX_SEP = r"(?:[ \t]*(?:(?:[ \t]{2}[^\n]{1,24})?\r?\n[ \t]*(?:[0-9a-fA-F]{6,8}:?)?)?[ \t]*)"
_OFFSET_LINE = re.compile(r"(?m)^[0-9a-fA-F]{6,8}:?")
_WS = re.compile(r"\s+")

# A character dump: most whitespace-separated items are single characters
# (od -c prints "\n" for a line break, so two-character escapes count too).
_ITEM = re.compile(r"\S+")
_ESCAPES = {"\\n": "\n", "\\t": "\t", "\\r": "\r", "\\0": ""}
# A hex dump line: an offset, then groups of hex digits (xxd, od -x, hexdump).
_ROW = re.compile(r"[ \t]*[0-9a-fA-F]{6,8}:?((?:[ \t]+[0-9a-fA-F]{2,8})+)")
_HEX_LINE = re.compile(r"(?m)^(?:[0-9a-fA-F]{6,8}:?)?((?:[ \t]+[0-9a-fA-F]{2,8}){4,})")


# Cheap gates, run before any per-value search. Ordinary prose and code have
# neither, so the slow searches only run on a dump (speed check 2026-11-15:
# 600 known values against a 73 KB Claude Code request took seconds without
# them).
_SPREAD_GATE = re.compile(r"(?<!\S)\S(?:" + _SEP + r"\S(?!\S)){5}")


def _char_dump(text: str) -> str | None:
    body = _OFFSET_LINE.sub("", text)
    items = _ITEM.findall(body)
    if len(items) < 24:
        return None
    single = sum(1 for it in items if len(it) == 1 or it in _ESCAPES)
    if single < 0.8 * len(items):
        return None
    # od -c marks a space with a wider gap: three or more spaces between two
    # items where one character sits in four columns. Keep it as one space.
    out = []
    for line in body.splitlines():
        for gap, item in re.findall(r"([ \t]*)(\S+)", line):
            if len(gap) >= 7:
                out.append(" ")
            out.append(_ESCAPES.get(item, item if len(item) == 1 else " " + item + " "))
    return "".join(out)


def _hex_dump(text: str) -> str | None:
    rows = []
    for line in text.splitlines():
        m = _ROW.match(line)
        if not m:
            continue
        digits = ""
        for g in m.group(1).split():          # at most 16 bytes a line: the
            if len(digits) + len(g) > 32:     # text column is never read as hex
                break
            digits += g
        if digits:
            rows.append((m.group(1), digits))
    if sum(1 for _, d in rows if len(d) >= 8) < 2:
        return None
    digits = "".join(d for _, d in rows)
    if len(digits) % 2:
        digits = digits[:-1]
    try:
        raw = binascii.unhexlify(digits)
    except (binascii.Error, ValueError):
        return None
    # od -x and plain hexdump print 2-byte words in this Mac's (little-endian)
    # order: 4-digit groups and no ":" after the offset. xxd also prints
    # 4-digit groups, but in file order, with "offset:".
    words = all(len(g) == 4 for r, _ in rows for g in r.split()[:8])
    if words and not re.search(r"(?m)^[0-9a-fA-F]{6,8}:", text):
        raw = b"".join(raw[i:i + 2][::-1] for i in range(0, len(raw), 2))
    return raw.decode("utf-8", "ignore")


# One line of a hex dump (xxd, hexdump -C, od -x, hexdump): an offset, groups
# of hex digits, maybe the text column. The last line may hold only an offset.
_DUMP_LINE = re.compile(r"[0-9a-fA-F]{6,8}:?(?:[ \t]+[0-9a-fA-F]{2,8})+(?:[ \t]{2,}[^\n]*)?[ \t]*|[0-9a-fA-F]{6,8}:?[ \t]*")
_HEX_GROUP = re.compile(r"[ \t][0-9a-fA-F]{2,8}(?=[ \t]|$)")
NOTE = "(Omna: this hex dump held private values, so it is shown as its text, masked.)\n"


def dump_blocks(text: str) -> list[tuple[int, int]]:
    """Where hex dumps sit in ``text``: runs of dump lines, at least two of
    them full (four groups or more)."""
    blocks, run, full, pos = [], None, 0, 0
    for line in text.splitlines(keepends=True):
        body = line.rstrip("\r\n")
        if _DUMP_LINE.fullmatch(body):
            if run is None:
                run, full = [pos, pos + len(line)], 0
            run[1] = pos + len(line)
            full += len(_HEX_GROUP.findall(body)) >= 4
        else:
            if run is not None and full >= 2:
                blocks.append(tuple(run))
            run = None
        pos += len(line)
    if run is not None and full >= 2:
        blocks.append(tuple(run))
    return blocks


def rewrite_dumps(text: str, mask) -> tuple[str, list]:
    """Each hex dump that hides a private value becomes its own text, masked.

    A hex dump repeats the bytes as text in a side column, cut every 16 bytes,
    so a value shows there in pieces no search can name, and the masking
    engine reads runs of hex digits as bank and phone numbers (2026-11-15,
    live: xxd and hexdump -C of config.txt). The decoded text is masked
    whole instead. A dump with nothing private is left exactly as it is.
    ``mask(text)`` returns a MaskResult; the results used are returned."""
    used = []
    for start, end in reversed(dump_blocks(text)):
        plain = _hex_dump(text[start:end])
        if not plain or not plain.strip():
            continue
        r = mask(plain)
        if r.masked == plain:
            continue
        used.append(r)
        tail = "\n" if text[start:end].endswith("\n") else ""
        text = text[:start] + NOTE + r.masked.rstrip("\n") + tail + text[end:]
    return text, used


def views(text: str) -> list[str]:
    """Plain-text readings of a dump in ``text``, for masking to learn from."""
    if not _SPREAD_GATE.search(text) and len(_HEX_LINE.findall(text)) < 2:
        return []
    out = []
    for read in (_char_dump, _hex_dump):
        v = read(text)
        if v and v.strip():
            out.append(v)
    return out


def _spread(chars: list[str]) -> str:
    return _SEP.join(chars)




# #24 (2-hour real-use run, 2026-11-22): every entry used to hold 3 compiled
# patterns (~30-50 KB) for as long as the service ran — memory grew with every
# real value ever masked (147 MB for 3,000 values). They are needed only for
# rare texts (a spread-out value, a hex dump), so they are built on use and at
# most _RX_KEEP are kept. Same patterns, same results.
_RX_KEEP = 1024


@functools.lru_cache(maxsize=_RX_KEEP)
def _rx(kind: str, core: str, hexed: str) -> re.Pattern:
    if kind == "spread":
        chars = [re.escape(c) for c in core]
        return re.compile(f"{_spread(chars)}|{_spread(chars[::-1])}")
    pairs = [f"(?i:{hexed[i:i + 2]})" for i in range(0, len(hexed), 2)]
    return re.compile((r"\s*" if kind == "hex_run" else _HEX_SEP).join(pairs))


class _Entry:
    __slots__ = ("stand_in", "core", "back", "enc", "hex_plain")

    def __init__(self, value: str, stand_in: str) -> None:
        self.core = _WS.sub("", value)
        self.stand_in = stand_in
        self.back = self.core[::-1]
        enc = quote(value, safe="")
        self.enc = (enc, enc.lower()) if enc != value else ()
        self.hex_plain = value.encode("utf-8").hex()

    @property
    def spread(self) -> re.Pattern:
        return _rx("spread", self.core, "")

    @property
    def hex_run(self) -> re.Pattern:
        return _rx("hex_run", "", self.hex_plain)

    @property
    def hexed(self) -> re.Pattern:
        return _rx("hexed", "", self.hex_plain)


class Finder:
    """Every known value's disguises, built once per set of known values."""

    def __init__(self) -> None:
        self._key: tuple[int, int, int] | None = None
        self._entries: dict[str, _Entry] = {}

    def compile(self, known: dict[str, str], version: tuple[int, int, int]) -> None:
        """``known``: real value -> its stand-in."""
        if version == self._key:
            return
        keep = {v: t for v, t in known.items() if len(_WS.sub("", v)) >= MIN_LEN}
        # Longest first, so a value that contains another is replaced whole.
        self._entries = {v: self._entries.get(v) or _Entry(v, t)
                         for v, t in sorted(keep.items(), key=lambda kv: -len(kv[0]))}
        self._key = version

    def find(self, text: str) -> tuple[str, list[str]]:
        """``text`` with every disguised known value replaced; the stand-ins used."""
        if not self._entries or len(text) < MIN_LEN:
            return text, []
        used: list[str] = []
        url = "%" in text
        spread = _SPREAD_GATE.search(text) is not None
        dump = len(_HEX_LINE.findall(text)) >= 2
        flat = _WS.sub("", text).lower()
        for e in self._entries.values():
            if not dump and e.hex_plain in flat:       # hex in one run (xxd -p wraps lines)
                text, n = e.hex_run.subn(e.stand_in, text)
                used += [e.stand_in] * n
                flat = _WS.sub("", text).lower()
            if e.back in text:
                used += [e.stand_in] * text.count(e.back)
                text = text.replace(e.back, e.stand_in)
            if url:
                for enc in e.enc:
                    if enc in text:
                        used += [e.stand_in] * text.count(enc)
                        text = text.replace(enc, e.stand_in)
            for name, on in (("spread", spread), ("hexed", dump)):
                if on:
                    rx = getattr(e, name)
                    text, n = rx.subn(e.stand_in, text)
                    used += [e.stand_in] * n
        return text, used
