"""Mask a Word (.docx) or Excel (.xlsx) file and keep it a Word or Excel file.

Both formats are a zip of XML parts. The text a person wrote sits in a few
known elements (Word: ``w:t`` inside ``w:p``; Excel: ``t`` inside a shared or
inline string, and the number in a value cell). Only the characters inside
those elements change; every other byte of every part, and every part that
holds no text (styles, images, settings), is copied as it was. The parts are
never parsed and re-written by an XML library: that drops namespace
declarations Word needs (``mc:Ignorable``) and Word then calls the file
corrupt.

A value can be split over several pieces of one paragraph (``<w:t>Ja</w:t>``
``<w:t>ne</w:t>`` when only half the name is bold), so the engine sees whole
paragraphs, and the masked paragraph is spread back over the pieces. Many
paragraphs are masked in one engine call, so neighbouring text gives context.

MASTER #160, option 2 ("original file, masked").
"""

from __future__ import annotations

import difflib
import html
import io
import re
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from typing import Callable

Mask = Callable[[str], str]

_MAX_UNZIPPED = 200 * 1024 * 1024      # a "document" bigger than this is not one
_BATCH_CHARS = 50_000                  # text per engine call
_SEP = "\n\n"                          # between paragraphs in one engine call

_TAG_RE = re.compile(r"<(/?)([A-Za-z_][\w.\-]*:)?([A-Za-z_][\w.\-]*)((?:\s[^>]*?)?)(/?)>")
_SPACE_ATTR_RE = re.compile(r"\sxml:space\s*=")
_AUTHOR_RE = re.compile(r'(\sw:author=")([^"]*)(")')
_NUM_CELL_RE = re.compile(r"<c\b([^>]*?)>\s*<v>([^<]*)</v>\s*</c>")
_CELL_TYPE_RE = re.compile(r'\st="([^"]*)"')


@dataclass
class _Part:
    """The text units of one XML part and where each piece of text sits."""
    xml: str
    # unit -> list of (start, end) offsets of the escaped text in ``xml``
    units: list[list[tuple[int, int]]] = field(default_factory=list)
    # (start, end) of each text element's opening tag, keyed by text start
    open_tags: dict[int, tuple[int, int]] = field(default_factory=dict)


# Which elements hold text in which part. "unit" elements group text into one
# piece the engine sees; "text" elements hold the characters; "split" elements
# (a tab, a line break) end a unit inside a paragraph; "skip" elements hide
# text that is not the person's (Excel's phonetic guide).
@dataclass(frozen=True)
class _Rules:
    unit: frozenset[str]
    text: frozenset[str]
    split: frozenset[str] = frozenset()
    skip: frozenset[str] = frozenset()
    # OpenDocument writes text straight into the paragraph (<text:p>Hi
    # <text:span>Ja</text:span>ne</text:p>), not into a text element: every
    # run of characters inside a unit is a piece.
    mixed: bool = False


_WORD = _Rules(unit=frozenset({"p"}), text=frozenset({"t", "delText", "instrText"}),
               split=frozenset({"tab", "br", "cr"}))
_EXCEL_STRINGS = _Rules(unit=frozenset({"si", "is", "text", "comment"}), text=frozenset({"t"}),
                        skip=frozenset({"rPh"}))
_EXCEL_THREADED = _Rules(unit=frozenset({"text"}), text=frozenset({"text"}))
_CHART = _Rules(unit=frozenset({"p", "pt"}), text=frozenset({"t", "v"}))
_ODF_TEXT = _Rules(unit=frozenset({"p", "h"}), text=frozenset(), split=frozenset({"tab", "line-break", "s"}),
                  skip=frozenset({"note-citation", "bookmark-ref", "reference-ref"}), mixed=True)
_ODF_META = _Rules(unit=frozenset({"creator", "initial-creator", "title", "subject", "description", "keyword"}),
                   text=frozenset({"creator", "initial-creator", "title", "subject", "description", "keyword"}))
_ODF_KINDS = {"application/vnd.oasis.opendocument.text": "odt",
              "application/vnd.oasis.opendocument.spreadsheet": "ods"}
_ODS_NUM_CELL_RE = re.compile(r"<table:table-cell\b([^>]*?\soffice:value=\"([^\"]*)\"[^>]*?)(/?)>")
_ODS_TYPE_RE = re.compile(r'\s(?:office|calcext):value-type="[^"]*"|\soffice:value="[^"]*"')
_DOC_PROPS = _Rules(unit=frozenset({"creator", "lastModifiedBy", "title", "subject", "description",
                                    "keywords", "Company", "Manager"}),
                    text=frozenset({"creator", "lastModifiedBy", "title", "subject", "description",
                                    "keywords", "Company", "Manager"}))


def kind(data: bytes) -> str | None:
    """"docx" / "xlsx" / "odt" / "ods" when the bytes are a Word, Excel or
    OpenDocument (LibreOffice) text / spreadsheet file, else None."""
    if not data.startswith(b"PK\x03\x04"):
        return None
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = set(z.namelist())
    except (zipfile.BadZipFile, ValueError, OSError):
        return None
    if "word/document.xml" in names:
        return "docx"
    if "xl/workbook.xml" in names:
        return "xlsx"
    if "mimetype" in names and "content.xml" in names:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                return _ODF_KINDS.get(z.read("mimetype").decode("ascii", "replace").strip())
        except (zipfile.BadZipFile, ValueError, OSError, KeyError):
            return None
    return None


_UNMASKABLE_MAGIC = (
    (b"%PDF-", "pdf"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "old-office"),   # .doc / .xls / .ppt (binary)
    (b"\x89PNG\r\n\x1a\n", "image"), (b"\xff\xd8\xff", "image"), (b"GIF8", "image"),
)


def unmaskable_kind(data: bytes) -> str:
    """A file type the curl command recognises but cannot mask in place
    ("pdf", "old-office", "image", "pptx"), or "" for anything else. Such a
    file goes through as it is and its receipt says so."""
    for magic, name in _UNMASKABLE_MAGIC:
        if data.startswith(magic):
            return name
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP" or data[4:12] in (b"ftypheic", b"ftypheix", b"ftypmif1"):
        return "image"
    if data.startswith(b"PK\x03\x04"):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                if "ppt/presentation.xml" in z.namelist():
                    return "pptx"
        except (zipfile.BadZipFile, ValueError, OSError):
            return ""
    return ""


def _rules_for(name: str, doc: str) -> _Rules | None:
    if doc in ("odt", "ods"):
        if name == "meta.xml":
            return _ODF_META
        if name in ("content.xml", "styles.xml"):          # body; headers and footers
            return _ODF_TEXT
        return None
    if name in ("docProps/core.xml", "docProps/app.xml"):
        return _DOC_PROPS
    if "/charts/" in name and name.endswith(".xml") and "/_rels/" not in name:
        return _CHART
    if "/drawings/" in name and name.endswith(".xml") and "/_rels/" not in name:
        return _CHART              # DrawingML text boxes: a:p / a:t
    if doc == "docx" and name.startswith("word/") and name.endswith(".xml") and "/_rels/" not in name:
        return _WORD
    if doc == "xlsx" and name.endswith(".xml") and "/_rels/" not in name and (
            name == "xl/sharedStrings.xml" or name.startswith(("xl/worksheets/", "xl/comments"))):
        return _EXCEL_STRINGS
    if doc == "xlsx" and name.startswith("xl/threadedComments/") and name.endswith(".xml"):
        return _EXCEL_THREADED      # <threadedComment><text>…</text>: the text sits in the element
    return None


def _scan(xml: str, rules: _Rules) -> _Part:
    """Find every text unit in one part without parsing it as a tree."""
    part = _Part(xml)
    stack: list[list[tuple[int, int]]] = []   # open units, innermost last
    skip = 0
    in_text: tuple[int, int] | None = None    # opening tag span of the open text element

    def end_unit_piece() -> None:
        # A tab or line break inside a paragraph: the text after it is a new unit.
        if stack and stack[-1]:
            part.units.append(stack[-1])
            stack[-1] = []

    last = 0
    for m in _TAG_RE.finditer(xml):
        closing, local, self_closing = m.group(1) == "/", m.group(3), m.group(5) == "/"
        if rules.mixed and stack and not skip and m.start() > last:
            stack[-1].append((last, m.start()))     # characters between two tags
        last = m.end()
        if local in rules.skip:
            if not self_closing:
                skip += -1 if closing else 1
            continue
        if skip:
            continue
        if in_text is not None:
            if closing and local in rules.text:
                start = in_text[1]
                if stack and m.start() > start:
                    stack[-1].append((start, m.start()))
                    part.open_tags[start] = in_text
                in_text = None
                if local in rules.unit and stack:   # docProps: the element was its own unit
                    if stack[-1]:
                        part.units.append(stack[-1])
                    stack.pop()
            continue
        if local in rules.text and not closing and not self_closing:
            if local in rules.unit:            # docProps: the element is its own unit
                stack.append([])
            in_text = (m.start(), m.end())
            if local in rules.unit:
                continue
        elif local in rules.unit and not self_closing:
            if closing:
                if stack:
                    if stack[-1]:
                        part.units.append(stack[-1])
                    stack.pop()
            else:
                stack.append([])
        elif local in rules.split:
            end_unit_piece()
    return part


def _texts(part: _Part, unit: list[tuple[int, int]]) -> list[str]:
    return [html.unescape(part.xml[a:b]) for a, b in unit]


def _spread(pieces: list[str], masked: str) -> list[str]:
    """Spread a masked unit back over its pieces; the pieces join to ``masked``."""
    if len(pieces) == 1:
        return [masked]
    orig = "".join(pieces)
    owner: list[int] = []                    # piece index of each original character
    for i, p in enumerate(pieces):
        owner.extend([i] * len(p))
    out = [""] * len(pieces)
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, orig, masked, autojunk=False).get_opcodes():
        if op == "equal":
            for k in range(i2 - i1):
                out[owner[i1 + k]] += masked[j1 + k]
        elif j2 > j1:                          # replace / insert: the stand-in goes where the value began
            at = owner[i1] if i1 < len(owner) else len(pieces) - 1
            out[at] += masked[j1:j2]
    return out


def _escape(text: str) -> str:
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _mask_units(texts: list[str], mask: Mask) -> list[str]:
    """Mask many units, several per engine call, each kept separate."""
    out: list[str] = []
    batch: list[str] = []
    size = 0

    def flush() -> None:
        nonlocal size
        if not batch:
            return
        joined = _SEP.join(batch)
        masked = mask(joined)
        parts = masked.split(_SEP)
        if len(parts) == len(batch):
            out.extend(parts)
        else:                                  # a value crossed a unit boundary: one at a time
            out.extend(mask(t) for t in batch)
        batch.clear()
        size = 0

    for t in texts:
        if _SEP in t or not t.strip():
            flush()
            out.append(mask(t) if t.strip() else t)
            continue
        batch.append(t)
        size += len(t) + len(_SEP)
        if size >= _BATCH_CHARS:
            flush()
    flush()
    return out


def _mask_part(xml: str, rules: _Rules, mask: Mask, excel_sheet: bool) -> str:
    part = _scan(xml, rules)
    pieces = [_texts(part, u) for u in part.units]
    joined = ["".join(p) for p in pieces]
    masked = _mask_units(joined, mask)
    edits: list[tuple[int, int, str]] = []
    for unit, before, orig, new in zip(part.units, pieces, joined, masked):
        if new == orig:
            continue
        for (a, b), old_text, new_text in zip(unit, before, _spread(before, new)):
            if new_text == old_text:
                continue
            edits.append((a, b, _escape(new_text)))
            if a not in part.open_tags:             # OpenDocument: no text element to mark
                continue
            tag_a, tag_b = part.open_tags[a]
            tag = xml[tag_a:tag_b]
            if new_text != new_text.strip() and not _SPACE_ATTR_RE.search(tag):
                edits.append((tag_b - 1, tag_b - 1, ' xml:space="preserve"'))
    if rules is _WORD:
        for m in _AUTHOR_RE.finditer(xml):     # tracked changes and comments name their author
            name = html.unescape(m.group(2))
            new = mask(name) if name.strip() else name
            if new != name:
                edits.append((m.start(2), m.end(2), _escape(new).replace('"', "&quot;")))
    if rules is _ODF_TEXT:
        edits.extend(_ods_number_cell_edits(xml, mask))
    out = _apply(xml, edits)
    if excel_sheet:
        out = _mask_number_cells(out, mask)
    return out


def _ods_number_cell_edits(xml: str, mask: Mask) -> list[tuple[int, int, str]]:
    """OpenDocument keeps a number cell's value twice: ``office:value="…"``
    and the text shown. The text is masked like any paragraph; a flagged value
    makes the cell a text cell (the number itself is dropped). Formula cells
    are left alone: the program recomputes them."""
    cells = [m for m in _ODS_NUM_CELL_RE.finditer(xml) if "table:formula=" not in m.group(1)]
    if not cells:
        return []
    masked = _mask_units([m.group(2) for m in cells], mask)
    # calcext (LibreOffice's own attributes) only where the file declares it.
    calcext = ' calcext:value-type="string"' if "xmlns:calcext=" in xml else ""
    edits = []
    for m, new in zip(cells, masked):
        if new == m.group(2):
            continue
        attrs = _ODS_TYPE_RE.sub("", m.group(1))
        edits.append((m.start(), m.end(), f'<table:table-cell{attrs} office:value-type="string"{calcext}{m.group(3)}>'))
    return edits


def _apply(xml: str, edits: list[tuple[int, int, str]]) -> str:
    if not edits:
        return xml
    edits.sort(key=lambda e: (e[0], e[1]))
    out, pos = [], 0
    for a, b, new in edits:
        out.append(xml[pos:a])
        out.append(new)
        pos = b
    out.append(xml[pos:])
    return "".join(out)


def _mask_number_cells(xml: str, mask: Mask) -> str:
    """A phone number or ID typed into Excel is stored as a number. If the
    engine flags it, the cell becomes a text cell holding the stand-in (a
    number cell cannot hold a bracketed stand-in). Cells with a formula, and
    cells of another type, are left alone: Excel recomputes formulas."""
    cells = [m for m in _NUM_CELL_RE.finditer(xml)
             if (t := _CELL_TYPE_RE.search(m.group(1))) is None or t.group(1) == "n"]
    if not cells:
        return xml
    masked = _mask_units([m.group(2) for m in cells], mask)
    edits = []
    for m, new in zip(cells, masked):
        if new == m.group(2):
            continue
        attrs = _CELL_TYPE_RE.sub("", m.group(1))
        space = ' xml:space="preserve"' if new != new.strip() else ""
        edits.append((m.start(), m.end(), f'<c{attrs} t="inlineStr"><is><t{space}>{_escape(new)}</t></is></c>'))
    return _apply(xml, edits)


# zlib (level, memLevel, strategy) for the masked parts: the usual default
# first; the rest only when a size-keeping upload needs bytes back.
_DEFLATE_SETTINGS = ((6, 8, zlib.Z_DEFAULT_STRATEGY), (9, 9, zlib.Z_DEFAULT_STRATEGY),
                     (9, 9, zlib.Z_FILTERED), (9, 8, zlib.Z_DEFAULT_STRATEGY))


def _raw_entry(data: bytes, info: zipfile.ZipInfo) -> bytes:
    """An entry's compressed bytes exactly as stored in ``data``."""
    at = info.header_offset
    if data[at:at + 4] != b"PK\x03\x04":
        raise zipfile.BadZipFile("bad local header")
    name_len, extra_len = struct.unpack("<HH", data[at + 26:at + 30])
    start = at + 30 + name_len + extra_len
    return data[start:start + info.compress_size]


def _write_zip(infos: list[zipfile.ZipInfo], raw: dict[str, bytes], changed: dict[str, bytes],
               setting: tuple[int, int, int], comment: bytes) -> bytes:
    """A zip with the same entries in the same order: unchanged ones copied
    as stored, changed ones compressed with ``setting`` (stored ones stay
    stored — OpenDocument's "mimetype" must). Sizes go in the headers, so no
    data descriptors; ZIP64 is never needed under _MAX_UNZIPPED."""
    level, mem, strategy = setting
    out = io.BytesIO()
    central = []
    for info in infos:
        name = info.filename.encode("utf-8" if info.flag_bits & 0x800 else "cp437")
        if info.filename in changed:
            body = changed[info.filename]
            crc, size = zlib.crc32(body) & 0xFFFFFFFF, len(body)
            if info.compress_type == zipfile.ZIP_DEFLATED:
                c = zlib.compressobj(level, zlib.DEFLATED, -15, mem, strategy)
                payload = c.compress(body) + c.flush()
            else:
                payload = body
        else:
            payload, crc, size = raw[info.filename], info.CRC, info.file_size
        flags = info.flag_bits & ~0x8                       # sizes are in the header: no data descriptor
        dt = info.date_time
        dos_time = dt[3] << 11 | dt[4] << 5 | dt[5] // 2
        dos_date = (dt[0] - 1980) << 9 | dt[1] << 5 | dt[2]
        offset = out.tell()
        out.write(struct.pack("<4s5H3L2H", b"PK\x03\x04", info.extract_version, flags, info.compress_type,
                              dos_time, dos_date, crc, len(payload), size, len(name), len(info.extra)))
        out.write(name + info.extra + payload)
        central.append(struct.pack("<4s6H3L5H2L", b"PK\x01\x02", info.create_version | info.create_system << 8,
                                   info.extract_version, flags, info.compress_type, dos_time, dos_date, crc,
                                   len(payload), size, len(name), len(info.extra), len(info.comment), 0,
                                   info.internal_attr, info.external_attr, offset)
                       + name + info.extra + info.comment)
    cd_start = out.tell()
    for c in central:
        out.write(c)
    out.write(struct.pack("<4s4H2LH", b"PK\x05\x06", 0, 0, len(infos), len(infos), out.tell() - cd_start,
                          cd_start, len(comment)) + comment)
    return out.getvalue()


class SizeChanged(Exception):
    """The masked file cannot be made exactly the original size."""


_ZIP_COMMENT_MAX = 0xFFFF


def mask_office(data: bytes, mask: Mask, _depth: int = 0, same_size: bool = False) -> bytes | None:
    """The masked file, the same type as ``data``; ``data`` itself when there
    was nothing to mask; None when it is not a Word or Excel file we can read
    (the caller then treats it as it did before).

    ``same_size``: some sites announce the file's size before uploading it and
    refuse a different one (ChatGPT: "file_size_mismatch"). The masked file is
    then made exactly as long as ``data``: a shorter one is filled up with the
    zip's own comment (invisible, at the very end); a longer one is compressed
    harder. If neither fits, SizeChanged is raised — the caller refuses the
    upload rather than send it unmasked."""
    doc = kind(data)
    if doc is None:
        return None
    try:
        zin = zipfile.ZipFile(io.BytesIO(data))
        infos = zin.infolist()
        if sum(i.file_size for i in infos) > _MAX_UNZIPPED or any(i.flag_bits & 0x1 for i in infos):
            return None
        changed: dict[str, bytes] = {}
        for info in infos:
            name = info.filename
            if _depth == 0 and "/embeddings/" in name and name.endswith((".xlsx", ".docx")):
                inner = mask_office(zin.read(info), mask, _depth + 1)
                if inner is not None and inner != zin.read(info):
                    changed[name] = inner
                continue
            rules = _rules_for(name, doc)
            if rules is None:
                continue
            raw = zin.read(info)
            try:
                xml = raw.decode("utf-8")
            except UnicodeDecodeError:
                continue                        # UTF-16 parts are legal but not seen in practice
            sheet = doc == "xlsx" and name.startswith("xl/worksheets/")
            out = _mask_part(xml, rules, mask, sheet)
            if out != xml:
                changed[name] = out.encode("utf-8")
        if not changed:
            return data

        # Read every part once: ZipFile.writestr updates the ZipInfo it is
        # given (offsets, sizes), so the originals are copied for each write
        # and never read back through a used one.
        # Parts that did not change are copied as their original compressed
        # bytes; only the masked parts are compressed again, with each setting
        # in _DEFLATE_SETTINGS tried until the file fits (smallest kept).
        raw = {i.filename: _raw_entry(data, i) for i in infos if i.filename not in changed}
        settings = _DEFLATE_SETTINGS[:1] if not same_size else _DEFLATE_SETTINGS
        best = None
        for setting in settings:
            out = _write_zip(infos, raw, changed, setting, zin.comment)
            if best is None or len(out) < len(best[0]):
                best = (out, setting)
            if len(out) <= len(data):
                break
        out, setting = best
        if not same_size or len(out) == len(data):
            return out
        gap = len(data) - len(out)
        if gap < 0 or len(zin.comment) + gap > _ZIP_COMMENT_MAX:
            raise SizeChanged(f"masked {len(out)} bytes, original {len(data)}")
        out = _write_zip(infos, raw, changed, setting, zin.comment + b" " * gap)
        if len(out) != len(data):
            raise SizeChanged(f"masked {len(out)} bytes, original {len(data)}")
        return out
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, KeyError, OSError, EOFError, NotImplementedError):
        return None


# --- RTF -------------------------------------------------------------------
# RTF is text, but formatting codes sit inside the words ("jane.doe@\b
# example.com" when half the address is bold), so the raw file never shows
# the engine a whole value. Read it like Word: the text between codes is a
# piece, a paragraph / tab / line break ends a unit, header tables (fonts,
# colours, styles, document info, pictures, "\*" destinations) are skipped.
# Only the characters of the pieces are rewritten; every code stays.

_RTF_SPLIT = frozenset({"par", "line", "tab", "cell", "row", "sect", "page", "column"})
_RTF_SKIP = frozenset({"fonttbl", "colortbl", "stylesheet", "info", "pict", "object", "listtable",
                       "listoverridetable", "rsidtbl", "generator", "themedata", "datastore", "xmlnstbl"})
_RTF_WORD_RE = re.compile(r"\\([a-zA-Z]{1,32})(-?\d{1,10})? ?")


def is_rtf(data: bytes) -> bool:
    return data.startswith(b"{\\rtf")


def _rtf_units(src: str) -> list[list[tuple[int, int, str]]]:
    """Units of (start, end, text) pieces; ``src`` is the file decoded as latin-1."""
    units: list[list[tuple[int, int, str]]] = [[]]
    skip_stack = [False]
    uc = 1                                   # characters that follow a \uN as its fallback
    piece_start, piece_text = -1, []
    i, n = 0, len(src)

    def end_piece(at: int) -> None:
        nonlocal piece_start, piece_text
        if piece_start >= 0 and piece_text:
            units[-1].append((piece_start, at, "".join(piece_text)))
        piece_start, piece_text = -1, []

    def add(ch: str, start: int) -> None:
        nonlocal piece_start
        if skip_stack[-1]:
            return
        if piece_start < 0:
            piece_start = start
        piece_text.append(ch)

    while i < n:
        c = src[i]
        if c == "{":
            end_piece(i)
            skip_stack.append(skip_stack[-1])
            i += 1
        elif c == "}":
            end_piece(i)
            if len(skip_stack) > 1:
                skip_stack.pop()
            i += 1
        elif c == "\\":
            nxt = src[i + 1] if i + 1 < n else ""
            if nxt == "'" and i + 3 < n:                    # \'hh: one byte in the document's code page
                try:
                    add(bytes([int(src[i + 2:i + 4], 16)]).decode("cp1252"), i)
                except (ValueError, UnicodeDecodeError):
                    end_piece(i)
                i += 4
            elif nxt in "\\{}":
                add(nxt, i)
                i += 2
            elif nxt == "*":                                 # an ignorable destination
                end_piece(i)
                skip_stack[-1] = True
                i += 2
            else:
                m = _RTF_WORD_RE.match(src, i)
                if not m:
                    end_piece(i)
                    if nxt in "\r\n" and units[-1]:        # backslash + line break = a paragraph (macOS writes these)
                        units.append([])
                    i += 2                                   # other control symbols (\~, \-, …)
                    continue
                word, num = m.group(1), m.group(2)
                if word == "u" and num is not None:          # \uN then `uc` fallback characters
                    code = int(num) + (65536 if int(num) < 0 else 0)
                    add(chr(code), i)
                    i = m.end()
                    for _ in range(uc):
                        if i < n and src[i] not in "\\{}":
                            i += 1
                    continue
                end_piece(i)
                if word == "uc" and num is not None:
                    uc = int(num)
                elif word in _RTF_SKIP:
                    skip_stack[-1] = True
                elif word in _RTF_SPLIT and units[-1]:
                    units.append([])
                i = m.end()
        elif c in "\r\n":                                   # line breaks in the file are not text
            end_piece(i)
            i += 1
        else:
            add(c, i)
            i += 1
    end_piece(n)
    return [u for u in units if u]


def _rtf_escape(text: str) -> str:
    out = []
    for ch in text:
        if ch in "\\{}":
            out.append("\\" + ch)
        elif ord(ch) < 128:
            out.append(ch)
        elif (b := ch.encode("cp1252", "ignore")):            # the way RTF writers spell é: \'e9
            out.append(f"\\'{b[0]:02x}")
        else:
            for unit in ch.encode("utf-16-be").hex(" ", 2).split():   # surrogate pairs become two \u
                v = int(unit, 16)
                out.append(f"\\u{v - 65536 if v > 32767 else v}?")
    return "".join(out)


def mask_rtf(data: bytes, mask: Mask) -> bytes:
    """The masked RTF file (``data`` itself when there was nothing to mask)."""
    src = data.decode("latin-1")
    units = _rtf_units(src)
    pieces = [[t for _, _, t in u] for u in units]
    joined = ["".join(p) for p in pieces]
    masked = _mask_units(joined, mask)
    edits: list[tuple[int, int, str]] = []
    for unit, before, orig, new in zip(units, pieces, joined, masked):
        if new == orig:
            continue
        for (a, b, old_text), new_text in zip(unit, _spread(before, new)):
            if new_text != old_text:
                edits.append((a, b, _rtf_escape(new_text)))
    if not edits:
        return data
    return _apply(src, edits).encode("latin-1")
