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

import copy
import difflib
import html
import io
import re
import zipfile
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


_WORD = _Rules(unit=frozenset({"p"}), text=frozenset({"t", "delText", "instrText"}),
               split=frozenset({"tab", "br", "cr"}))
_EXCEL_STRINGS = _Rules(unit=frozenset({"si", "is", "text", "comment"}), text=frozenset({"t"}),
                        skip=frozenset({"rPh"}))
_EXCEL_THREADED = _Rules(unit=frozenset({"text"}), text=frozenset({"text"}))
_CHART = _Rules(unit=frozenset({"p", "pt"}), text=frozenset({"t", "v"}))
_DOC_PROPS = _Rules(unit=frozenset({"creator", "lastModifiedBy", "title", "subject", "description",
                                    "keywords", "Company", "Manager"}),
                    text=frozenset({"creator", "lastModifiedBy", "title", "subject", "description",
                                    "keywords", "Company", "Manager"}))


def kind(data: bytes) -> str | None:
    """"docx" / "xlsx" when the bytes are a Word or Excel file, else None."""
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
    return None


def _rules_for(name: str, doc: str) -> _Rules | None:
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

    for m in _TAG_RE.finditer(xml):
        closing, local, self_closing = m.group(1) == "/", m.group(3), m.group(5) == "/"
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
    out = _apply(xml, edits)
    if excel_sheet:
        out = _mask_number_cells(out, mask)
    return out


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
        bodies = {i.filename: changed.get(i.filename) or zin.read(i) for i in infos}

        def write(level: int | None, comment: bytes) -> bytes:
            # Every part is compressed again (same content): level None is
            # zlib's default, 9 squeezes harder when the masked file grew.
            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zout:
                zout.comment = comment
                for info in infos:
                    zout.writestr(copy.copy(info), bodies[info.filename], compress_type=info.compress_type,
                                  compresslevel=level)
            return buf.getvalue()

        level = None                            # zlib's default, as the original was most likely written
        out = write(level, zin.comment)
        if not same_size or len(out) == len(data):
            return out
        if len(out) > len(data):
            level = 9
            out = write(level, zin.comment)
        gap = len(data) - len(out)
        if gap < 0 or len(zin.comment) + gap > _ZIP_COMMENT_MAX:
            raise SizeChanged(f"masked {len(out)} bytes, original {len(data)}")
        out = write(level, zin.comment + b" " * gap)
        if len(out) != len(data):
            raise SizeChanged(f"masked {len(out)} bytes, original {len(data)}")
        return out
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, KeyError, OSError, EOFError, NotImplementedError):
        return None
