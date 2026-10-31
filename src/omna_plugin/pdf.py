"""Black out values INSIDE a PDF, keeping it a PDF (MASTER #160, option C).

The curl command sits on the network, so it can't turn a PDF into text — the
site already announced a PDF. Until 2026-10-31 every PDF went through
unmasked. On a Mac (Apple's PDFKit, via pyobjc) it now:

  * reads each page's text and finds values with the session's own settings
    (fast/--smart, ruleset) — `detect`, never minting stand-ins;
  * leaves every page WITHOUT a value exactly as it was (still text);
  * turns each page WITH a value into a picture of itself (144 dpi) with a
    black box over each value — so nothing hidden can be copied back out of
    the text layer. A black box drawn over text that is still underneath
    would only LOOK masked; this never does that.

The AI still reads the painted pages (every major AI reads PDF pages as
pictures too). The file usually grows, so a same-size site (ChatGPT) gets a
refusal rather than a different size — the existing rule.

Returns None (→ goes as it is, receipt "file NOT masked (pdf)", as before)
when: not a Mac, unreadable, encrypted/locked, or over MAX_PAGES.
"""

from __future__ import annotations

import sys
from collections.abc import Callable

try:
    import Quartz  # type: ignore[import-not-found]
    from AppKit import NSImage  # type: ignore[import-not-found]
    from Foundation import NSData, NSMakeRange  # type: ignore[import-not-found]
    from Quartz import PDFDocument, PDFPage  # type: ignore[import-not-found]

    _HAVE_PDFKIT = True
except Exception:  # noqa: BLE001 - any import problem means "no PDF masking here"
    _HAVE_PDFKIT = False

SCALE = 2.0      # 144 dpi: readable for the AI, not huge
PAD = 2.0        # points of margin around each box
MAX_PAGES = 2000


def available() -> bool:
    return _HAVE_PDFKIT and sys.platform == "darwin"


def _open(data: bytes):
    doc = PDFDocument.alloc().initWithData_(NSData.dataWithBytes_length_(data, len(data)))
    if doc is None or doc.isEncrypted() or doc.isLocked() or doc.pageCount() < 1:
        return None
    return doc


def page_texts(data: bytes) -> list[str]:
    """Each page's text (what can still be copied out)."""
    doc = _open(data)
    return [] if doc is None else [doc.pageAtIndex_(i).string() or "" for i in range(doc.pageCount())]


def _char_spans(text: str, spans: list[dict]) -> list[tuple[int, int]]:
    raw = text.encode("utf-8")
    out = []
    for s in spans:
        a, b = s.get("start"), s.get("end")
        if isinstance(a, int) and isinstance(b, int) and 0 <= a < b <= len(raw):
            out.append((len(raw[:a].decode("utf-8", "ignore")), len(raw[:b].decode("utf-8", "ignore"))))
    return out


def _utf16(text: str, i: int) -> int:
    """PDFKit ranges count UTF-16 units; Python counts characters."""
    return len(text[:i].encode("utf-16-le")) // 2


def _value_rects(page, text: str, spans: list[dict]) -> list:
    rects = []
    for a, b in _char_spans(text, spans):
        start, end = _utf16(text, a), _utf16(text, b)
        sel = page.selectionForRange_(NSMakeRange(start, end - start))
        if sel is None:
            continue
        for line in sel.selectionsByLine() or [sel]:
            r = line.boundsForPage_(page)
            if r.size.width > 0 and r.size.height > 0:
                rects.append(r)
    return rects


def _painted_page(page, rects):
    box = page.boundsForBox_(Quartz.kPDFDisplayBoxMediaBox)
    w, h = int(box.size.width * SCALE), int(box.size.height * SCALE)
    ctx = Quartz.CGBitmapContextCreate(
        None, w, h, 8, 0, Quartz.CGColorSpaceCreateDeviceRGB(), Quartz.kCGImageAlphaPremultipliedLast,
    )
    if ctx is None:
        return None
    Quartz.CGContextSetRGBFillColor(ctx, 1, 1, 1, 1)
    Quartz.CGContextFillRect(ctx, Quartz.CGRectMake(0, 0, w, h))
    Quartz.CGContextScaleCTM(ctx, SCALE, SCALE)
    Quartz.CGContextTranslateCTM(ctx, -box.origin.x, -box.origin.y)
    Quartz.CGContextDrawPDFPage(ctx, page.pageRef())
    Quartz.CGContextSetRGBFillColor(ctx, 0, 0, 0, 1)
    for r in rects:
        Quartz.CGContextFillRect(ctx, Quartz.CGRectMake(
            r.origin.x - PAD, r.origin.y - PAD, r.size.width + 2 * PAD, r.size.height + 2 * PAD))
    img = Quartz.CGBitmapContextCreateImage(ctx)
    if img is None:
        return None
    return PDFPage.alloc().initWithImage_(NSImage.alloc().initWithCGImage_size_(img, (box.size.width, box.size.height)))


def redact(data: bytes, detect: Callable[[str], list[dict]]) -> tuple[bytes, list[dict]] | None:
    """(PDF with values painted over, every span found) — or (the original, [])
    when nothing was found. None = can't do it safely here (see module)."""
    if not available():
        return None
    try:
        doc = _open(data)
        if doc is None or doc.pageCount() > MAX_PAGES:
            return None
        out = PDFDocument.alloc().init()
        found: list[dict] = []
        for i in range(doc.pageCount()):
            page = doc.pageAtIndex_(i)
            text = page.string() or ""
            spans = detect(text) if text.strip() else []
            if not spans:
                out.insertPage_atIndex_(page.copy(), out.pageCount())
                continue
            rects = _value_rects(page, text, spans)
            if len(rects) < len(spans):
                return None  # a value we can't locate can't be hidden — don't pretend
            painted = _painted_page(page, rects)
            if painted is None:
                return None
            out.insertPage_atIndex_(painted, out.pageCount())
            found.extend(spans)
        if not found:
            return data, []
        result = out.dataRepresentation()
        return (bytes(result), found) if result is not None else None
    except Exception:  # noqa: BLE001 - any PDFKit failure: honest "not masked"
        return None


def render_page_png(data: bytes, index: int) -> bytes:
    """One page as a PNG (tests use it to look at what the AI would see)."""
    from Foundation import NSMutableData  # type: ignore[import-not-found]

    doc = _open(data)
    page = doc.pageAtIndex_(index)
    painted = _painted_page(page, [])
    img = painted.thumbnailOfSize_forBox_((1240, 1754), Quartz.kPDFDisplayBoxMediaBox)
    cg = img.CGImageForProposedRect_context_hints_(None, None, None)[0]
    buf = NSMutableData.data()
    dest = Quartz.CGImageDestinationCreateWithData(buf, "public.png", 1, None)
    Quartz.CGImageDestinationAddImage(dest, cg, None)
    Quartz.CGImageDestinationFinalize(dest)
    return bytes(buf)
