"""Black out sensitive lines inside a picture, keeping it the same kind of picture.

Until 2026-10-31 the curl command let every picture through unmasked (MASTER
#160: it sits on the network, so it can't turn a picture into text — the site
already announced an image). Now, on a Mac, it reads the picture (ocr.py,
Apple Vision), finds sensitive values in the text with the same engine call
and settings as everything else (fast or --smart, same ruleset), and paints a
solid black box over every line that holds one. The result is encoded in the
SAME format (PNG stays PNG, JPEG stays JPEG), so the announced type still
matches; the caller pads it to the announced size where a site requires it.

Re-encoding also drops the original's metadata (EXIF, GPS) — a side benefit.

Refuses (returns None → the picture goes as it is, labelled "not masked",
exactly as before) when: not a Mac, unreadable, or the picture carries a
rotation flag (phone photos) — Vision reads it rotated while the pixels are
stored unrotated, so a box could land in the wrong place. A wrongly placed box
looks masked and isn't; a "not masked" label is honest.
"""

from __future__ import annotations

from collections.abc import Callable

from . import ocr, receipts

PAD = 3  # pixels of margin around each box, so letter edges don't show


def join_lines(lines: list[dict]) -> tuple[str, list[tuple[int, int]]]:
    """Lines joined with newlines, and each line's [start, end) char range."""
    text, ranges = "", []
    for i, line in enumerate(lines):
        if i:
            text += "\n"
        start = len(text)
        text += line["text"]
        ranges.append((start, len(text)))
    return text, ranges


def _char_spans(text: str, spans: list[dict]) -> list[tuple[int, int]]:
    """Engine spans are UTF-8 byte offsets; lines are char offsets."""
    raw = text.encode("utf-8")
    out = []
    for s in spans:
        a, b = s.get("start"), s.get("end")
        if isinstance(a, int) and isinstance(b, int) and 0 <= a < b <= len(raw):
            out.append((len(raw[:a].decode("utf-8", "ignore")), len(raw[:b].decode("utf-8", "ignore"))))
    return out


def boxes_to_hide(lines: list[dict], spans: list[dict]) -> list[tuple[float, float, float, float]]:
    """Box (x, y, w, h — top-left origin) of every line that holds a found value."""
    text, ranges = join_lines(lines)
    found = _char_spans(text, spans)
    boxes = []
    for (ls, le), line in zip(ranges, lines):
        if any(a < le and b > ls for a, b in found):
            boxes.append((line["x"], line["y"], line["w"], line["h"]))
    return boxes


def stats_of(spans: list[dict]) -> dict:
    """Counts in the shape MaskStats wants (same rules as engine.mask_text)."""
    counts: dict[str, int] = {}
    by_layer: dict[str, int] = {}
    secrets = pii = validated = 0
    for s in spans:
        counts[s["entity"]] = counts.get(s["entity"], 0) + 1
        layer = s.get("layer") or "?"
        by_layer[layer] = by_layer.get(layer, 0) + 1
        validated += 1 if s.get("validated") else 0
        if layer == "L2":
            secrets += 1
        else:
            pii += 1
    # Every value found in a picture or PDF is blacked out, whatever the
    # engine would have done with it as text.
    return {"counts": counts, "by_layer": by_layer, "secrets": secrets, "pii": pii, "validated": validated,
            "finds": receipts.finds_of(spans, action="redacted")}


def _rotated(data: bytes) -> bool:
    import Quartz  # type: ignore[import-not-found]
    from Foundation import NSData  # type: ignore[import-not-found]

    src = Quartz.CGImageSourceCreateWithData(NSData.dataWithBytes_length_(data, len(data)), None)
    props = Quartz.CGImageSourceCopyPropertiesAtIndex(src, 0, None) if src is not None else None
    orientation = (props or {}).get(Quartz.kCGImagePropertyOrientation, 1)
    return int(orientation or 1) != 1


def paint_boxes(data: bytes, boxes: list[tuple[float, float, float, float]]) -> bytes | None:
    """The picture with each box filled black, re-encoded in its own format."""
    import Quartz  # type: ignore[import-not-found]
    from Foundation import NSData, NSMutableData  # type: ignore[import-not-found]

    src = Quartz.CGImageSourceCreateWithData(NSData.dataWithBytes_length_(data, len(data)), None)
    if src is None:
        return None
    uti = Quartz.CGImageSourceGetType(src)
    img = Quartz.CGImageSourceCreateImageAtIndex(src, 0, None)
    if img is None or uti is None:
        return None
    w, h = Quartz.CGImageGetWidth(img), Quartz.CGImageGetHeight(img)
    ctx = Quartz.CGBitmapContextCreate(
        None, w, h, 8, 0, Quartz.CGColorSpaceCreateDeviceRGB(), Quartz.kCGImageAlphaPremultipliedLast,
    )
    if ctx is None:
        return None
    Quartz.CGContextDrawImage(ctx, Quartz.CGRectMake(0, 0, w, h), img)
    Quartz.CGContextSetRGBFillColor(ctx, 0, 0, 0, 1)
    for x, y, bw, bh in boxes:
        # Quartz draws with the origin at the BOTTOM-left; boxes are top-left.
        Quartz.CGContextFillRect(ctx, Quartz.CGRectMake(x - PAD, h - y - bh - PAD, bw + 2 * PAD, bh + 2 * PAD))
    out_img = Quartz.CGBitmapContextCreateImage(ctx)
    buf = NSMutableData.data()
    dest = Quartz.CGImageDestinationCreateWithData(buf, uti, 1, None)
    if dest is None or out_img is None:
        return None
    Quartz.CGImageDestinationAddImage(dest, out_img, {Quartz.kCGImageDestinationLossyCompressionQuality: 0.85})
    if not Quartz.CGImageDestinationFinalize(dest):
        return None
    return bytes(buf)


def redact(data: bytes, detect: Callable[[str], list[dict]]) -> tuple[bytes, dict] | None:
    """(picture with sensitive lines blacked out, stats) — or the original and
    empty stats when nothing was found. None = can't do it here (see module)."""
    if not ocr.available():
        return None
    try:
        if _rotated(data):
            return None
        read = ocr.recognize(data)
    except (ValueError, RuntimeError):
        return None
    if not read["lines"]:
        return data, stats_of([])
    text, _ = join_lines(read["lines"])
    spans = detect(text)
    boxes = boxes_to_hide(read["lines"], spans)
    if not boxes:
        return data, stats_of([])
    out = paint_boxes(data, boxes)
    if out is None:
        return None
    return out, stats_of(spans)
