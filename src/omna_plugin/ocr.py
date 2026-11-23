"""Read the text in a picture or screenshot, with Apple's own Vision framework.

The Omna Mac app reads pictures with Apple Vision through a small Swift helper
(native/src/ocr.rs in omna-workspace). This is the same framework, reached from
Python (pyobjc), so the curl command can do it too — no model download: Vision
ships with macOS.

It only READS: the text of each line and where the line sits (pixels, top-left
origin — the Mac app's `OcrLine` shape). Masking stays with whoever asked, so a
picture's stand-ins come from the same list as the rest of the conversation
(two separate lists can give one stand-in two meanings — MASTER #179/#181).

macOS only. Elsewhere `available()` is False and callers send the picture as
it is, labelled, exactly as before.
"""

from __future__ import annotations

import sys

try:  # pyobjc: installed on macOS only (pyproject marker)
    import Quartz  # type: ignore[import-not-found]
    import Vision  # type: ignore[import-not-found]
    from Foundation import NSData  # type: ignore[import-not-found]

    _HAVE_VISION = True
except Exception:  # noqa: BLE001 - any import problem means "no OCR here"
    _HAVE_VISION = False

# Largest picture read in one go. Was 25 MB, a number copied from the Mac
# app's chunked transfer. Measured 2026-11-01 (M5 MacBook Air, noisy PNGs that
# don't compress): 35 MB 1.2 s, 88 MB 2.5 s, 8000x8000 / 161 MB 4.4 s, all
# blacked out correctly. 100 MB = the extension's file limit; above it the
# picture goes as it is, logged "not masked" (lesson #34: a lifted cap keeps a
# bound). Omna for Chrome sends at most 40 MB here (Chrome's 64 MB message
# limit on the base64 copy — extension PLUGIN_OCR_MAX_BYTES).
MAX_BYTES = 100 * 1024 * 1024


def available() -> bool:
    """True when this machine can read text in pictures (macOS + Vision)."""
    return _HAVE_VISION and sys.platform == "darwin"


# P3 (client test 2026-11-22): Vision shrinks the whole picture to read it in
# one go, so a whole-page screenshot came back as gibberish or as nothing
# (measured 2026-11-23: 1200 px wide reads at 8,000 px tall, ZERO lines at
# 16,000). A picture taller than TALL x its width is read in slices SLICE x
# its width tall, overlapping by more than a line, each line kept once.
# SLICE measured on a 30,000 px page, 10 emails: 1x 10/10 2.6 s; 2x 10/10,
# fewest misread lines, 1.2 s; 3x only 8/10.
TALL = 4
SLICE = 2
# Review of P3: slices followed the width, so a 10 x 100,000 px picture was
# ~5,000 slices (78 s). A thin picture gets taller slices instead: never more
# than this many reads (about 0.1 s each).
MAX_SLICES = 32
OVERLAP = 240   # px: taller than any line of text on a screenshot


def _open(data: bytes):
    """(stored picture, upright width, upright height, orientation) or None."""
    src = Quartz.CGImageSourceCreateWithData(NSData.dataWithBytes_length_(data, len(data)), None)
    if src is None or Quartz.CGImageSourceGetCount(src) < 1:
        return None
    img = Quartz.CGImageSourceCreateImageAtIndex(src, 0, None)
    if img is None:
        return None
    w, h = float(Quartz.CGImageGetWidth(img)), float(Quartz.CGImageGetHeight(img))
    # Vision measures its boxes on the UPRIGHT picture (it applies the photo's
    # "rotate me" tag). Tags 5–8 turn it a quarter, so the upright picture's
    # width and height are swapped (checker 2026-11-22: a portrait phone photo
    # got its black bar on blank paper and the email went out).
    props = Quartz.CGImageSourceCopyPropertiesAtIndex(src, 0, None) or {}
    try:
        orientation = int(props.get(Quartz.kCGImagePropertyOrientation, 1) or 1)
    except (TypeError, ValueError):
        orientation = 1
    if orientation in (5, 6, 7, 8):
        w, h = h, w
    return img, w, h, orientation


def _read(handler, width: float, height: float, top: float = 0.0) -> list[dict]:
    """Vision on one handler; boxes in the full picture's pixels (top-left
    origin, like the Mac app). ``width``/``height`` = the part read, ``top`` =
    where that part starts in the full picture."""
    request = Vision.VNRecognizeTextRequest.alloc().init()
    request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
    request.setUsesLanguageCorrection_(False)  # keep IDs, keys and emails as written
    ok, err = handler.performRequests_error_([request], None)
    if not ok:
        raise ValueError(f"could not read the picture: {err}")
    lines = []
    for obs in request.results() or []:
        cands = obs.topCandidates_(1)
        if not cands:
            continue
        text = str(cands[0].string())
        if not text.strip():
            continue
        box = obs.boundingBox()  # normalised, bottom-left origin
        bx, by = box.origin.x, box.origin.y
        bw, bh = box.size.width, box.size.height
        lines.append({
            "text": text,
            "x": bx * width,
            "y": top + (1.0 - by - bh) * height,
            "w": bw * width,
            "h": bh * height,
        })
    return lines


def _read_tall(img, width: float, height: float) -> list[dict]:
    """A tall upright picture in overlapping slices. A line is kept by the one
    slice whose own stretch (overlap split in the middle) holds its centre."""
    step = max(SLICE * width, height / MAX_SLICES)
    lines: list[dict] = []
    top = 0.0
    while top < height:
        start = max(0.0, top - OVERLAP)
        end = min(height, top + step + OVERLAP)
        tile = Quartz.CGImageCreateWithImageInRect(img, Quartz.CGRectMake(0, start, width, end - start))
        if tile is None:
            raise ValueError("could not cut the picture into slices")
        handler = Vision.VNImageRequestHandler.alloc().initWithCGImage_options_(tile, None)
        own_end = min(height, top + step)
        for ln in _read(handler, width, end - start, start):
            if top <= ln["y"] + ln["h"] / 2 < own_end:
                lines.append(ln)
        top = own_end
    return lines


def recognize(data: bytes) -> dict:
    """Text lines in the picture: {"width", "height", "lines": [{text,x,y,w,h}]}.

    Raises ValueError for something that isn't a readable picture and
    RuntimeError when this machine can't read pictures at all.
    """
    if not available():
        raise RuntimeError("reading pictures needs macOS")
    if not data or len(data) > MAX_BYTES:
        raise ValueError("picture is empty or too large")
    opened = _open(data)
    if opened is None:
        raise ValueError("not a picture this Mac can open")
    img, width, height, orientation = opened
    # Slices are cut from the stored pixels, so only an untagged picture is
    # sliced (screenshots carry no "rotate me" tag; phone photos are not tall).
    if orientation == 1 and height > TALL * width + OVERLAP:
        return {"width": width, "height": height, "lines": _read_tall(img, width, height)}
    handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(
        NSData.dataWithBytes_length_(data, len(data)), None,
    )
    return {"width": width, "height": height, "lines": _read(handler, width, height)}
