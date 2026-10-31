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

# Largest picture read in one go. Same bound as the extension's OCR_MAX_BYTES.
MAX_BYTES = 25 * 1024 * 1024


def available() -> bool:
    """True when this machine can read text in pictures (macOS + Vision)."""
    return _HAVE_VISION and sys.platform == "darwin"


def _image_size(data: bytes) -> tuple[float, float] | None:
    src = Quartz.CGImageSourceCreateWithData(NSData.dataWithBytes_length_(data, len(data)), None)
    if src is None or Quartz.CGImageSourceGetCount(src) < 1:
        return None
    img = Quartz.CGImageSourceCreateImageAtIndex(src, 0, None)
    if img is None:
        return None
    return float(Quartz.CGImageGetWidth(img)), float(Quartz.CGImageGetHeight(img))


def recognize(data: bytes) -> dict:
    """Text lines in the picture: {"width", "height", "lines": [{text,x,y,w,h}]}.

    Raises ValueError for something that isn't a readable picture and
    RuntimeError when this machine can't read pictures at all.
    """
    if not available():
        raise RuntimeError("reading pictures needs macOS")
    if not data or len(data) > MAX_BYTES:
        raise ValueError("picture is empty or too large")
    size = _image_size(data)
    if size is None:
        raise ValueError("not a picture this Mac can open")
    width, height = size

    request = Vision.VNRecognizeTextRequest.alloc().init()
    request.setRecognitionLevel_(Vision.VNRequestTextRecognitionLevelAccurate)
    request.setUsesLanguageCorrection_(False)  # keep IDs, keys and emails as written
    handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(
        NSData.dataWithBytes_length_(data, len(data)), None,
    )
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
            "y": (1.0 - by - bh) * height,  # -> top-left origin, like the Mac app
            "w": bw * width,
            "h": bh * height,
        })
    return {"width": width, "height": height, "lines": lines}
