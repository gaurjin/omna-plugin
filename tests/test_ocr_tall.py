"""P3 (client test 2026-11-22): a very tall screenshot (a whole web page) was
read as gibberish or as nothing — Apple Vision shrinks the whole picture to
read it in one go. Measured 2026-11-23: 1200 px wide reads fine at 8,000 px
tall and gives ZERO lines at 16,000 and 30,000 px, so every email in it went
out. The reader now reads a tall picture in overlapping slices. Real Apple
Vision, macOS only."""
import io
import sys

import pytest

from omna_plugin import ocr

pytestmark = pytest.mark.skipif(sys.platform != "darwin" or not ocr.available(), reason="needs macOS Vision")

PIL = pytest.importorskip("PIL")
from PIL import Image, ImageDraw, ImageFont  # noqa: E402


def _page(height: int, width: int = 1200) -> tuple[bytes, dict[str, int]]:
    f = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 26)
    im = Image.new("RGB", (width, height), "white")
    d = ImageDraw.Draw(im)
    emails = {}
    for i, y in enumerate(range(40, height - 40, 48)):
        text = f"Line {i}: the quarterly plan review notes for the team"
        if i % 60 == 30:
            text = f"Contact ana.lopez{i}" + f"@example-mail.com for line {i}"
            emails[f"ana.lopez{i}@example-mail.com"] = y
        d.text((40, y), text, fill="black", font=f)
    b = io.BytesIO()
    im.save(b, "PNG")
    return b.getvalue(), emails


@pytest.mark.parametrize("height", [16000, 30000])
def test_every_email_on_a_tall_page_is_read_where_it_is(height):
    data, emails = _page(height)
    r = ocr.recognize(data)
    assert (r["width"], r["height"]) == (1200, height)
    for email, y in emails.items():
        hits = [ln for ln in r["lines"] if email in ln["text"]]
        assert len(hits) == 1, f"{email}: read {len(hits)} times"
        assert abs(hits[0]["y"] - y) < 40, f"{email}: box at {hits[0]['y']:.0f}, text at {y}"


def test_a_line_on_a_slice_border_is_read_once():
    data, _ = _page(16000)
    texts = [ln["text"] for ln in ocr.recognize(data)["lines"]]
    lines = [t for t in texts if t.startswith("Line ")]
    assert len(lines) == len(set(lines)), "a line in two slices was kept twice"
    assert len(lines) > 300


def test_a_normal_picture_is_read_in_one_go(monkeypatch):
    data, emails = _page(3000)
    calls = []
    real = ocr._read
    monkeypatch.setattr(ocr, "_read", lambda *a, **k: calls.append(1) or real(*a, **k))
    r = ocr.recognize(data)
    assert len(calls) == 1
    assert all(any(e in ln["text"] for ln in r["lines"]) for e in emails)


def test_a_thin_very_tall_picture_is_read_in_a_bounded_number_of_slices(monkeypatch):
    """Review of P3: slices followed the width, so a 10 x 100,000 px picture
    was cut into ~5,000 slices (78 s, measured). At most MAX_SLICES now."""
    im = Image.new("RGB", (10, 100_000), "white")
    b = io.BytesIO()
    im.save(b, "PNG")
    calls = []
    monkeypatch.setattr(ocr, "_read", lambda *a, **k: calls.append(1) or [])
    ocr.recognize(b.getvalue())
    assert 1 < len(calls) <= ocr.MAX_SLICES
