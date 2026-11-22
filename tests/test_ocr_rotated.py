"""The picture reader reports the UPRIGHT picture's size, so its line boxes
land on the text (checker 2026-11-22). Phone photos carry a "rotate me" tag
(EXIF orientation); Apple Vision measures its boxes on the upright picture,
but the size came from the stored pixels — for a sideways photo (tags 5–8,
portrait iPhone = 6) every box was stretched to the wrong place and Omna for
Chrome's black bar missed the email. Real Apple Vision, macOS only."""
import io
import sys

import pytest

from omna_plugin import ocr

pytestmark = pytest.mark.skipif(sys.platform != "darwin" or not ocr.available(), reason="needs macOS Vision")

PIL = pytest.importorskip("PIL")
from PIL import Image, ImageDraw, ImageFont  # noqa: E402

INV = {1: [], 2: [Image.FLIP_LEFT_RIGHT], 3: [Image.ROTATE_180], 4: [Image.FLIP_TOP_BOTTOM],
       5: [Image.TRANSPOSE], 6: [Image.ROTATE_90], 7: [Image.TRANSVERSE], 8: [Image.ROTATE_270]}


def _photo(orientation: int) -> bytes:
    up = Image.new("RGB", (600, 800), "white")
    d = ImageDraw.Draw(up)
    f = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 30)
    d.text((30, 100), "Plan line: review the launch", fill="black", font=f)
    d.text((30, 460), "Contact: ana.lopez.test" + "@example-mail.com", fill="black", font=f)
    im = up
    for op in INV[orientation]:
        im = im.transpose(op)
    ex = Image.Exif()
    ex[0x0112] = orientation
    b = io.BytesIO()
    im.save(b, "JPEG", quality=90, exif=ex)
    return b.getvalue()


@pytest.mark.parametrize("orientation", range(1, 9))
def test_size_and_boxes_are_the_upright_pictures(orientation):
    r = ocr.recognize(_photo(orientation))
    assert (r["width"], r["height"]) == (600, 800)
    email = [line for line in r["lines"] if "@" in line["text"]]
    assert len(email) == 1
    assert abs(email[0]["y"] - 460) < 15 and email[0]["x"] < 60, email[0]
