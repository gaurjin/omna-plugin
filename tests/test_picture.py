"""Pictures through the curl command: sensitive lines blacked out, same format.

Fake data only (tests/fixtures/fake-ticket.png: a made-up support ticket).
The real-Vision test runs only on a Mac with Vision available.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from omna_plugin import ocr, picture
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline

TICKET = (Path(__file__).parent / "fixtures" / "fake-ticket.png").read_bytes()


def _line(text, y):
    return {"text": text, "x": 10.0, "y": y, "w": 300.0, "h": 20.0}


def test_only_lines_with_a_value_get_a_box_even_after_an_emoji():
    lines = [_line("Ticket 😀 #4471", 0), _line("Email: maria@acme-test.com", 30), _line("Thanks!", 60)]
    text, _ = picture.join_lines(lines)
    raw = text.encode()
    a = raw.index(b"maria")
    spans = [{"start": a, "end": a + len(b"maria@acme-test.com"), "entity": "EMAIL", "layer": "L1"}]
    assert picture.boxes_to_hide(lines, spans) == [(10.0, 30.0, 300.0, 20.0)]


def test_stats_count_secrets_and_personal_data_like_the_engine():
    st = picture.stats_of([{"entity": "EMAIL", "layer": "L1"}, {"entity": "AWS_KEY", "layer": "L2", "validated": True}])
    assert st["counts"] == {"EMAIL": 1, "AWS_KEY": 1}
    assert (st["secrets"], st["pii"], st["validated"]) == (1, 1, 1)


def test_pipeline_labels_a_picture_not_masked_when_it_cannot_be_done(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    monkeypatch.setattr(picture, "redact", lambda data, detect: None)
    out, st = Pipeline(MaskingSession()).mask_file(TICKET, "image/png")
    assert out == TICKET and st.not_masked == "image"


def test_pipeline_uses_the_blacked_out_picture(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    monkeypatch.setattr(picture, "redact", lambda data, detect: (b"\x89PNG-redacted", picture.stats_of([{"entity": "EMAIL", "layer": "L1"}])))
    out, st = Pipeline(MaskingSession()).mask_file(TICKET, "image/png")
    assert out == b"\x89PNG-redacted" and st.counts == {"EMAIL": 1} and not st.not_masked


@pytest.mark.skipif(not ocr.available(), reason="needs macOS + Apple Vision")
def test_real_picture_values_are_gone_and_it_stays_a_png(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    out, st = Pipeline(MaskingSession()).mask_file(TICKET, "image/png")
    assert out.startswith(b"\x89PNG"), "must stay a PNG"
    assert st.counts and not st.not_masked
    after = " ".join(l["text"] for l in ocr.recognize(out)["lines"])
    for value in ("maria.gonzalez", "415-555-0137", "AKIAIOSFODNN"):
        assert value not in after, f"{value} still readable"
    assert "Customer support ticket" in after and "invoice" in after, "lines without values must stay"


@pytest.mark.skipif(not ocr.available(), reason="needs macOS + Apple Vision")
def test_same_size_upload_keeps_the_announced_size(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    out, st = Pipeline(MaskingSession()).mask_file_same_size(TICKET, "image/png")
    assert out is None or len(out) == len(TICKET), "same size, or refused — never a different size"


def test_picture_limit_is_100_mb_and_bigger_is_refused_not_misread():
    # Was 25 MB (copied from the Mac app's chunked path); measured 2026-11-01:
    # an 8000x8000 / 161 MB picture is blacked out in 4.4 s on an M5 Air.
    from omna_plugin import ocr

    assert ocr.MAX_BYTES == 100 * 1024 * 1024
    if not ocr.available():
        pytest.skip("reading pictures needs macOS")
    with pytest.raises(ValueError, match="too large"):
        ocr.recognize(b"\x89PNG" + b"\0" * ocr.MAX_BYTES)


@pytest.mark.skipif(not ocr.available(), reason="needs macOS + Apple Vision")
def test_a_value_wrapped_onto_two_lines_is_blacked_out_on_both(tmp_path, monkeypatch):
    """P2 (client test 2026-11-22): an email or phone number that wraps onto the
    next line was never found — the read lines were joined with a line break.
    Ordinary lines keep their break and are never blacked out."""
    import io

    from PIL import Image, ImageDraw, ImageFont

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    f = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 30)
    im = Image.new("RGB", (520, 560), "white")
    d = ImageDraw.Draw(im)
    rows = ["Plan line: review the launch", "Write to ana.lopez.test@", "example-mail.com today", "",
            "Or maria.garcia.test@example-", "mail.com for billing", "", "Call 415-555-", "0199 after five",
            "", "Total-", "2024 budget"]
    for i, t in enumerate(rows):
        d.text((30, 30 + i * 42), t, fill="black", font=f)
    b = io.BytesIO()
    im.save(b, "PNG")
    out, st = Pipeline(MaskingSession()).mask_file(b.getvalue(), "image/png")
    after = [ln["text"] for ln in ocr.recognize(out)["lines"]]
    for gone in ("ana.lopez", "example-mail.com", "maria.garcia", "mail.com for", "415-555", "0199"):
        assert not any(gone in t for t in after), f"{gone} still readable: {after}"
    for kept in ("Plan line: review the launch", "Total-", "2024 budget"):
        assert any(kept in t for t in after), f"{kept} was blacked out: {after}"


def test_only_a_real_continuation_is_joined():
    L = lambda t, x, y: {"text": t, "x": x, "y": y, "w": 200.0, "h": 30.0}  # noqa: E731
    assert picture.join_lines([L("ana.lopez.test@", 30, 72), L("example-mail.com", 600, 72)])[0] == "ana.lopez.test@\nexample-mail.com"
    assert picture.join_lines([L("ana.lopez.test@", 30, 72), L("example-mail.com", 30, 400)])[0] == "ana.lopez.test@\nexample-mail.com"
    assert picture.join_lines([L("Meeting notes", 30, 72), L("Budget review", 30, 109)])[0] == "Meeting notes\nBudget review"
    assert picture.join_lines([L("ana.lopez.test@", 30, 72), L("example-mail.com", 30, 109)])[0] == "ana.lopez.test@example-mail.com"


def test_a_sentence_end_is_not_a_value_breaking():
    """Review of P2: joining after ANY "." made "me." + an email one email
    ("me.ana.lopez@…": both lines blacked out) and hid "John Smith" after
    "Thank you.". Only a word that already holds "." or "@" continues."""
    L = lambda t, y: {"text": t, "x": 30.0, "y": y, "w": 330.0, "h": 30.0}  # noqa: E731
    pair = lambda a, b: [L(a, 72.0), L(b, 109.0)]  # noqa: E731
    assert picture.join_lines(pair("Please reply to me.", "ana.lopez@example.com"))[0] == "Please reply to me.\nana.lopez@example.com"
    assert picture.join_lines(pair("Thank you.", "John Smith"))[0] == "Thank you.\nJohn Smith"
    assert picture.join_lines(pair("Upgrade to 192.", "168.1.20 later"))[0] == "Upgrade to 192.\n168.1.20 later"
    assert picture.join_lines(pair("Write to ana.lopez.", "test@example-mail.com"))[0] == "Write to ana.lopez.test@example-mail.com"
    assert picture.join_lines(pair("Write to ana.lopez.test", "@example-mail.com"))[0] == "Write to ana.lopez.test@example-mail.com"


@pytest.mark.skipif(not ocr.available(), reason="needs macOS + Apple Vision")
def test_mirrored_text_in_a_photo_is_blacked_out(tmp_path, monkeypatch):
    """P1 (client test 2026-11-22): text mirrored in a photo (a selfie) reads as
    gibberish ("pggâє: yus rober"), so the email went out. A photo is also read
    flipped, and what is found there is blacked out at the mirrored spot."""
    import io

    from PIL import Image, ImageDraw, ImageFont, ImageOps

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    f = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 30)
    up = Image.new("RGB", (600, 800), (190, 170, 150))
    d = ImageDraw.Draw(up)
    d.text((30, 100), "Plan line: review the launch", fill="black", font=f)
    d.text((30, 460), "Contact: ana.lopez.test" + "@example-mail.com", fill="black", font=f)
    b = io.BytesIO()
    ImageOps.mirror(up).save(b, "JPEG", quality=90)
    out, st = Pipeline(MaskingSession()).mask_file(b.getvalue(), "image/jpeg")
    assert out[:3] == b"\xff\xd8\xff", "must stay a JPEG"
    back = Image.open(io.BytesIO(out))
    flipped = io.BytesIO()
    ImageOps.mirror(back).save(flipped, "PNG")
    read = " ".join(ln["text"] for ln in ocr.recognize(flipped.getvalue())["lines"])
    assert "example-mail" not in read and "lopez" not in read, read
    assert "Plan line" in read, "the rest of the picture must stay"
