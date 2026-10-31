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
