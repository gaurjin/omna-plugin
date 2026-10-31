"""PDFs through the curl command: values blacked out INSIDE the PDF.

Only pages holding a found value change: each becomes a picture of itself
with those values painted over, so nothing hidden can be copied back out.
Other pages stay byte-for-byte the same page. Fake data only.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from omna_plugin import ocr, pdf
from omna_plugin.engine import MaskingSession
from omna_plugin.pipeline import Pipeline

FIX = Path(__file__).parent / "fixtures"
REVIEW = (FIX / "fake-review.pdf").read_bytes()
CLEAN = (FIX / "fake-clean.pdf").read_bytes()
mac = pytest.mark.skipif(not pdf.available(), reason="needs macOS PDFKit")


def test_pipeline_labels_a_pdf_not_masked_when_it_cannot_be_done(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    monkeypatch.setattr(pdf, "redact", lambda data, detect: None)
    out, st = Pipeline(MaskingSession()).mask_file(REVIEW, "application/pdf")
    assert out == REVIEW and st.not_masked == "pdf"


@mac
def test_values_are_gone_and_clean_pages_keep_their_text(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    out, st = Pipeline(MaskingSession()).mask_file(REVIEW, "application/pdf")
    assert out.startswith(b"%PDF"), "must stay a PDF"
    assert st.counts and not st.not_masked
    pages = pdf.page_texts(out)
    assert len(pages) == 2
    joined = " ".join(pages)
    for value in ("maria.gonzalez@acmecorp-test.com", "415-555-0137", "AKIAIOSFODNN7EXAMPLE"):
        assert value not in joined, f"{value} still copyable"
    assert "Nothing sensitive here" in pages[1], "a page without values keeps its text"


@mac
@pytest.mark.skipif(not ocr.available(), reason="needs Apple Vision to look at the picture")
def test_the_painted_page_does_not_show_the_values(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    out, _ = Pipeline(MaskingSession()).mask_file(REVIEW, "application/pdf")
    seen = " ".join(l["text"] for l in ocr.recognize(pdf.render_page_png(out, 0))["lines"])
    for value in ("maria.gonzalez", "415-555-0137", "AKIAIOSFODNN"):
        assert value not in seen, f"{value} still visible on the page"
    assert "Vendor review" in seen and "rotate after the review" in seen, "the rest of the page stays readable"


@mac
def test_a_pdf_with_nothing_sensitive_goes_exactly_as_it_is(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    out, st = Pipeline(MaskingSession()).mask_file(CLEAN, "application/pdf")
    assert out == CLEAN and not st.counts and not st.not_masked


@mac
def test_same_size_sites_get_the_same_size_or_a_refusal(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    out, _ = Pipeline(MaskingSession()).mask_file_same_size(REVIEW, "application/pdf")
    assert out is None or len(out) == len(REVIEW)


@mac
def test_unreadable_or_locked_pdf_is_not_pretended_masked():
    assert pdf.redact(b"%PDF-1.4 garbage", lambda t: []) is None
