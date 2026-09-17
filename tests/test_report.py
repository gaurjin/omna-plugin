import pytest

from omna_plugin import receipts, report


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


def test_report_aggregates_receipts():
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "stream": True, "masked": {"EMAIL": 2, "AWS_KEY": 1}, "secrets": 1, "pii": 2, "ms": 900, "mask_ms": 12, "tokens": ["EMAIL_1", "EMAIL_2", "SECRET_AWS_KEY_1"], "session": "s1"})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "stream": True, "masked": {}, "secrets": 0, "pii": 0, "ms": 300, "mask_ms": 4, "tokens": ["EMAIL_1", "SECRET_AWS_KEY_1"], "session": "s1"})
    receipts.append({"route": "/v1/chat/completions", "upstream": "api.openai.com", "status": 400, "stream": False, "masked": {}, "secrets": 0, "pii": 0, "ms": 5, "note": "unparseable"})
    d = report.build(days=7)
    assert d["requests"] == 3 and d["requests_ok"] == 2 and d["requests_refused"] == 1
    assert d["secrets_caught"] == 1 and d["pii_caught"] == 2
    assert d["distinct_secrets"] == 1 and d["distinct_pii"] == 2 and d["avg_mask_ms"] == 8
    assert d["by_kind"] == {"EMAIL": 2, "AWS_KEY": 1}
    assert d["by_upstream"] == {"api.anthropic.com": 2, "api.openai.com": 1}
    assert d["sessions"] == 1 and d["requests_with_catch"] == 1
    assert d["chain"]["intact"] is True and d["chain"]["receipts"] == 3
    text = report.render_text(d)
    assert "3 AI requests enabled" in text and "1 distinct secrets kept off the wire" in text and "INTACT" in text
    page = report.render_html(d)
    assert "<html" in page and "AWS_KEY" in page and "@" not in page


def test_report_on_empty_receipts():
    d = report.build(days=7)
    assert d["requests"] == 0 and d["by_kind"] == {}
    assert "no requests" in report.render_text(d)
