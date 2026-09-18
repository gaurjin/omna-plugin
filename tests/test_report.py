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


def test_report_by_app_counts():
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system", "app": "Google Chrome", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system", "app": "Google Chrome", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "deep", "app": "Claude", "masked": {}, "secrets": 0, "pii": 0})
    d = report.build(days=7)
    assert d["by_app"] == {"Google Chrome": 2, "Claude": 1}


def test_report_by_door_backward_compat():
    # New-format receipts: explicit door.
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system", "app": "Google Chrome", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "deep", "app": "Claude", "masked": {}, "secrets": 0, "pii": 0})
    # Old-format receipt: no "door" key and no "app" key at all (pre-Stage-2).
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "masked": {}, "secrets": 0, "pii": 0})
    d = report.build(days=7)
    assert d["requests"] == 3
    assert d["by_door"]["api"] == 1
    assert d["by_door"]["system"] == 1
    assert d["by_door"]["deep"] == 1
    assert "None" not in d["by_app"]
    assert "none" not in {k.lower() for k in d["by_app"]}
    assert len(d["by_app"]) == 2  # the door-less/app-less receipt contributes no key


def test_report_bypassed_count():
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system", "app": "Slack", "note": "bypassed-by-policy", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system", "app": "Slack", "note": "bypassed-by-policy", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system", "app": "Google Chrome", "masked": {}, "secrets": 0, "pii": 0})
    d = report.build(days=7)
    assert d["bypassed"] == 2


def test_report_refused_is_distinct_from_requests_refused():
    # Existing meaning: requests_refused counts "unparseable"/"mask-failed" notes.
    receipts.append({"route": "/v1/messages", "upstream": "api.openai.com", "status": 400, "masked": {}, "secrets": 0, "pii": 0, "note": "unparseable"})
    # New meaning: refused counts "tls-refused" notes, broken down by (app, host).
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "host": "api.anthropic.com", "status": 0, "door": "deep", "app": "Claude Desktop", "masked": {}, "secrets": 0, "pii": 0, "note": "tls-refused"})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "host": "api.anthropic.com", "status": 0, "door": "deep", "app": "Claude Desktop", "masked": {}, "secrets": 0, "pii": 0, "note": "tls-refused"})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "host": "api.anthropic.com", "status": 0, "door": "deep", "app": "Claude Desktop", "masked": {}, "secrets": 0, "pii": 0, "note": "tls-refused"})
    d = report.build(days=7)
    assert d["requests_refused"] == 1
    assert d["refused"]["count"] == 3
    assert d["refused"]["by_app_host"] == [{"app": "Claude Desktop", "host": "api.anthropic.com", "count": 3}]


def test_render_text_shows_apps_door_and_refused():
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system", "app": "Google Chrome", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "deep", "app": "Claude", "note": "bypassed-by-policy", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "host": "api.anthropic.com", "status": 0, "door": "deep", "app": "Claude Desktop", "masked": {}, "secrets": 0, "pii": 0, "note": "tls-refused"})
    d = report.build(days=7)
    text = report.render_text(d)
    assert "apps:" in text
    assert "Google Chrome" in text
    assert "refused:" in text
    assert "Claude Desktop" in text and "api.anthropic.com" in text
    assert "by door:" in text
    assert "system" in text and "deep" in text


def test_render_html_shows_apps_and_door_and_stays_safe():
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system", "app": "Google Chrome", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "host": "api.anthropic.com", "status": 0, "door": "deep", "app": "Claude Desktop", "masked": {}, "secrets": 0, "pii": 0, "note": "tls-refused"})
    d = report.build(days=7)
    page = report.render_html(d)
    assert "Google Chrome" in page
    assert "Claude Desktop" in page
    assert "system" in page and "door" in page.lower()
    assert "@" not in page
