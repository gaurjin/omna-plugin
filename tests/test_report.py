import pytest

from omna_plugin import receipts, report
from omna_plugin.policy import Policy


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
    assert "Claude 1 (bypassed)" in text   # per-app bypass tag, not just a global count
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


def test_render_html_escapes_a_hostile_app_or_host_name():
    # A malicious/renamed app or host string must never break out of its <td>.
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "door": "system",
                     "app": "<script>evil</script>", "masked": {}, "secrets": 0, "pii": 0})
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "host": "<img src=x onerror=evil()>",
                     "status": 0, "door": "deep", "app": "Claude Desktop", "masked": {}, "secrets": 0, "pii": 0,
                     "note": "tls-refused"})
    d = report.build(days=7)
    page = report.render_html(d)
    assert "<script>evil</script>" not in page
    assert "&lt;script&gt;evil&lt;/script&gt;" in page
    assert "<img src=x onerror=evil()>" not in page
    assert "&lt;img src=x onerror=evil()&gt;" in page


# ------------------------------------------------- company rollup (share/merge)
def _share(org="Acme Inc", dept="engineering", device="dev1", generated="2026-09-20 10:00", **over):
    base = {
        "format": "omna-share-1", "org": org, "dept": dept, "device_id": device,
        "generated": generated, "period_days": 7, "since": "2026-09-13",
        "requests": 10, "requests_ok": 9, "requests_refused": 1, "requests_failed": 0,
        "requests_with_catch": 4, "sessions": 2,
        "secrets_caught": 3, "pii_caught": 5, "distinct_secrets": 2, "distinct_pii": 4,
        "bypassed": 0, "by_kind": {"EMAIL": 5}, "by_day": {"2026-09-19": 10},
        "by_door": {"api": 10},
    }
    base.update(over)
    return base


def test_share_carries_counts_and_the_org_tags():
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "masked": {"EMAIL": 2}, "secrets": 0, "pii": 2, "ms": 10, "mask_ms": 2, "tokens": ["EMAIL_1", "EMAIL_2"]})
    pol = Policy.load()
    pol.enroll(org="Acme Inc", dept="engineering")
    pol.save()
    s = report.share(report.build(days=7))
    assert s["format"] == "omna-share-1"
    assert s["org"] == "Acme Inc" and s["dept"] == "engineering" and s["device_id"]
    assert s["requests"] == 1 and s["pii_caught"] == 2 and s["by_kind"] == {"EMAIL": 2}


def test_share_drops_every_field_that_could_identify_the_person():
    # The whole point of the export is that it can be handed to an admin. A new
    # key added to build() later must NOT ride along by default — share() is an
    # allowlist, and this test is what keeps it one.
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "masked": {"EMAIL": 1}, "secrets": 0, "pii": 1, "ms": 10, "mask_ms": 2, "app": "Cursor", "tokens": ["EMAIL_1"]})
    d = report.build(days=7)
    d["secret_new_field"] = "/Users/someone/private"     # pretend a future key
    s = report.share(d)
    assert "home" not in s, "the home path carries the username"
    assert "by_app" not in s, "which apps someone runs is not the company's business"
    assert "by_upstream" not in s
    assert "secret_new_field" not in s, "share() must be an allowlist, not a blocklist"
    blob = report.to_json(s)
    assert "/Users/" not in blob and "Cursor" not in blob


def test_merge_totals_company_and_departments():
    m = report.merge([
        _share(dept="engineering", device="d1"),
        _share(dept="engineering", device="d2"),
        _share(dept="sales", device="d3", requests=4, secrets_caught=1, pii_caught=2),
    ])
    assert m["devices"] == 3
    assert m["company"]["requests"] == 24 and m["company"]["secrets_caught"] == 7
    assert m["departments"]["engineering"]["devices"] == 2
    assert m["departments"]["engineering"]["requests"] == 20
    assert m["departments"]["sales"]["requests"] == 4
    text = report.render_merge_text(m)
    assert "engineering" in text and "sales" in text and "Acme Inc" in text


def test_merge_counts_the_same_device_once_keeping_the_newer_file():
    # An admin collecting the same machine's export twice must not double the
    # company's numbers — a plausible-looking wrong total nobody would catch.
    m = report.merge([
        _share(device="d1", generated="2026-09-19 10:00", requests=10),
        _share(device="d1", generated="2026-09-20 10:00", requests=99),
        _share(device="d2", requests=1),
    ])
    assert m["devices"] == 2 and m["duplicates_dropped"] == 1
    assert m["company"]["requests"] == 100, "newer file wins, older is dropped entirely"


def test_merge_keeps_unenrolled_machines_but_cannot_dedupe_them():
    m = report.merge([_share(device="", org="", dept=""), _share(device="", org="", dept="")])
    assert m["devices"] == 2
    assert m["departments"]["(no department)"]["devices"] == 2


def test_merge_refuses_a_plain_json_report_with_a_clear_message():
    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "masked": {}, "ms": 1})
    with pytest.raises(ValueError, match="not Omna share exports"):
        report.merge([report.build(days=7)])
