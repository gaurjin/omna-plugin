"""The install/uninstall count: what it sends, when, and how to turn it off."""

import httpx
import pytest

from omna_plugin import installping


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    monkeypatch.delenv("OMNA_NO_TELEMETRY", raising=False)
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    return tmp_path


@pytest.fixture
def wire(monkeypatch):
    calls = []

    def fake(url, json=None, timeout=None, headers=None):
        calls.append({"url": url, "json": json})
        return httpx.Response(200, request=httpx.Request("POST", url))

    monkeypatch.setattr(installping.httpx, "post", fake)
    return calls


def test_install_sends_only_the_four_fields(home, wire):
    assert installping.send_install() is True
    assert len(wire) == 1
    body = wire[0]["json"]
    assert set(body) == {"device_id", "event", "version", "source"}
    assert body["event"] == "install" and body["source"] == "cli"
    assert wire[0]["url"] == "https://omna.dev/api/public/telemetry"
    assert (home / "install_id").read_text().strip() == body["device_id"]


def test_running_init_again_does_not_count_again(home, wire):
    installping.send_install()
    assert installping.send_install() is False
    assert len(wire) == 1


def test_uninstall_reuses_the_install_id(home, wire):
    installping.send_install()
    installping.send_uninstall()
    assert wire[1]["json"]["event"] == "uninstall"
    assert wire[1]["json"]["device_id"] == wire[0]["json"]["device_id"]


def test_uninstall_without_an_install_id_still_counts(home, wire):
    assert installping.send_uninstall() is True
    assert wire[0]["json"]["event"] == "uninstall"


@pytest.mark.parametrize("name", ["OMNA_NO_TELEMETRY", "DO_NOT_TRACK"])
def test_opt_out_sends_nothing(home, wire, monkeypatch, name):
    monkeypatch.setenv(name, "1")
    assert installping.send_install() is False
    assert installping.send_uninstall() is False
    assert wire == []
    assert not (home / "install_id").exists()


def test_network_failure_is_silent(home, monkeypatch):
    def boom(*a, **k):
        raise httpx.ConnectError("offline")

    monkeypatch.setattr(installping.httpx, "post", boom)
    assert installping.send_install() is False
    assert installping.send_uninstall() is False


# ---- daily usage (owner decision 2026-11-21: counts by type, once a day; never values) ----

from omna_plugin import receipts


def _rec(day, masked, product="curl", door="api"):
    receipts.append({"v": receipts.FORMAT, "product": product, "door": door, "ts": f"{day}T10:00:00-0500",
                     "masked": masked, "finds": []})


def test_daily_sends_counts_only_for_days_with_use(home, wire):
    installping.send_install()
    _rec("2026-11-20", {"EMAIL": 2, "API_KEY": 1})
    _rec("2026-11-20", {"EMAIL": 3})
    _rec("2026-11-21", {})                         # used, nothing to mask: still a day of use
    sent = installping.send_daily(today="2026-11-21")
    assert sent == 2
    daily = [c["json"] for c in wire if c["json"]["event"] == "daily_active"]
    by_day = {b["day"]: b for b in daily}
    assert by_day["2026-11-20"]["counts"] == {"EMAIL": 5, "API_KEY": 1}
    assert by_day["2026-11-21"]["counts"] == {}
    for b in daily:
        assert set(b) == {"device_id", "event", "version", "source", "day", "counts"}
        assert b["device_id"] == wire[0]["json"]["device_id"] and b["source"] == "cli"


def test_daily_ignores_chrome_and_control_records(home, wire):
    _rec("2026-11-21", {"EMAIL": 9}, product="chrome", door="chrome")
    _rec("2026-11-21", {}, door="control")
    assert installping.send_daily(today="2026-11-21") == 0
    assert wire == []


def test_daily_does_not_resend_the_same_numbers(home, wire):
    _rec("2026-11-21", {"EMAIL": 1})
    assert installping.send_daily(today="2026-11-21") == 1
    assert installping.send_daily(today="2026-11-21") == 0      # nothing new
    _rec("2026-11-21", {"EMAIL": 1})
    assert installping.send_daily(today="2026-11-21") == 1      # the day grew: send the new total
    assert wire[-1]["json"]["counts"] == {"EMAIL": 2}


@pytest.mark.parametrize("name", ["OMNA_NO_TELEMETRY", "DO_NOT_TRACK"])
def test_daily_opt_out_sends_nothing(home, wire, monkeypatch, name):
    _rec("2026-11-21", {"EMAIL": 1})
    monkeypatch.setenv(name, "1")
    assert installping.send_daily(today="2026-11-21") == 0
    assert wire == []


def test_daily_loop_never_starts_when_counting_is_off(home, monkeypatch):
    import threading
    monkeypatch.setenv("OMNA_NO_TELEMETRY", "1")
    before = {t.name for t in threading.enumerate()}
    installping.start_daily_loop(first_delay=0)
    assert "omna-daily-count" not in {t.name for t in threading.enumerate()} - before
