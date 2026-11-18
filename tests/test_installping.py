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
