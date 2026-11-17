"""Muse QA B1 (2026-11-17): a bracketed IPv6 entry in NO_PROXY ("[::1]") made
httpx raise InvalidURL — `omna status` crashed, the installer exited 1 after a
good install, and the proxy could not open its connection to the AI provider."""

import httpx
import pytest

from omna_plugin import config


@pytest.mark.parametrize(
    "raw, want",
    [
        ("localhost,[::1]", "localhost,::1"),
        ("[fe80::1]:8080,.corp.com", "fe80::1,.corp.com"),
        ("::1/128,10.0.0.0/8", "::1,10.0.0.0/8"),
        ("[::1]/128", "::1"),
        ("localhost,127.0.0.1,.corp.com,*", "localhost,127.0.0.1,.corp.com,*"),
    ],
)
def test_no_proxy_is_tidied_so_httpx_can_read_it(monkeypatch, raw, want):
    for key in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(key, raw)
    config.tidy_no_proxy()
    for key in ("NO_PROXY", "no_proxy"):
        assert config.os.environ[key] == want
    httpx.Client().close()  # the crash Muse hit, now gone


def test_unset_no_proxy_stays_unset(monkeypatch):
    monkeypatch.delenv("NO_PROXY", raising=False)
    monkeypatch.delenv("no_proxy", raising=False)
    config.tidy_no_proxy()
    assert "NO_PROXY" not in config.os.environ and "no_proxy" not in config.os.environ


def test_status_survives_bracketed_ipv6(monkeypatch, capsys):
    from omna_plugin import cli

    monkeypatch.setenv("NO_PROXY", "localhost,[::1]")
    # Nothing listens on port 9: the health call must fail quietly, not crash.
    assert cli.main(["status", "--port", "9"]) == 0
