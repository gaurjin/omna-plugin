"""#41 (owner 2026-11-22): `omna status` is for a client — short, plain, no
fact said twice, never claims protection that is not there, fits 80 columns.
Wording from a fresh client read-through of the real screens. The full
technical screen is `omna status --details`."""
import time

import pytest

from omna_plugin import cli, pause, receipts
from omna_plugin.cli import main


def _h(**kw):
    base = {"ok": True, "smart": True, "smart_models": ["compact"], "restore_secrets": True,
            "requests_this_run": 0, "extension_last_seen": time.time() - 5, "extension_version": "1.1.0",
            "doors": {"api": True, "system": True, "deep": False}}
    base.update(kw)
    return base


@pytest.fixture
def mac(monkeypatch):
    monkeypatch.setattr(cli, "_health", lambda port: _h())
    monkeypatch.setattr(cli, "_mac_apps_route", lambda: ("Wi-Fi", True))
    monkeypatch.setattr(cli.claude_code, "status", lambda f: {"wired": True, "hook": True, "file": "x"})
    monkeypatch.setattr(cli.sys, "platform", "darwin")
    monkeypatch.setattr(cli.shutil, "which", lambda name: None)
    monkeypatch.setattr(cli.continue_dev, "detected", lambda: False)


def _out(capsys, *args):
    assert main(["status", *args]) == 0
    return capsys.readouterr().out


def test_all_covered_short_plain_and_fits_80_columns(mac, capsys):
    out = _out(capsys)
    lines = [l for l in out.splitlines() if l.strip()]
    assert lines[0] == "Omna is on — protecting everything below"
    assert len(lines) <= 12, out
    assert max(len(l) for l in out.splitlines()) <= 80, max(out.splitlines(), key=len)
    for jargon in ("doors:", "style:", "fingerprint", "registry:", "chrome link", "proxy:", "engine ", "values"):
        assert jargon not in out, jargon
    assert "✓  Claude Code" in out and "✓  Chrome" in out and "✓  Mac apps" in out
    from omna_plugin.proxy import __version__
    assert "omna status --details" in out and f"Omna {__version__}" in out.splitlines()[-1]


def test_no_fact_said_twice(mac, capsys):
    out = _out(capsys).lower()
    assert out.count("privacy filter") <= 1
    assert out.count("what leaves") + out.count("sends to ai") <= 1


def test_the_headline_names_what_is_not_protected(mac, monkeypatch, capsys):
    # #38: the owner's Wi-Fi had Mac-wide masking off; the headline said "is on".
    monkeypatch.setattr(cli, "_mac_apps_route", lambda: ("Wi-Fi", False))
    out = _out(capsys)
    assert out.splitlines()[0] == "Omna is on — but Mac apps are not protected"
    assert "✗  Mac apps" in out and "Not connected on Wi-Fi" in out and "Off on" not in out
    assert "To fix: omna init (asks for your Mac password)" in out


def test_nothing_covered_is_not_called_on(mac, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_health", lambda port: _h(extension_last_seen=None, doors={"api": True, "system": False}))
    monkeypatch.setattr(cli.claude_code, "status", lambda f: {"wired": False, "hook": False, "file": "x"})
    out = _out(capsys)
    assert out.splitlines()[0] == "Omna is running, but nothing is protected yet"
    # one fix line for both, naming every step that is really needed (read-through 2)
    assert out.count("omna init") == 1 and "omna stop && omna start -d" in out
    assert "Switched off in Omna" not in out


def test_chrome_not_connected_fits_and_says_both_cases(mac, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_health", lambda port: _h(extension_last_seen=None))
    out = _out(capsys)
    assert "Chrome" in out and "Not connected yet" in out and "chromewebstore.google.com" in out
    assert "✓  Chrome" not in out
    assert max(len(l) for l in out.splitlines()) <= 80


def test_off_says_so_and_claims_nothing(mac, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_health", lambda port: None)
    out = _out(capsys)
    assert out.splitlines()[0] == "Omna is OFF — nothing is masked"
    assert "exactly as you wrote it" in out and "Claude Code" in out and "omna start -d" in out
    monkeypatch.setattr(cli.claude_code, "status", lambda f: {"wired": False, "hook": False, "file": "x"})
    assert "Claude Code" not in _out(capsys)                 # never set up: it keeps working
    assert "only the masked message" not in out and "✓" not in out


def test_a_pause_that_is_over_is_not_shown_as_0_minutes(mac, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_health", lambda port: None)
    pause.begin("menubar", now=time.time() - 3600)          # 15-minute pause, an hour ago
    out = _out(capsys)
    assert "0 more minutes" not in out
    assert "pause ended at" in out and "menu-bar icon is not running" in out and "omna start -d" in out


def test_a_pause_says_it_comes_back_by_itself(mac, monkeypatch, capsys):
    monkeypatch.setattr(cli, "_health", lambda port: None)
    pause.begin("menubar")
    out = _out(capsys)
    assert out.splitlines()[0].startswith("Omna is paused for 15 more minutes")
    monkeypatch.setattr(cli, "_menu_bar_running", lambda: True)
    assert "turns back on by itself at" in _out(capsys)
    monkeypatch.setattr(cli, "_menu_bar_running", lambda: False)
    out = _out(capsys)
    assert "will not turn back on by itself" in out and "omna start -d" in out


def test_today_counts_each_private_detail_once(mac, capsys):
    from datetime import date
    today = date.today().isoformat() + "T10:00:00"
    f = lambda fps: [{"entity": "EMAIL", "n": len(fps), "fp": fps}]          # noqa: E731
    receipts.append({"ts": today, "app": "claude", "masked": {"EMAIL": 2}, "finds": f(["a1", "b2"])})
    receipts.append({"ts": today, "app": "claude", "masked": {"EMAIL": 2}, "finds": f(["a1", "b2"])})   # a long chat sends them again
    out = _out(capsys)
    assert "2 messages to AI" in out and "2 private details hidden" in out
    assert "refused" not in out


def test_proof_in_plain_words(mac, capsys):
    out = _out(capsys)
    assert "Nothing yet" in out                                   # no receipts
    receipts.append({"ts": "2026-11-21T10:00:00-0500", "masked": {}})
    out = _out(capsys)
    assert "none changed ✓" in out


def test_a_broken_proof_says_when_and_that_masking_still_works(mac, capsys):
    receipts.append({"ts": "2026-11-21T15:15:56-0500", "masked": {}})
    p = receipts.config.receipts_path()
    lines = p.read_text().splitlines()
    receipts.append({"ts": "2026-11-21T15:16:00-0500", "masked": {}})
    lines = p.read_text().splitlines()
    p.write_text("\n".join([lines[0], lines[0], lines[1], lines[1]]) + "\n")   # each written twice: #40
    out = _out(capsys)
    assert "⚠ 2 of 4 receipts don't check out" in out and "Nov 21, 3:15 PM" in out
    assert "All others do. Masking still works." in out and "broken" not in out
    assert max(len(l) for l in out.splitlines()) <= 80
    det = _out(capsys, "--details")
    assert "4 total, 2 don't check out" in det                       # both screens agree


def test_details_keeps_the_full_screen(mac, capsys):
    out = _out(capsys, "--details")
    assert "extension:" in out and "doors:" in out and "receipts:" in out


def test_init_turns_mac_apps_back_on(monkeypatch):
    from omna_plugin.policy import Policy
    pol = Policy.load(); pol.doors["system"] = False; pol.save()
    cli._system_door_on()
    assert Policy.load().doors["system"] is True


def test_privacy_filter_off_reads_as_normal(mac, capsys):
    out = _out(capsys)
    assert "Off (normal)" in out and "name-finder" not in out


def test_footer_says_content_never_reaches_omna(capsys, monkeypatch, tmp_path):
    """Owner decision G (2026-11-22): "Nothing goes to Omna" is untrue since the
    install count and daily counts go to omna.dev. The footer says what is true:
    the person's content never reaches Omna."""
    import inspect
    from omna_plugin import cli

    src = inspect.getsource(cli)
    assert "Nothing goes to Omna" not in src
    assert src.count("Your content never reaches Omna.") >= 2   # status and status --details
