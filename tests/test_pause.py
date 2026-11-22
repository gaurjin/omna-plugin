"""Pause is loud, written down, and ends by itself.

Security review 2026-11-11, finding 16: Pause stops the proxy, and a browser
or desktop app then goes straight to the AI, unmasked. It showed a calm grey
dot, left nothing in the report, and lasted until somebody remembered. Owner
decision: red icon, report lines, automatic end after 15 minutes.
"""

from __future__ import annotations

import inspect

import pytest

from omna_plugin import menubar, pause, receipts, report
from omna_plugin.cli import main
from omna_plugin.policy import Policy

SELF = __import__('omna_plugin.config', fromlist=['x']).self_command()   # how the menu bar runs omna (#34)


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture
def cli_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    return calls


def _notes():
    return [r.get("note") for r in receipts.tail(0)]


def test_pausing_is_written_down_before_the_proxy_stops(cli_calls):
    state = {"paused": False}
    menubar._toggle_masking({"ok": True}, state)
    assert state["paused"] is True
    assert cli_calls == [SELF + ["stop"]]
    assert _notes() == ["protection-paused"]
    rec = receipts.tail(1)[0]
    assert rec["door"] == "control" and rec["auto_end_seconds"] == 15 * 60
    st = pause.state()
    assert st["by"] == "menubar" and st["until"] - st["since"] == 15 * 60


def test_a_pause_ends_by_itself_after_15_minutes(cli_calls, monkeypatch):
    state = {"paused": False}
    menubar._toggle_masking({"ok": True}, state)
    since = pause.state()["since"]
    monkeypatch.setattr(pause.time, "time", lambda: since + 14 * 60)
    assert menubar._end_pause_if_over(state) is False and state["paused"] is True
    monkeypatch.setattr(pause.time, "time", lambda: since + 15 * 60 + 1)
    assert menubar._end_pause_if_over(state) is True
    assert state["paused"] is False and cli_calls[-1] == SELF + ["start", "-d"]
    assert _notes() == ["protection-paused", "protection-resumed"]
    rec = receipts.tail(1)[0]
    assert rec["why"] == "auto" and rec["off_seconds"] == 15 * 60 + 1
    assert pause.state() is None


def test_clicking_resume_ends_it_early_and_says_how_long_it_was_off(cli_calls, monkeypatch):
    state = {"paused": False}
    menubar._toggle_masking({"ok": True}, state)
    since = pause.state()["since"]
    monkeypatch.setattr(pause.time, "time", lambda: since + 120)
    menubar._toggle_masking(None, state)
    rec = receipts.tail(1)[0]
    assert rec["note"] == "protection-resumed" and rec["why"] == "click" and rec["off_seconds"] == 120


def test_the_menu_says_not_masking_in_plain_words_while_paused(cli_calls):
    menubar._toggle_masking({"ok": True}, {"paused": False})
    lines = menubar.status_lines(None)
    assert lines[0] == "Omna: PAUSED — NOT masking · click to resume"
    assert "UNMASKED" in lines[1] and "Resumes by itself in 15 min" in lines[3]


def test_the_off_dot_is_red():
    r, g, b, _ = menubar.OFF_DOT_COLOR
    assert r > 200 and g < 80 and b < 80


def test_the_wrong_comment_is_gone():
    doc = inspect.getdoc(menubar._toggle_masking)
    assert "nothing is ever forwarded unmasked" not in doc.replace("\n", " ").split("(This comment used to say")[0]
    assert "UNMASKED" in doc


def test_a_pause_survives_the_menu_bar_being_reopened(cli_calls):
    menubar._toggle_masking({"ok": True}, {"paused": False})
    st = pause.state()                     # what a freshly started menu bar reads
    assert st and st["by"] == "menubar"


def test_omna_stop_is_written_down_and_start_closes_it(monkeypatch, capsys, home):
    from omna_plugin import config

    config.ensure_home()
    config.pid_path().write_text("999999")
    monkeypatch.setattr("os.kill", lambda pid, sig: None)
    assert main(["stop"]) == 0
    assert "UNMASKED" in capsys.readouterr()[0]
    assert _notes() == ["protection-stopped"] and pause.state()["until"] == 0
    assert pause.expired() is False, "a plain stop has no automatic end"
    assert "STOPPED on purpose" in pause.status_line()
    monkeypatch.setattr("omna_plugin.cli._who_answers", lambda port: None)
    monkeypatch.setattr("omna_plugin.cli._pair_chrome", lambda quiet=False: None)
    monkeypatch.setattr("omna_plugin.cli._spawn", lambda port, smart, no_restore_secrets=False: 4243)
    monkeypatch.setattr("omna_plugin.cli._wait_healthy", lambda port, seconds: {"engine": "x"})
    assert main(["start", "-d"]) == 0
    assert _notes() == ["protection-stopped", "protection-resumed"] and pause.state() is None


def test_status_names_the_pause_and_the_minutes_left(cli_calls, monkeypatch, capsys):
    menubar._toggle_masking({"ok": True}, {"paused": False})
    monkeypatch.setattr("omna_plugin.cli._health", lambda port: None)
    main(["status", "--details"])
    out = capsys.readouterr()[0]
    assert "PAUSED" in out and "UNMASKED" in out and "Resumes by itself in 15 min" in out


def test_the_report_counts_the_time_protection_was_off_and_not_as_requests(cli_calls, monkeypatch):
    receipts.append({"door": "api", "route": "/v1/messages", "host": "x", "status": 200, "masked": {}, "ms": 5})
    state = {"paused": False}
    menubar._toggle_masking({"ok": True}, state)
    since = pause.state()["since"]
    monkeypatch.setattr(pause.time, "time", lambda: since + 9 * 60)
    menubar._toggle_masking(None, state)
    d = report.build(7)
    assert d["requests"] == 1, "a pause is not an AI request"
    assert d["protection_off_times"] == 1 and d["protection_off_seconds"] == 9 * 60
    text = report.render_text(d)
    assert "PROTECTION OFF: paused or stopped 1 time(s), about 9 min in total" in text
    assert "PROTECTION OFF" in report.render_html(d)
    assert receipts.verify()[0]


def test_a_quiet_period_says_so(home):
    receipts.append({"door": "api", "route": "/v1/messages", "host": "x", "status": 200, "masked": {}, "ms": 5})
    assert "masking was never paused or stopped" in report.render_text(report.build(7))


def test_nothing_is_recorded_when_local_reports_are_off(cli_calls):
    pol = Policy.load()
    pol.reports_enabled = False
    pol.save()
    menubar._toggle_masking({"ok": True}, {"paused": False})
    assert receipts.count() == 0 and pause.state() is not None      # still paused, still ends by itself


def test_two_ends_at_once_write_one_resumed_receipt(tmp_path, monkeypatch):
    # #40: two processes ended the same pause; both wrote "protection-resumed".
    from omna_plugin import pause
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    written = []
    monkeypatch.setattr(pause, "_record", lambda note, **kw: written.append(note))
    pause.begin("stop", now=100.0)
    written.clear()                                       # only the ends count here
    have = pause.state()
    monkeypatch.setattr(pause, "state", lambda: have)     # both saw the note before either removed it
    assert pause.end("start", now=105.0) is True
    assert pause.end("start", now=105.0) is False
    assert written == [pause.NOTE_RESUMED]


def test_real_processes_racing_write_one_receipt_each_way(tmp_path):
    # Checker 2026-11-22 (#40): on APFS two processes deleting the same file can
    # BOTH be told "deleted", so 12% of real races wrote two "resumed"
    # receipts; and begin()'s shared temp file crashed one of two stoppers.
    import os
    import subprocess
    import sys
    env = {**os.environ, "OMNA_HOME": str(tmp_path), "OMNA_REGISTRY_ENCRYPTION": "off", "OMNA_NO_TELEMETRY": "1"}
    code = ("import sys, time\nfrom omna_plugin import pause\n"
            "go = float(sys.argv[2])\n"
            "while time.time() < go: pass\n"
            "getattr(pause, sys.argv[1])('stop' if sys.argv[1] == 'begin' else 'start')\n")
    rounds = 25
    for _ in range(rounds):
        import time as _t
        for what in ("begin", "end"):
            go = str(_t.time() + 0.4)
            ps = [subprocess.Popen([sys.executable, "-c", code, what, go], env=env, stderr=subprocess.PIPE) for _ in range(4)]
            errs = [p.communicate(timeout=30)[1] for p in ps]
            assert all(p.returncode == 0 for p in ps), errs
    out = subprocess.run([sys.executable, "-c",
                          "from omna_plugin import receipts\n"
                          "rs = receipts.tail(0)\n"
                          "print(sum(r.get('note') == 'protection-stopped' for r in rs), sum(r.get('note') == 'protection-resumed' for r in rs))"],
                         env=env, capture_output=True, text=True).stdout.split()
    assert out == [str(rounds), str(rounds)], out


def test_a_late_end_records_the_pause_it_really_ended(tmp_path, monkeypatch):
    # Checker 2026-11-22 (#40 problem A): end() read the note, another process
    # ended that pause and a new stop began, then end() claimed the NEW one but
    # wrote the old one's length.
    from omna_plugin import pause
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    written = []
    monkeypatch.setattr(pause, "_record", lambda note, **kw: written.append((note, kw)))
    pause.begin("stop", now=100.0)
    stale = pause.state()                              # A reads: since 100
    assert pause.end("start", now=150.0)               # B ends it
    pause.begin("stop", now=700.0)                     # C stops again
    written.clear()
    monkeypatch.setattr(pause, "state", lambda: stale) # A goes on with what it read
    assert pause.end("start", now=710.0)
    assert written == [(pause.NOTE_RESUMED, {"off_seconds": 10, "why": "start"})], written


def test_an_unreadable_note_is_replaced_not_kept(tmp_path, monkeypatch):
    # #43 checker 2026-11-22: a corrupt paused.json made begin() return a pause
    # it never saved, so the menu bar undid `omna stop` within seconds.
    from omna_plugin import pause
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    pause.path().parent.mkdir(parents=True, exist_ok=True)
    pause.path().write_text("{")
    pause.begin("stop", now=500.0)
    assert pause.state() is not None and pause.state()["since"] == 500.0
