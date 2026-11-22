from PIL import Image

from omna_plugin import menubar
_real_stop_other_menu_bars = menubar.stop_other_menu_bars  # captured before conftest's guard patches it
from omna_plugin.mac import app_bundle, launchd

SELF = __import__('omna_plugin.config', fromlist=['x']).self_command()   # how the menu bar runs omna (#34)


def test_status_lines_not_running(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    assert menubar.status_lines(None) == ["Omna: OFF — NOT masking · click to resume",
                                          "Browsers and desktop apps go to the AI UNMASKED",
                                          "omna start -d (or click above)"]


def test_status_lines_api_door_only():
    h = {
        "doors": {"api": True, "system": False},
        "requests_this_run": 3,
        "distinct_secrets_this_run": 2,
        "distinct_pii_this_run": 5,
        "avg_mask_ms_this_run": 16,
    }
    lines = menubar.status_lines(h)
    assert lines[0] == "Omna: ON · click to pause"
    assert lines[1] == "Secrets kept off the wire: 2"
    assert lines[2] == "Personal values tokenized: 5"
    assert lines[3] == "Requests masked this session: 3"
    assert "coding tools only" in lines[4]
    assert lines[5] == "Masking overhead: 16 ms/request"


def test_status_lines_system_door_on():
    h = {"doors": {"api": True, "system": True}, "requests_this_run": 0}
    lines = menubar.status_lines(h)
    assert "every app on this Mac" in lines[4]


def test_status_lines_missing_doors_key_does_not_crash():
    assert menubar.status_lines({"requests_this_run": 1}) == [
        "Omna: ON · click to pause",
        "Secrets kept off the wire: 0",
        "Personal values tokenized: 0",
        "Requests masked this session: 1",
        "Covers: coding tools only (Claude Code etc.)",
        "Masking overhead: 0 ms/request",
    ]


def test_icon_image_size_and_mode():
    img = menubar._icon_image(True)
    assert img.size == Image.open(menubar.LOGO_PATH).size
    assert img.mode == "RGBA"


def test_icon_image_on_state_is_the_unmodified_logo():
    base = Image.open(menubar.LOGO_PATH).convert("RGBA")
    on = menubar._icon_image(True)
    assert on.tobytes() == base.tobytes()


def test_icon_image_off_state_adds_a_status_dot_without_recoloring_the_logo():
    w, h = Image.open(menubar.LOGO_PATH).size
    cx, cy = int(w * 0.78), int(h * 0.22)
    on = menubar._icon_image(True)
    off = menubar._icon_image(False)
    assert off.getpixel((cx, cy)) == menubar.OFF_DOT_COLOR
    assert on.getpixel((cx, cy)) != menubar.OFF_DOT_COLOR


class _FakeIcon:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


def test_confirm_and_uninstall_non_darwin_never_shells_out(monkeypatch, capsys):
    monkeypatch.setattr(menubar.sys, "platform", "linux")
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda *a, **k: calls.append(a))
    icon, state = _FakeIcon(), {"paused": False}
    menubar._confirm_and_uninstall(icon, state)
    assert calls == []
    assert "omna uninstall" in capsys.readouterr().out
    assert not icon.stopped


def test_confirm_and_uninstall_darwin_cancel_runs_only_the_dialog(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []

    class R:
        stdout = b"button returned:Cancel"

    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd) or R())
    icon, state = _FakeIcon(), {"paused": False}
    menubar._confirm_and_uninstall(icon, state)
    assert len(calls) == 1
    assert not icon.stopped
    assert state["paused"] is False


def test_confirm_and_uninstall_darwin_confirm_opens_terminal_then_stops_itself(monkeypatch):
    # Regression: this process's own crash-recovery poll loop must not be left
    # running to respawn the daemon `omna uninstall` (in the Terminal window it
    # just opened) is in the middle of wiping — belt (paused) and suspenders
    # (icon.stop(), which ends this whole process).
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []

    class R:
        stdout = b"button returned:Uninstall"

    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd) or R())
    icon, state = _FakeIcon(), {"paused": False}
    menubar._confirm_and_uninstall(icon, state)
    assert len(calls) == 2
    assert "omna uninstall" in calls[1][2]
    assert state["paused"] is True
    assert icon.stopped


def test_toggle_masking_running_pauses_via_cli_stop_and_sets_paused_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    state = {"paused": False}
    menubar._toggle_masking({"doors": {}}, state)
    assert calls == [SELF + ["stop"]]
    assert state["paused"] is True


def test_toggle_masking_not_running_resumes_via_cli_start_and_clears_paused_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    state = {"paused": True}
    menubar._toggle_masking(None, state)
    assert calls == [SELF + ["start", "-d"]]
    assert state["paused"] is False


def test_ensure_daemon_calls_omna_ensure_when_not_paused(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    menubar._ensure_daemon({"paused": False})
    assert calls == [SELF + ["ensure"]]


def test_ensure_daemon_does_nothing_when_paused(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    menubar._ensure_daemon({"paused": True})
    assert calls == []


def test_toggle_login_item_enables_when_currently_disabled(monkeypatch):
    calls = []
    monkeypatch.setattr(app_bundle, "login_item_enabled", lambda: False)
    monkeypatch.setattr(app_bundle, "enable_login_item", lambda: calls.append("enable"))
    monkeypatch.setattr(app_bundle, "disable_login_item", lambda: calls.append("disable"))
    menubar._toggle_login_item()
    assert calls == ["enable"]


def test_toggle_login_item_disables_when_currently_enabled(monkeypatch):
    calls = []
    monkeypatch.setattr(app_bundle, "login_item_enabled", lambda: True)
    monkeypatch.setattr(app_bundle, "enable_login_item", lambda: calls.append("enable"))
    monkeypatch.setattr(app_bundle, "disable_login_item", lambda: calls.append("disable"))
    menubar._toggle_login_item()
    assert calls == ["disable"]


def test_toggle_reports_flips_the_policy_flag(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    assert menubar._reports_enabled() is True  # default
    menubar._toggle_reports()
    assert menubar._reports_enabled() is False
    menubar._toggle_reports()
    assert menubar._reports_enabled() is True


def test_quit_darwin_unloads_its_own_launchd_job_before_stopping(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []
    monkeypatch.setattr(launchd, "bootout", lambda label: calls.append(("bootout", label)))

    class Icon:
        def stop(self_inner):
            calls.append("stop")

    menubar._quit(Icon())
    assert calls == [("bootout", launchd.MENUBAR_LABEL), "stop"]


def test_quit_non_darwin_just_stops_the_icon(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "linux")
    calls = []

    class Icon:
        def stop(self_inner):
            calls.append("stop")

    menubar._quit(Icon())
    assert calls == ["stop"]


def test_toggle_realistic_style_flips_the_policy_style(tmp_path, monkeypatch):
    """#143(a): switching the style used to need a terminal."""
    from omna_plugin.policy import Policy
    from omna_plugin.style import REALISTIC, TOKENS

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    assert Policy.load().style == TOKENS
    assert menubar._realistic_style() is False
    menubar._toggle_realistic_style()
    assert Policy.load().style == REALISTIC
    assert menubar._realistic_style() is True
    menubar._toggle_realistic_style()
    assert Policy.load().style == TOKENS
    assert menubar._realistic_style() is False


def test_the_icon_survives_its_file_vanishing_during_an_upgrade(monkeypatch, tmp_path):
    """#18 (client test 2026-11-21): reinstalling the curl command replaced its
    files while the menu-bar icon ran; the next redraw could not open the logo,
    the drawing thread died, and the icon vanished with no message."""
    from omna_plugin import menubar
    monkeypatch.setattr(menubar, "LOGO_PATH", tmp_path / "gone.png")
    img = menubar._icon_image(True)
    assert img.size[0] > 0


def test_menu_bar_runs_omna_by_full_path_not_by_name(monkeypatch):
    # #34 (2026-11-21): the menu bar is started by macOS at login, where PATH
    # does not include ~/.local/bin. ["omna", "ensure"] failed every 4 s with
    # "No such file or directory: 'omna'": the curl command was never brought
    # back after it went down, and the whole Mac lost its AI traffic.
    import os
    calls = []
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    monkeypatch.setattr(menubar.pause, "end", lambda *a, **k: None)
    monkeypatch.setattr(menubar.pause, "begin", lambda *a, **k: None, raising=False)
    menubar._ensure_daemon({"paused": False})
    menubar._resume({"paused": True}, "click")
    menubar._toggle_masking(None, {"paused": False})
    assert len(calls) == 3
    for cmd in calls:
        assert os.path.isabs(cmd[0]) and os.path.exists(cmd[0]), f"menu bar runs {cmd!r}: not a full path"


# ---------------------------------------------------------------- #35: no menu-bar icon after an upgrade
# Owner, 2026-11-21: no Omna icon in the menu bar, and clicking
# /Applications/Omna Plugin.app did nothing. The running menu bar came from a
# tool folder an upgrade had deleted; its poll thread died on its first error
# (FileNotFoundError 'omna'), so crash recovery stopped for good; and because
# it was still running, macOS only "activated" it on a click.

class _PollIcon:
    def __init__(self):
        self.icon = None
        self.title = ""

    def update_menu(self):
        pass


def test_one_error_never_ends_the_menu_bar_crash_recovery(monkeypatch):
    calls = []

    def flaky_ensure(state):
        calls.append(1)
        if len(calls) == 1:
            raise FileNotFoundError("omna")

    monkeypatch.setattr(menubar, "_health", lambda port: None)
    monkeypatch.setattr(menubar, "_ensure_daemon", flaky_ensure)
    naps = []

    def sleep(s):
        naps.append(s)
        if len(naps) == 3:
            raise SystemExit                 # end the test after three rounds

    try:
        menubar._poll_forever(_PollIcon(), {"paused": False}, 7788, sleep=sleep)
    except SystemExit:
        pass
    assert len(calls) == 3, f"crash recovery stopped after the first error ({len(calls)} round(s) ran)"


def test_a_new_menu_bar_replaces_an_old_one_still_running(monkeypatch):
    import os
    import signal
    me = os.getpid()
    listing = f"{me} /x/python -m omna_plugin.cli menubar\n1012 /old/python3.12 /old/bin/omna menubar\n77 /x/python -m omna_plugin.cli start --port 7788\n"
    comm = f"{me} /x/python\n1012 /old/python3.12\n77 /x/python\n"
    monkeypatch.setattr(menubar.subprocess, "run",
                        lambda cmd, **k: type("R", (), {"stdout": comm if "comm=" in cmd[-1] else listing, "returncode": 0})())
    sent = []
    monkeypatch.setattr(menubar.os, "kill", lambda pid, sig: sent.append((pid, sig)))
    _real_stop_other_menu_bars()
    assert (1012, signal.SIGTERM) in sent, "the old menu bar was left running"
    assert all(pid != me for pid, _ in sent), "it stopped itself"
    assert all(pid != 77 for pid, _ in sent), "it stopped the curl command (plugin/proxy) service — must never happen"



def test_closing_old_menu_bars_never_touches_unrelated_programs(monkeypatch):
    # Checker 2026-11-21: the pattern also matched editors and searches.
    import signal
    listing = "\n".join([
        "11 /Users/x/.local/share/uv/tools/omna-plugin/bin/python /Users/x/.local/share/uv/tools/omna-plugin/bin/omna menubar",
        "12 /Users/x/Omna Labs/omna-plugin/.venv/bin/python -m omna_plugin.cli menubar --port 7788",
        "21 vim /tmp/omna menubar notes",
        "22 grep /omna menubar",
        "23 rg omna_plugin.cli menubar src/",
        "24 python3 -c import omna_plugin.cli menubar",
        "25 /x/python -m omna_plugin.cli start --port 7788",
        "26 tail -f /Users/x/.omna/menubar.log",
        "27 less /bin/omna menubar",
        "28 sh -c echo python -m omna_plugin.cli menubar",
        "29 /usr/bin/vim /tmp/bin/omna menubar",
    ]) + "\n"
    # What program each process really is (ps comm): checker 2, 2026-11-21.
    programs = {"11": "/Users/x/.local/share/uv/tools/omna-plugin/bin/python", "12": "/Users/x/Omna Labs/omna-plugin/.venv/bin/python",
                "21": "vim", "22": "grep", "23": "rg", "24": "/usr/bin/python3", "25": "/x/python", "26": "tail",
                "27": "/usr/bin/less", "28": "/bin/sh", "29": "/usr/bin/vim"}
    comm = "".join(f"{k} {v}\n" for k, v in programs.items())
    monkeypatch.setattr(menubar.subprocess, "run",
                        lambda cmd, **k: type("R", (), {"stdout": comm if "comm=" in cmd[-1] else listing, "returncode": 0})())
    sent = []
    monkeypatch.setattr(menubar.os, "kill", lambda pid, sig: sent.append(pid))
    _real_stop_other_menu_bars()
    assert sorted(sent) == [11, 12], sent
