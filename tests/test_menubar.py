from PIL import Image

from omna_plugin import menubar
from omna_plugin.mac import app_bundle, launchd


def test_status_lines_not_running():
    assert menubar.status_lines(None) == ["Omna: OFF · click to resume", "omna start -d (or click above)"]


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


def test_confirm_and_uninstall_non_darwin_never_shells_out(monkeypatch, capsys):
    monkeypatch.setattr(menubar.sys, "platform", "linux")
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda *a, **k: calls.append(a))
    menubar._confirm_and_uninstall()
    assert calls == []
    assert "omna uninstall" in capsys.readouterr().out


def test_confirm_and_uninstall_darwin_cancel_runs_only_the_dialog(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []

    class R:
        stdout = b"button returned:Cancel"

    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd) or R())
    menubar._confirm_and_uninstall()
    assert len(calls) == 1


def test_confirm_and_uninstall_darwin_confirm_opens_terminal(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []

    class R:
        stdout = b"button returned:Uninstall"

    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd) or R())
    menubar._confirm_and_uninstall()
    assert len(calls) == 2
    assert "omna uninstall" in calls[1][2]


def test_toggle_masking_running_pauses_via_cli_stop_and_sets_paused_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    state = {"paused": False}
    menubar._toggle_masking({"doors": {}}, state)
    assert calls == [["omna", "stop"]]
    assert state["paused"] is True


def test_toggle_masking_not_running_resumes_via_cli_start_and_clears_paused_flag(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    state = {"paused": True}
    menubar._toggle_masking(None, state)
    assert calls == [["omna", "start", "-d"]]
    assert state["paused"] is False


def test_ensure_daemon_calls_omna_ensure_when_not_paused(monkeypatch):
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    menubar._ensure_daemon({"paused": False})
    assert calls == [["omna", "ensure"]]


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
