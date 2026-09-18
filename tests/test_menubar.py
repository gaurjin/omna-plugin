from PIL import Image

from omna_plugin import menubar
from omna_plugin.mac import launchd


def test_status_lines_not_running():
    assert menubar.status_lines(None) == ["Omna: NOT RUNNING", "→ Resume Omna below, or omna start -d"]


def test_status_lines_api_door_only():
    h = {"doors": {"api": True, "system": False}, "requests_this_run": 3}
    lines = menubar.status_lines(h)
    assert lines[0] == "Omna: ON"
    assert "coding tools only" in lines[1]
    assert "3" in lines[2]


def test_status_lines_system_door_on():
    h = {"doors": {"api": True, "system": True}, "requests_this_run": 0}
    lines = menubar.status_lines(h)
    assert "every app on this Mac" in lines[1]


def test_status_lines_missing_doors_key_does_not_crash():
    assert menubar.status_lines({"requests_this_run": 1}) == [
        "Omna: ON",
        "Covers: coding tools only (Claude Code etc.)",
        "Requests masked this session: 1",
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


def test_toggle_masking_darwin_running_pauses_via_bootout(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []
    monkeypatch.setattr(launchd, "bootout", lambda label: calls.append(("bootout", label)))
    monkeypatch.setattr(launchd, "bootstrap", lambda label: calls.append(("bootstrap", label)))
    menubar._toggle_masking({"doors": {}})
    assert calls == [("bootout", launchd.LABEL)]


def test_toggle_masking_darwin_not_running_resumes_via_bootstrap(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "darwin")
    calls = []
    monkeypatch.setattr(launchd, "bootout", lambda label: calls.append(("bootout", label)))
    monkeypatch.setattr(launchd, "bootstrap", lambda label: calls.append(("bootstrap", label)))
    menubar._toggle_masking(None)
    assert calls == [("bootstrap", launchd.LABEL)]


def test_toggle_masking_non_darwin_running_shells_out_to_stop(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "linux")
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    menubar._toggle_masking({"doors": {}})
    assert calls == [["omna", "stop"]]


def test_toggle_masking_non_darwin_not_running_shells_out_to_start_daemonized(monkeypatch):
    monkeypatch.setattr(menubar.sys, "platform", "linux")
    calls = []
    monkeypatch.setattr(menubar.subprocess, "run", lambda cmd, **k: calls.append(cmd))
    menubar._toggle_masking(None)
    assert calls == [["omna", "start", "-d"]]


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
