from omna_plugin import menubar


def test_status_lines_not_running():
    assert menubar.status_lines(None) == ["Omna: NOT RUNNING", "→ omna start -d"]


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
    assert img.size == (64, 64)
    assert img.mode == "RGBA"


def test_icon_image_color_reflects_on_state():
    on = menubar._icon_image(True).getpixel((32, 32))
    off = menubar._icon_image(False).getpixel((32, 32))
    assert on == menubar.ON_COLOR
    assert off == menubar.OFF_COLOR
    assert on != off


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
