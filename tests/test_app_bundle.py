import os
from pathlib import Path

from omna_plugin.mac import app_bundle


def test_app_name_is_distinct_from_the_native_mac_app():
    # The native Mac app owns /Applications/Omna.app; this wrapper must never
    # collide with or overwrite it.
    assert app_bundle.APP_PATH.name != "Omna.app"
    assert str(app_bundle.APP_PATH) == "/Applications/Omna Plugin.app"


def test_install_writes_a_launchable_bundle(tmp_path):
    dest = tmp_path / "Omna Plugin.app"
    log = tmp_path / "menubar.log"
    out = app_bundle.install(Path("/usr/local/bin/omna"), dest=dest, log=log)

    assert out == dest
    plist = (dest / "Contents" / "Info.plist").read_text()
    assert "<key>LSUIElement</key><true/>" in plist
    assert app_bundle.BUNDLE_ID in plist

    launcher = dest / "Contents" / "MacOS" / app_bundle.BIN_NAME
    script = launcher.read_text()
    assert "/usr/local/bin/omna" in script
    assert "menubar" in script
    assert launcher.stat().st_mode & 0o111  # executable


def test_install_redirects_the_launcher_output_to_the_menubar_log(tmp_path):
    # A login item has no launchd StandardOutPath/StandardErrorPath to capture
    # output for us, so the launcher script must redirect it itself.
    dest = tmp_path / "Omna Plugin.app"
    log = tmp_path / "menubar.log"
    app_bundle.install(Path("/usr/local/bin/omna"), dest=dest, log=log)

    script = (dest / "Contents" / "MacOS" / app_bundle.BIN_NAME).read_text()
    assert str(log) in script
    assert ">>" in script


def test_install_wires_the_icon_into_info_plist_and_copies_it_into_resources(tmp_path):
    dest = tmp_path / "Omna Plugin.app"
    app_bundle.install(Path("/usr/local/bin/omna"), dest=dest)

    plist = (dest / "Contents" / "Info.plist").read_text()
    assert f"<key>CFBundleIconFile</key><string>{app_bundle.ICON_NAME}</string>" in plist

    icon = dest / "Contents" / "Resources" / f"{app_bundle.ICON_NAME}.icns"
    assert icon.exists()
    assert icon.read_bytes() == app_bundle.ICON_SRC.read_bytes()


def test_install_is_idempotent(tmp_path):
    dest = tmp_path / "Omna Plugin.app"
    app_bundle.install(Path("/usr/local/bin/omna"), dest=dest)
    app_bundle.install(Path("/usr/local/bin/omna"), dest=dest)  # must not raise
    assert dest.exists()


def test_remove_deletes_the_bundle(tmp_path):
    dest = tmp_path / "Omna Plugin.app"
    app_bundle.install(Path("/usr/local/bin/omna"), dest=dest)
    app_bundle.remove(dest)
    assert not dest.exists()


def test_remove_on_a_missing_bundle_does_not_raise(tmp_path):
    app_bundle.remove(tmp_path / "does-not-exist.app")  # no error


def test_login_item_enabled_reads_the_flag_file(monkeypatch, tmp_path):
    monkeypatch.setattr(app_bundle.config, "home", lambda: tmp_path)
    assert app_bundle.login_item_enabled() is False
    (tmp_path / app_bundle.LOGIN_ITEM_FLAG).touch()
    assert app_bundle.login_item_enabled() is True


def test_enable_login_item_calls_osascript_and_writes_the_flag(monkeypatch, tmp_path):
    monkeypatch.setattr(app_bundle.config, "home", lambda: tmp_path)
    tmp_path.mkdir(exist_ok=True)
    calls = []
    monkeypatch.setattr(app_bundle.subprocess, "run", lambda cmd, **k: calls.append(cmd))

    app_bundle.enable_login_item(app_path=Path("/Applications/Omna Plugin.app"))

    assert len(calls) == 1
    assert "System Events" in calls[0][2]
    assert "/Applications/Omna Plugin.app" in calls[0][2]
    assert (tmp_path / app_bundle.LOGIN_ITEM_FLAG).exists()


def test_disable_login_item_calls_osascript_and_removes_the_flag(monkeypatch, tmp_path):
    monkeypatch.setattr(app_bundle.config, "home", lambda: tmp_path)
    (tmp_path / app_bundle.LOGIN_ITEM_FLAG).touch()
    calls = []
    monkeypatch.setattr(app_bundle.subprocess, "run", lambda cmd, **k: calls.append(cmd))

    app_bundle.disable_login_item()

    assert len(calls) == 1
    assert "System Events" in calls[0][2]
    assert not (tmp_path / app_bundle.LOGIN_ITEM_FLAG).exists()


# #35 (2026-11-21, tested on macOS 27.2.1 with 13 variants): macOS shows a
# menu-bar icon from an app only when the running program IS the app's main
# program file. Any hand-over (a shell script or compiled launcher that execs
# another program, even one inside the app) left no icon. So the app's main
# program is a copy of the curl command's own Python.
def _python_app(tmp_path):
    py = tmp_path / "cpython" / "bin" / "python3.14"
    py.parent.mkdir(parents=True)
    py.write_bytes(b"\xcf\xfa\xed\xfe fake python")
    os.chmod(py, 0o755)
    tool = tmp_path / "tool"
    sp = tool / "lib" / "python3.14" / "site-packages"
    sp.mkdir(parents=True)
    (tool / "pyvenv.cfg").write_text("home = /x/cpython-3.14/bin\nversion_info = 3.14.10\n")
    dest = tmp_path / "Omna Plugin.app"
    app_bundle.install(Path("/usr/local/bin/omna"), dest=dest, log=tmp_path / "m.log",
                       python=py, tool_prefix=tool, site_packages=sp, py_version="3.14")
    return dest, py, tool, sp


def test_the_apps_main_program_is_python_itself(tmp_path):
    dest, py, tool, sp = _python_app(tmp_path)
    plist = (dest / "Contents" / "Info.plist").read_text()
    assert f"<key>CFBundleExecutable</key><string>{app_bundle.PY_NAME}</string>" in plist
    main = dest / "Contents" / "MacOS" / app_bundle.PY_NAME
    assert main.read_bytes() == py.read_bytes() and not main.is_symlink()
    assert main.stat().st_mode & 0o111
    assert sorted(p.name for p in (dest / "Contents" / "MacOS").iterdir()) == [app_bundle.PY_NAME]
    assert (dest / "Contents" / "pyvenv.cfg").read_text() == (tool / "pyvenv.cfg").read_text()
    here = dest / "Contents" / "lib" / "python3.14" / "site-packages"
    pths = sorted(p.name for p in here.glob("*.pth"))
    assert len(pths) == 2
    assert (here / pths[0]).read_text().strip() == str(sp)          # the installed code, first
    assert (here / pths[1]).read_text().strip() == "import omna_plugin.mac.app_boot"


def test_reinstalling_over_an_old_shell_launcher_removes_it(tmp_path):
    dest = tmp_path / "Omna Plugin.app"
    app_bundle.install(Path("/usr/local/bin/omna"), dest=dest, log=tmp_path / "m.log")
    assert (dest / "Contents" / "MacOS" / app_bundle.BIN_NAME).exists()
    dest2, *_ = _python_app(tmp_path)
    assert not (dest2 / "Contents" / "MacOS" / app_bundle.BIN_NAME).exists()


def test_the_app_start_file_runs_the_menu_bar_only_when_opened_as_the_app():
    from omna_plugin.mac import app_boot
    exe = "/Applications/Omna Plugin.app/Contents/MacOS/" + app_bundle.PY_NAME
    assert app_boot.opened_as_the_app([exe], exe)
    # the menu bar runs `omna ensure` with this same Python: never a second menu bar
    assert not app_boot.opened_as_the_app([exe, "-m", "omna_plugin.cli", "ensure"], exe)
    assert not app_boot.opened_as_the_app([exe, "-c", "print(1)"], exe)
    assert not app_boot.opened_as_the_app(["/usr/bin/python3"], "/usr/bin/python3")
