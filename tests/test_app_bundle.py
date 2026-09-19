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
