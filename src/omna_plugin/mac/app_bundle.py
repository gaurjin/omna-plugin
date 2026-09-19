"""The ``.app`` wrapper that lets the menu-bar icon come back after Quit.

``omna-plugin`` is installed as a ``uv tool`` CLI — there is nothing Spotlight or
Launchpad can find once the tray icon is quit, unlike the native Mac app, which ships
a real bundle at ``/Applications/Omna.app`` with a Launch-at-Login toggle. This module
gives the plugin the same mechanism: a tiny bundle at ``/Applications/Omna Plugin.app``
(a distinct name — never ``Omna.app`` — so it can never collide with or overwrite the
native app's own bundle) whose only job is to exec ``omna menubar``, plus the same
System-Events login-item registration the native app uses.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from .. import config

APP_NAME = "Omna Plugin"
APP_PATH = Path("/Applications") / f"{APP_NAME}.app"
BUNDLE_ID = "dev.omna.plugin.app"
BIN_NAME = "omna-plugin-launcher"
LOGIN_ITEM_FLAG = "login_item_enabled.flag"
ICON_NAME = "AppIcon"
ICON_SRC = Path(__file__).parent.parent / "assets" / f"{ICON_NAME}.icns"


def _info_plist() -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>{_xml_escape(APP_NAME)}</string>
  <key>CFBundleIdentifier</key><string>{BUNDLE_ID}</string>
  <key>CFBundleExecutable</key><string>{_xml_escape(BIN_NAME)}</string>
  <key>CFBundleIconFile</key><string>{ICON_NAME}</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>1.0</string>
  <key>LSUIElement</key><true/>
</dict>
</plist>
"""


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _launcher_script(omna_bin: Path, log: Path) -> str:
    # Re-execs the real `omna` binary at whatever path `uv tool install` put it —
    # same shutil.which("omna") resolution mac/setup.py uses, baked in at install time.
    # Output is redirected to `log` since this now launches via a System Events login
    # item (no launchd StandardOutPath/StandardErrorPath to capture it for us).
    log_x = _sh_quote(str(log))
    return f"#!/bin/sh\nexec {_sh_quote(str(omna_bin))} menubar >>{log_x} 2>&1\n"


def install(omna_bin: Path, *, dest: Path = APP_PATH, log: Path | None = None) -> Path:
    """Write (or overwrite) the bundle. Idempotent — safe to call on every `omna init`."""
    macos_dir = dest / "Contents" / "MacOS"
    resources_dir = dest / "Contents" / "Resources"
    macos_dir.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)
    (dest / "Contents" / "Info.plist").write_text(_info_plist())
    launcher = macos_dir / BIN_NAME
    launcher.write_text(_launcher_script(omna_bin, log or config.menubar_log_path()))
    os.chmod(launcher, 0o755)
    if ICON_SRC.exists():
        shutil.copyfile(ICON_SRC, resources_dir / f"{ICON_NAME}.icns")
    return dest


def remove(dest: Path = APP_PATH) -> None:
    shutil.rmtree(dest, ignore_errors=True)


def login_item_enabled() -> bool:
    return (config.home() / LOGIN_ITEM_FLAG).exists()


def enable_login_item(*, app_path: Path = APP_PATH) -> None:
    """Mirrors the native Mac app's own enable_login_item() (tray.rs) — same System
    Events call, same flag-file bookkeeping, just a different app name/path."""
    subprocess.run(
        [
            "osascript", "-e",
            f'tell application "System Events" to make login item at end with properties '
            f'{{path:"{app_path}", hidden:false, name:"{APP_NAME}"}}',
        ],
        capture_output=True,
    )
    config.ensure_home()
    (config.home() / LOGIN_ITEM_FLAG).touch()


def disable_login_item() -> None:
    subprocess.run(
        ["osascript", "-e", f'tell application "System Events" to delete login item "{APP_NAME}"'],
        capture_output=True,
    )
    (config.home() / LOGIN_ITEM_FLAG).unlink(missing_ok=True)
