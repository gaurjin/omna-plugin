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
import sys
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from .. import config

APP_NAME = "Omna Plugin"
APP_PATH = Path("/Applications") / f"{APP_NAME}.app"
BUNDLE_ID = "dev.omna.plugin.app"
BIN_NAME = "omna-plugin-launcher"   # the old shell launcher (kept for a packaged build)
PY_NAME = "omna-menubar"            # #35: the app's own Python (see mac/app_boot.py)
LOGIN_ITEM_FLAG = "login_item_enabled.flag"
ICON_NAME = "AppIcon"
ICON_SRC = Path(__file__).parent.parent / "assets" / f"{ICON_NAME}.icns"


def _info_plist(main: str = BIN_NAME) -> str:
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>{_xml_escape(APP_NAME)}</string>
  <key>CFBundleIdentifier</key><string>{BUNDLE_ID}</string>
  <key>CFBundleExecutable</key><string>{_xml_escape(main)}</string>
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


def install(omna_bin: Path, *, dest: Path = APP_PATH, log: Path | None = None,
            python: Path | None = None, tool_prefix: Path | None = None,
            site_packages: Path | None = None, py_version: str | None = None) -> Path:
    """Write (or overwrite) the bundle. Idempotent — safe to call on every `omna init`.

    With ``python`` (the curl command's own interpreter file), the app's main
    program is a copy of it (#35: macOS 27 shows the icon only then); it finds
    the installed code through ``pyvenv.cfg`` and a ``.pth`` pointer, and
    ``mac/app_boot.py`` starts the menu bar. Without it (a packaged build),
    the old shell launcher."""
    macos_dir = dest / "Contents" / "MacOS"
    resources_dir = dest / "Contents" / "Resources"
    shutil.rmtree(macos_dir, ignore_errors=True)     # never leave the other kind of launcher
    shutil.rmtree(dest / "Contents" / "lib", ignore_errors=True)
    macos_dir.mkdir(parents=True, exist_ok=True)
    resources_dir.mkdir(parents=True, exist_ok=True)
    if python is not None and tool_prefix is not None and site_packages is not None and py_version:
        (dest / "Contents" / "Info.plist").write_text(_info_plist(PY_NAME))
        main = macos_dir / PY_NAME
        shutil.copyfile(python, main)                 # a real copy: a link is not "inside the app"
        os.chmod(main, 0o755)
        shutil.copyfile(tool_prefix / "pyvenv.cfg", dest / "Contents" / "pyvenv.cfg")
        here = dest / "Contents" / "lib" / f"python{py_version}" / "site-packages"
        here.mkdir(parents=True, exist_ok=True)
        # .pth files run in name order: the pointer to the installed code first.
        (here / "omna_a_installed_code.pth").write_text(f"{site_packages}\n")
        (here / "omna_b_start_menu_bar.pth").write_text("import omna_plugin.mac.app_boot\n")
    else:
        (dest / "Contents" / "Info.plist").write_text(_info_plist())
        launcher = macos_dir / BIN_NAME
        launcher.write_text(_launcher_script(omna_bin, log or config.menubar_log_path()))
        os.chmod(launcher, 0o755)
    if ICON_SRC.exists():
        shutil.copyfile(ICON_SRC, resources_dir / f"{ICON_NAME}.icns")
    return dest


def own_python() -> dict:
    """What ``install`` needs to make this Python the app's main program, or
    {} for a packaged build (no separate Python to copy)."""
    if getattr(sys, "frozen", False):
        return {}
    prefix = Path(sys.prefix)
    import omna_plugin
    if not (prefix / "pyvenv.cfg").exists():
        return {}
    return {"python": Path(sys.executable).resolve(), "tool_prefix": prefix,
            "site_packages": Path(omna_plugin.__file__).resolve().parent.parent,
            "py_version": f"{sys.version_info[0]}.{sys.version_info[1]}"}


def stale(dest: Path = APP_PATH, *, python: Path | None = None, tool_prefix: Path | None = None,
          site_packages: Path | None = None, py_version: str | None = None) -> bool:
    """Is the app's own-Python setup pointing at an Omna folder that is gone or
    not this one (#37: an update moved Omna to another Python)? False for a
    missing app or the old shell launcher — nothing to repair there."""
    main = dest / "Contents" / "MacOS" / PY_NAME
    if not main.exists() or site_packages is None:
        return False
    pths = list((dest / "Contents" / "lib").glob("python*/site-packages/omna_a_installed_code.pth"))
    if len(pths) != 1:
        return True
    try:
        pointed = Path(pths[0].read_text().strip())
    except OSError:
        return True
    return (not pointed.is_dir() or pointed.resolve() != Path(site_packages).resolve()
            or pths[0].parent.parent.name != f"python{py_version}")


def repair_if_stale(dest: Path = APP_PATH, **python_kw) -> bool:
    """Rebuild the app when stale(); True when it did. Quiet, never raises."""
    try:
        if not stale(dest, **python_kw):
            return False
        install(Path(shutil.which("omna") or sys.argv[0]), dest=dest, **python_kw)
        return True
    except OSError:
        return False


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
