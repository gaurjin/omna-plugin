"""``omna menubar`` — a small always-visible status icon: on/off, what's covered, Uninstall.

Polls the API door's own ``/omna/health`` (the same data ``omna status`` prints); no new
backend endpoint. Started automatically at login via its own launchd agent (installed by
``mac/setup.py`` alongside the daemon's), so a non-technical person sees it appear without
running anything themselves.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx

from . import config

POLL_SECONDS = 4
LOGO_PATH = Path(__file__).parent / "assets" / "menubar-icon.png"
OFF_DOT_COLOR = (156, 163, 175, 255)  # gray — overlay shown when not reachable/paused


def _health(port: int) -> dict | None:
    try:
        r = httpx.get(f"{config.base_url(port)}/omna/health", timeout=1.0)
        if r.status_code == 200:
            return r.json()
    except httpx.HTTPError:
        pass
    return None


def status_lines(h: dict | None) -> list[str]:
    """Pure so it's testable without a running proxy or the tray library."""
    if not h:
        return ["Omna: NOT RUNNING", "→ Resume Omna below, or omna start -d"]
    doors = h.get("doors") or {}
    coverage = "every app on this Mac" if doors.get("system") else "coding tools only (Claude Code etc.)"
    return [
        "Omna: ON",
        f"Covers: {coverage}",
        f"Requests masked this session: {h.get('requests_this_run', 0)}",
    ]


def _icon_image(on: bool):
    from PIL import Image, ImageDraw

    img = Image.open(LOGO_PATH).convert("RGBA")
    if not on:
        # Same overlay position the Mac app uses for its state dots: a small
        # circle in the top-right corner of the glyph, not a full recolor.
        w, h = img.size
        cx, cy, r = w * 0.78, h * 0.22, max(w * 0.16, 3.0)
        ImageDraw.Draw(img).ellipse((cx - r, cy - r, cx + r, cy + r), fill=OFF_DOT_COLOR)
    return img


def _toggle_masking(h: dict | None) -> None:
    """Pause = stop the proxy so it fails closed (connection refused for any tool
    still pointed at it — nothing is ever forwarded unmasked). Resume starts it
    again. Uses the same launchd job `omna init` installed, so this works whether
    Omna was started by the login agent or manually."""
    from .mac import launchd

    if sys.platform != "darwin":
        subprocess.run(["omna", "stop" if h else "start", *([] if h else ["-d"])], capture_output=True)
        return
    launchd.bootout(launchd.LABEL) if h else launchd.bootstrap(launchd.LABEL)


def _quit(icon) -> None:
    """Unloads the menu-bar's OWN launchd job first — its ``KeepAlive`` would
    otherwise relaunch the icon within a second of this exiting, which is why
    Quit used to appear to do nothing. The plist stays on disk, so the icon
    still comes back at the next login."""
    if sys.platform == "darwin":
        from .mac import launchd

        launchd.bootout(launchd.MENUBAR_LABEL)
    icon.stop()


def _confirm_and_uninstall() -> None:
    if sys.platform != "darwin":
        print("omna: run `omna uninstall` in a terminal.")
        return
    dialog = subprocess.run(
        [
            "osascript", "-e",
            'display dialog "Uninstall Omna? This turns off masking for every app on this Mac." '
            'buttons {"Cancel", "Uninstall"} default button "Cancel" with icon caution',
        ],
        capture_output=True,
    )
    if b"Uninstall" not in dialog.stdout:
        return
    # Runs in a real Terminal window, not this process, so the person sees the sudo
    # password prompt and types it themselves — same reason `omna init` needs a real
    # terminal for its own sudo batch.
    subprocess.run(["osascript", "-e", 'tell application "Terminal" to do script "omna uninstall"'])


def run(port: int = config.DEFAULT_PORT) -> int:
    import pystray

    def menu_items():
        h = _health(port)
        items = [pystray.MenuItem(line, None, enabled=False) for line in status_lines(h)]
        items.append(pystray.Menu.SEPARATOR)
        pause_label = "Pause Omna" if h else "Resume Omna"
        items.append(pystray.MenuItem(pause_label, lambda: _toggle_masking(h)))
        items.append(pystray.MenuItem("Uninstall Omna…", lambda: _confirm_and_uninstall()))
        items.append(pystray.MenuItem("Quit", lambda icon: _quit(icon)))
        return items

    icon = pystray.Icon("omna", _icon_image(False), "Omna", menu=pystray.Menu(menu_items))

    def poll() -> None:
        while True:
            h = _health(port)
            icon.icon = _icon_image(bool(h))
            icon.title = "\n".join(status_lines(h))
            icon.update_menu()
            time.sleep(POLL_SECONDS)

    def setup(icon) -> None:
        icon.visible = True
        threading.Thread(target=poll, daemon=True).start()

    icon.run(setup=setup)
    return 0
