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

import httpx

from . import config

POLL_SECONDS = 4
ON_COLOR = (34, 197, 94, 255)     # green — the proxy answered a health check
OFF_COLOR = (156, 163, 175, 255)  # gray — not reachable


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
        return ["Omna: NOT RUNNING", "→ omna start -d"]
    doors = h.get("doors") or {}
    coverage = "every app on this Mac" if doors.get("system") else "coding tools only (Claude Code etc.)"
    return [
        "Omna: ON",
        f"Covers: {coverage}",
        f"Requests masked this session: {h.get('requests_this_run', 0)}",
    ]


def _icon_image(on: bool):
    from PIL import Image, ImageDraw

    img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
    ImageDraw.Draw(img).ellipse((6, 6, 58, 58), fill=ON_COLOR if on else OFF_COLOR)
    return img


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
        items.append(pystray.MenuItem("Uninstall Omna…", lambda: _confirm_and_uninstall()))
        items.append(pystray.MenuItem("Quit (Omna keeps masking in the background)", lambda icon: icon.stop()))
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
