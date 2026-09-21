"""``omna menubar`` — a small always-visible status icon: on/off, what's covered, Uninstall.

Polls the API door's own ``/omna/health`` (the same data ``omna status`` prints); no new
backend endpoint. Started automatically at login via its own launchd agent (installed by
``mac/setup.py``) — the ONLY launchd agent Omna installs. The proxy itself has no separate
login item; this process supervises it as a plain subprocess (``omna ensure``/``omna stop``/
``omna start -d``, the same pidfile-based primitives the CLI already uses on its own), so a
non-technical person sees exactly one entry in System Settings → Login Items.
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
    """Pure so it's testable without a running proxy or the tray library. Line 1 is
    the clickable toggle itself — same self-describing pattern as the native Mac
    app's "PII Masking: ON/OFF" item — so there is no separate Pause/Resume entry.
    Every metric gets its own line — never merged into one run-on sentence."""
    if not h:
        return ["Omna: OFF · click to resume", "omna start -d (or click above)"]
    doors = h.get("doors") or {}
    coverage = "every app on this Mac" if doors.get("system") else "coding tools only (Claude Code etc.)"
    return [
        "Omna: ON · click to pause",
        f"Secrets kept off the wire: {h.get('distinct_secrets_this_run', 0)}",
        f"Personal values tokenized: {h.get('distinct_pii_this_run', 0)}",
        f"Requests masked this session: {h.get('requests_this_run', 0)}",
        f"Covers: {coverage}",
        f"Masking overhead: {h.get('avg_mask_ms_this_run', 0)} ms/request",
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


def _toggle_masking(h: dict | None, state: dict) -> None:
    """Pause = stop the proxy so it fails closed (connection refused for any tool
    still pointed at it — nothing is ever forwarded unmasked). Resume starts it
    again. The proxy has no launchd job of its own anymore (it's a plain
    subprocess this menu-bar process supervises), so both platforms just drive
    the `omna` CLI's own pidfile-based start/stop. `state["paused"]` records a
    deliberate pause so the poll loop's crash-recovery doesn't fight it."""
    if h:
        state["paused"] = True
        subprocess.run(["omna", "stop"], capture_output=True)
    else:
        state["paused"] = False
        subprocess.run(["omna", "start", "-d"], capture_output=True)


def _ensure_daemon(state: dict) -> None:
    """Crash recovery for the proxy: it has no launchd `KeepAlive` of its own, so
    this menu-bar process restarts it if it's down and nobody asked for that.
    Never runs while `state["paused"]` is set."""
    if state["paused"]:
        return
    subprocess.run(["omna", "ensure"], capture_output=True)


def _toggle_login_item() -> None:
    """Launch at Login, same mechanism the native Mac app uses (System Events),
    pointed at the plugin's own ``.app`` wrapper instead of the native app's."""
    from .mac import app_bundle

    app_bundle.disable_login_item() if app_bundle.login_item_enabled() else app_bundle.enable_login_item()


def _reports_enabled() -> bool:
    from .policy import Policy

    return Policy.load().reports_enabled


def _toggle_reports() -> None:
    """Local receipts are counts only, never real values, but someone may not
    want even that kept on their machine. Off takes effect on the very next
    request — `Pipeline.receipt()` re-reads the policy each time, no restart
    needed."""
    from .policy import Policy

    pol = Policy.load()
    pol.reports_enabled = not pol.reports_enabled
    pol.save()


def _restore_browser() -> bool:
    from .policy import Policy

    return Policy.load().restore_browser


def _toggle_restore_browser() -> None:
    """Whether a BROWSER reply shows you real values or the `[EMAIL_1]` labels.

    Masking is not affected and is never optional — this only decides what you
    read back. Scoped to the browser on purpose: the coding tools must always
    get real values, or Claude Code writes `[SECRET_AWS_KEY_1]` into your file
    instead of editing the real line.

    Takes effect on the next request: the system door re-reads policy.json
    whenever its timestamp moves (`OmnaAddon._fresh`). Before 2026-09-21 it did
    NOT — the running daemon kept the copy it started with, so this toggle did
    nothing at all until a restart while saying otherwise right here.
    """
    from .policy import Policy

    pol = Policy.load()
    pol.restore_browser = not pol.restore_browser
    pol.save()


def _realistic_style() -> bool:
    from .policy import Policy
    from .style import REALISTIC

    return Policy.load().style == REALISTIC


def _toggle_realistic_style() -> None:
    """How a masked value is WRITTEN: a numbered token, or a realistic fake one.

    Ticked means an e-mail is sent as something like robert.jones@example.org
    instead of `[EMAIL_1]`, which reads better to the AI. It applies in the
    BROWSER only — style.py refuses it at the coding-tool and per-app doors,
    because a realistic fake value left behind in a file looks like real data
    while a numbered token looks obviously wrong. Secrets are never faked under
    either setting.

    Takes effect on the next request: the system door re-reads policy.json when
    its timestamp moves (`OmnaAddon._fresh`), and so does the answer the Chrome
    extension reads from /omna/health.
    """
    from .policy import Policy
    from .style import REALISTIC, TOKENS

    pol = Policy.load()
    pol.style = TOKENS if pol.style == REALISTIC else REALISTIC
    pol.save()


def _quit(icon) -> None:
    """The menu-bar has no launchd job to fight anymore, so Quit just quits —
    reopen it from Applications/Spotlight, or it comes back on its own at the
    next login if Launch at Login is on. `launchd.bootout` here is a no-op
    cleanup for a machine that still has the old raw menu-bar LaunchAgent from
    before that was replaced by the login item."""
    if sys.platform == "darwin":
        from .mac import launchd

        launchd.bootout(launchd.MENUBAR_LABEL)
    icon.stop()


def _confirm_and_uninstall(icon, state: dict) -> None:
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
    # This process's own poll loop would otherwise see the daemon go down mid-uninstall
    # and respawn it via `_ensure_daemon` within POLL_SECONDS, undoing the wipe `omna
    # uninstall` just did — set paused first (belt), then quit outright (suspenders),
    # since uninstall is about to delete this very .app anyway.
    state["paused"] = True
    # Runs in a real Terminal window, not this process, so the person sees the sudo
    # password prompt and types it themselves — same reason `omna init` needs a real
    # terminal for its own sudo batch.
    subprocess.run(["osascript", "-e", 'tell application "Terminal" to do script "omna uninstall"'])
    icon.stop()


def run(port: int = config.DEFAULT_PORT) -> int:
    import pystray

    state = {"paused": False}

    def menu_items():
        h = _health(port)
        lines = status_lines(h)
        items = [pystray.MenuItem(lines[0], lambda: _toggle_masking(h, state), checked=lambda item: bool(h))]
        items += [pystray.MenuItem(line, None, enabled=False) for line in lines[1:]]
        items.append(pystray.Menu.SEPARATOR)
        if sys.platform == "darwin":
            from .mac import app_bundle

            items.append(pystray.MenuItem(
                "Launch at Login",
                lambda: _toggle_login_item(),
                checked=lambda item: app_bundle.login_item_enabled(),
            ))
        items.append(pystray.MenuItem(
            "Keep Local Reports",
            lambda: _toggle_reports(),
            checked=lambda item: _reports_enabled(),
        ))
        items.append(pystray.MenuItem(
            "Restore Real Values in Browser",
            lambda: _toggle_restore_browser(),
            checked=lambda item: _restore_browser(),
        ))
        items.append(pystray.MenuItem(
            "Use Realistic Fake Values in Browser",
            lambda: _toggle_realistic_style(),
            checked=lambda item: _realistic_style(),
        ))
        items.append(pystray.MenuItem("Uninstall Omna…", lambda icon: _confirm_and_uninstall(icon, state)))
        items.append(pystray.MenuItem("Quit", lambda icon: _quit(icon)))
        return items

    icon = pystray.Icon("omna", _icon_image(False), "Omna", menu=pystray.Menu(menu_items))

    def poll() -> None:
        while True:
            h = _health(port)
            if h is None:
                _ensure_daemon(state)
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
