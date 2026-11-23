"""``omna menubar`` — a small always-visible status icon: on/off, what's covered, Uninstall.

Polls the API door's own ``/omna/health`` (the same data ``omna status`` prints); no new
backend endpoint. Started automatically at login via its own launchd agent (installed by
``mac/setup.py``) — the ONLY launchd agent Omna installs. The proxy itself has no separate
login item; this process supervises it as a plain subprocess (``omna ensure``/``omna stop``/
``omna start -d``, the same pidfile-based primitives the CLI already uses on its own), so a
non-technical person sees exactly one entry in System Settings → Login Items.
"""

from __future__ import annotations

import os
import re
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx

from . import config, pause

POLL_SECONDS = 4
LOGO_PATH = Path(__file__).parent / "assets" / "menubar-icon.png"
_last_logo = None   # the last picture that opened (see _icon_image)
# RED — shown whenever Omna is not masking (paused or not running). It was a
# calm grey, for a state in which browsers go to the AI unmasked (security
# review 2026-11-11, finding 16).
OFF_DOT_COLOR = (220, 38, 38, 255)
# #45 (owner 2026-11-22): the logo is the website's own O in its own colours
# on a clear background (scripts/make_menubar_icon.py draws it from favicon.svg).
# OFF: the same O in grey, which reads on a light and on a dark menu bar, with
# the red dot just outside its top-right corner so the ring stays whole.
OFF_LOGO_COLOR = (142, 142, 147, 255)
OFF_DOT_AT = (0.84, 0.16, 0.12)   # centre x, centre y, radius, as parts of the width


# What `/omna/health` says a request gets right now, in plain words (the menu
# never said whether fast or smart masking was in use — security review 2026-11-11).
MASKING_WORDS = {
    "smart": "smart (rules + the on-device model)",
    "fast": "fast (rules only)",
    "fast-smart-not-ready": "FAST ONLY — the smart model is still loading",
}


def _health(port: int) -> dict | None:
    try:
        r = httpx.get(f"{config.base_url(port)}/omna/health", timeout=1.0, trust_env=False)
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
        left = pause.minutes_left()
        if left is not None:
            return [
                "Omna: PAUSED — NOT masking · click to resume",
                "Browsers and desktop apps go to the AI UNMASKED",
                "Coding tools cannot connect until you resume",
                f"Resumes by itself in {left} min",
            ]
        return ["Omna: OFF — NOT masking · click to resume",
                "Browsers and desktop apps go to the AI UNMASKED",
                "omna start -d (or click above)"]
    doors = h.get("doors") or {}
    coverage = "every app on this Mac" if doors.get("system") else "coding tools only (Claude Code etc.)"
    return [
        "Omna: ON · click to pause",
        f"Secrets kept off the wire: {h.get('distinct_secrets_this_run', 0)}",
        f"Personal values tokenized: {h.get('distinct_pii_this_run', 0)}",
        f"Requests masked this session: {h.get('requests_this_run', 0)}",
        f"Covers: {coverage}",
        f"Masking overhead: {h.get('avg_mask_ms_this_run', 0)} ms/request",
    ] + _masking_line(h)


def _masking_line(h: dict) -> list[str]:
    if h.get("masking") == "fast-smart-not-ready" and h.get("smart_failed"):
        # The model is not loading — it failed (Muse QA B4, 2026-11-17).
        return ["Masking: FAST ONLY — the smart model failed to download (restart Omna to retry)"]
    return [f"Masking: {MASKING_WORDS[h['masking']]}"] if h.get("masking") in MASKING_WORDS else []


def _icon_image(on: bool):
    from PIL import Image, ImageDraw

    global _last_logo
    try:
        img = Image.open(LOGO_PATH).convert("RGBA")
        _last_logo = img.copy()
    except OSError:
        # An upgrade replaces this file while the icon runs (client test
        # 2026-11-21, #18): the drawing thread died and the icon vanished.
        # Keep drawing with the last good picture, or a plain dot.
        img = _last_logo.copy() if _last_logo is not None else Image.new("RGBA", (44, 44), (0, 0, 0, 0))
        if _last_logo is None:
            ImageDraw.Draw(img).ellipse((8, 8, 36, 36), fill=(30, 30, 30, 255))
    if not on:
        grey = Image.new("RGBA", img.size, OFF_LOGO_COLOR)
        grey.putalpha(img.getchannel("A"))
        img = grey
        w = img.width
        cx, cy, r = (part * w for part in OFF_DOT_AT)
        ImageDraw.Draw(img).ellipse((cx - r, cy - r, cx + r, cy + r), fill=OFF_DOT_COLOR)
    return img


def _toggle_masking(h: dict | None, state: dict) -> None:
    """Pause = stop the proxy. A coding tool still pointed at it then cannot
    connect at all — but a browser or desktop app goes STRAIGHT to the AI,
    UNMASKED, because the routing file that sends it through Omna is served
    by the proxy itself. (This comment used to say "nothing is ever forwarded
    unmasked", which was wrong — security review 2026-11-11, finding 16.)

    So a pause is loud and short (`pause.py`): red in the menu bar, a line in
    the receipts when it starts and when it ends, and it ends by itself after
    15 minutes (the poll loop below). Resume starts the proxy again.
    `state["paused"]` records a deliberate pause so the poll loop's
    crash-recovery doesn't fight it."""
    if h:
        state["paused"] = True
        pause.begin("menubar")
        subprocess.run(config.self_command() + ["stop"], capture_output=True)
    else:
        _resume(state, "click")


def _resume(state: dict, why: str) -> None:
    state["paused"] = False
    pause.end(why)
    subprocess.run(config.self_command() + ["start", "-d"], capture_output=True)


def _sync_pause(state: dict) -> bool:
    """Is protection off on purpose right now? The note on disk decides, not
    this process's memory (#43, 2026-11-22): `omna start -d` can end a Pause
    and `omna stop` can start one from the Terminal; the menu bar used to miss
    both — crash recovery stayed off for good, or undid a stop in 4 seconds."""
    on_disk = pause.state() is not None
    state["paused"] = on_disk
    return on_disk


def _end_pause_if_over(state: dict) -> bool:
    """A Pause ends by itself after 15 minutes (finding 16). True when it did.
    Any timed pause counts, even one an earlier menu bar started."""
    if pause.expired():
        _resume(state, "auto")
        return True
    return False


def _ensure_daemon(state: dict) -> None:
    """Crash recovery for the proxy: it has no launchd `KeepAlive` of its own, so
    this menu-bar process restarts it if it's down and nobody asked for that.
    Never runs while protection is off on purpose (a Pause or `omna stop`)."""
    if _sync_pause(state):
        return
    subprocess.run(config.self_command() + ["ensure"], capture_output=True)


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


def _poll_once(icon, state: dict, port: int) -> None:
    _end_pause_if_over(state)
    h = _health(port)
    st = pause.state()
    if h and st and time.time() - st["since"] > 30:
        # #43 (checker 2026-11-22): Omna is answering, so this "off on purpose"
        # note is a leftover; kept, it would switch crash recovery off for good.
        # Under 30 s it may be our own Pause on its way to stopping the service.
        pause.end("running")
    if h is None:
        _ensure_daemon(state)
        h = _health(port)
    on = bool(h)
    lines = status_lines(h)

    def draw() -> None:
        # #35: macOS 27 lets only the main thread change a menu-bar icon;
        # from this check thread it trapped the process or left no icon.
        try:
            icon.icon = _icon_image(on)
        except Exception:  # noqa: BLE001 — the icon must keep running (#18)
            pass
        icon.title = "\n".join(lines)
        icon.update_menu()

    _on_main(draw)



def _setup(icon, state: dict, port: int) -> None:
    """pystray's start-up step. It runs on pystray's own thread, so the icon is
    shown on the main thread (#35: macOS 27 raced it — sometimes no icon,
    always none when the app was opened from Finder)."""
    _on_main(lambda: setattr(icon, "visible", True))
    threading.Thread(target=_poll_forever, args=(icon, state, port), daemon=True).start()

def _on_main(fn) -> None:
    """Run ``fn`` on the main thread (the one that owns the icon) on a Mac;
    elsewhere, right here."""
    if sys.platform == "darwin":
        from PyObjCTools import AppHelper

        AppHelper.callAfter(fn)
    else:
        fn()


def _poll_forever(icon, state: dict, port: int, sleep=time.sleep) -> None:
    """Every POLL_SECONDS: crash recovery + the icon. One error must never end
    it (#35, 2026-11-21: a single FileNotFoundError on the first round stopped
    crash recovery for good, and nobody noticed for two hours)."""
    while True:
        try:
            _poll_once(icon, state, port)
        except Exception as e:  # noqa: BLE001 — written to menubar.log, then the next round
            print(f"omna menubar: poll round failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)
        sleep(POLL_SECONDS)


# A menu-bar process, either way it can be started: `.../bin/omna menubar`
# (the app's launcher) or `python -m omna_plugin.cli menubar`.
# Only a command line that ENDS like one of those (plus an optional --port N)
# counts — never an editor, grep or rg that merely mentions "omna menubar"
# (checker 2026-11-21).
_MENUBAR_CMD = re.compile(r"(?:/bin/omna|python\S*(?: -\S+)* -m omna_plugin\.cli) menubar(?: --port \d+)?$")
# #35: the Omna Plugin app's own Python, opened with no arguments.
_APP_MENUBAR = re.compile(r"\.app/Contents/MacOS/omna-menubar$")


def stop_other_menu_bars() -> None:
    """#35: close every OTHER Omna menu-bar process. An old one — still running
    from a tool folder an upgrade deleted — shows no icon and makes a click on
    the app (or `omna init`'s `open`) do nothing, because macOS only brings the
    running one forward. Only menu-bar processes are touched; the curl command
    (plugin/proxy) service keeps running."""
    try:
        out = getattr(subprocess.run(["ps", "-axo", "pid=,command="], capture_output=True, text=True), "stdout", "")
        progs = getattr(subprocess.run(["ps", "-axo", "pid=,comm="], capture_output=True, text=True), "stdout", "")
    except OSError:
        return
    # What program each process really is. A menu bar is always Python (or the
    # packaged `omna`) — never less, vim, grep or sh that merely shows the
    # words "omna menubar" (checker 2, 2026-11-21).
    program = {}
    for line in (progs or "").splitlines():
        pid_s, _, prog = line.strip().partition(" ")
        program[pid_s] = prog.strip().rsplit("/", 1)[-1]
    me = os.getpid()
    for line in (out or "").splitlines():
        pid_s, _, command = line.strip().partition(" ")
        try:
            pid = int(pid_s)
        except ValueError:
            continue
        name = program.get(pid_s, "")
        is_app = name == "omna-menubar" and bool(_APP_MENUBAR.search(command))
        if pid == me or not (is_app or ((name.startswith("python") or name == "omna") and _MENUBAR_CMD.search(command))):
            continue
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass


def run(port: int = config.DEFAULT_PORT) -> int:
    import pystray

    stop_other_menu_bars()          # #35: the newest menu bar wins

    # A pause survives this process being quit and reopened: it is on disk.
    st = pause.state()
    state = {"paused": bool(st and st["by"] == "menubar")}

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
            "Restore on reply (shield mode)",
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

    icon.run(setup=lambda i: _setup(i, state, port))
    return 0
