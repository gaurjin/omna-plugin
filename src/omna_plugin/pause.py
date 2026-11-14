"""Pause: masking is OFF on purpose — said in red, written down, and it ends by itself.

Pausing stops the proxy. A coding tool pointed at it then cannot connect at
all, but a browser or desktop app goes STRAIGHT to the AI, unmasked: the
routing file that sends it through Omna is served by the proxy itself. That
is what the person asked for when they clicked Pause — but it used to look
like a calm grey dot, leave nothing in the report, and last until somebody
remembered (security review 2026-11-11, finding 16; the old comment in
menubar.py even said "nothing is ever forwarded unmasked").

Owner decision: keep Pause, make it loud and short —
  * a red "NOT masking" state in the menu bar and in ``omna status``;
  * a line in the receipts when protection goes off and when it comes back
    (with how long it was off), counted in the report;
  * it ends by itself after 15 minutes.
"""

from __future__ import annotations

import json
import os
import time

from . import config, receipts
from .policy import Policy

PAUSE_SECONDS = 15 * 60

NOTE_PAUSED = "protection-paused"       # the menu bar's Pause: ends by itself
NOTE_STOPPED = "protection-stopped"     # `omna stop`: off until somebody starts it
NOTE_RESUMED = "protection-resumed"
NOTES = (NOTE_PAUSED, NOTE_STOPPED, NOTE_RESUMED)


def path():
    return config.home() / "paused.json"


def state() -> dict | None:
    """``{"since", "until", "by"}`` while protection is off on purpose, else None.
    ``until`` is 0 for an ``omna stop`` (no automatic end)."""
    try:
        data = json.loads(path().read_text())
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict) or not isinstance(data.get("since"), (int, float)):
        return None
    return {"since": float(data["since"]), "until": float(data.get("until") or 0), "by": str(data.get("by") or "")}


def _record(note: str, **extra) -> None:
    # Same rule as every other receipt: nothing is kept when the person
    # switched Local Reports off.
    if not Policy.load().reports_enabled:
        return
    try:
        receipts.append({"v": receipts.FORMAT, "product": "curl", "door": "control", "route": "pause",
                         "host": "", "status": 0, "finds": [], "note": note, **extra})
    except OSError:
        pass


def begin(by: str = "menubar", now: float | None = None) -> dict:
    """Protection is going off on purpose. ``by="menubar"`` is a Pause (ends
    by itself after PAUSE_SECONDS); anything else is a stop."""
    have = state()
    if have:
        return have
    now = time.time() if now is None else now
    auto = by == "menubar"
    st = {"since": now, "until": now + PAUSE_SECONDS if auto else 0, "by": by}
    config.ensure_home()
    tmp = path().with_suffix(".json.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(st))
    os.replace(tmp, path())
    _record(NOTE_PAUSED if auto else NOTE_STOPPED, **({"auto_end_seconds": PAUSE_SECONDS} if auto else {}))
    return st


def end(why: str = "start", now: float | None = None) -> bool:
    """Protection is back. Writes how long it was off. False when nothing was paused."""
    have = state()
    if not have:
        return False
    now = time.time() if now is None else now
    try:
        path().unlink()
    except OSError:
        pass
    _record(NOTE_RESUMED, off_seconds=max(0, int(now - have["since"])), why=why)
    return True


def expired(now: float | None = None) -> bool:
    """A Pause whose 15 minutes are over."""
    have = state()
    now = time.time() if now is None else now
    return bool(have and have["until"] and now >= have["until"])


def minutes_left(now: float | None = None) -> int | None:
    have = state()
    if not have or not have["until"]:
        return None
    now = time.time() if now is None else now
    return max(0, int((have["until"] - now + 59) // 60))


def status_line() -> str | None:
    """For ``omna status`` while protection is off on purpose."""
    have = state()
    if not have:
        return None
    left = minutes_left()
    if left is None:
        return ("proxy:        STOPPED on purpose — browsers and desktop apps go to the AI UNMASKED; "
                "coding tools cannot connect  → `omna start -d`")
    return (f"proxy:        PAUSED — browsers and desktop apps go to the AI UNMASKED; coding tools cannot connect. "
            f"Resumes by itself in {left} min  → `omna start -d` to resume now")
