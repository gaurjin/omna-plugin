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
import threading
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



def _sweep_leftovers(older_than: float = 60.0) -> None:
    """Files a process killed halfway through begin()/end() left behind
    (checker 2026-11-22: they block nothing, but would pile up forever)."""
    cutoff = time.time() - older_than
    for f in config.home().glob("paused.json.*"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
        except OSError:
            pass


def _me() -> str:
    """A name no other process or thread uses right now."""
    return f"{os.getpid()}-{threading.get_ident()}"


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
    _sweep_leftovers()
    # #40: a temp file of its own (a shared one crashed one of two stoppers),
    # and os.link, which fails when the note already exists, so exactly one
    # process starts the pause and writes its receipt.
    tmp = path().with_name(f"paused.json.{_me()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(st))
    try:
        os.link(tmp, path())
    except FileExistsError:
        return state() or st          # another process started it a moment ago
    finally:
        try:
            tmp.unlink()
        except OSError:
            pass
    _record(NOTE_PAUSED if auto else NOTE_STOPPED, **({"auto_end_seconds": PAUSE_SECONDS} if auto else {}))
    return st


def end(why: str = "start", now: float | None = None) -> bool:
    """Protection is back. Writes how long it was off. False when nothing was paused."""
    have = state()
    if not have:
        return False
    now = time.time() if now is None else now
    # #40: claim the note by renaming it to a name of our own. On APFS two
    # processes deleting the same file can BOTH be told "deleted" (checker
    # 2026-11-22: 161 of 200 races); a rename has exactly one winner.
    claim = path().with_name(f"paused.json.{_me()}.ending")
    try:
        os.rename(path(), claim)
    except OSError:
        return False                  # another process ended it and wrote the receipt
    # The length comes from the note we really claimed, not the earlier read:
    # another process may have ended that pause and started a new one since
    # (checker 2026-11-22, #40 problem A).
    try:
        since = float(json.loads(claim.read_text()).get("since", have["since"]))
    except (OSError, ValueError, TypeError, AttributeError):
        since = have["since"]
    try:
        claim.unlink()
    except OSError:
        pass
    _record(NOTE_RESUMED, off_seconds=max(0, int(now - since)), why=why)
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
