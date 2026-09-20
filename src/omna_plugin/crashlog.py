"""Crash reports a privacy buyer can actually audit (#132).

We were blind to failures in the field: when the plugin broke on someone's
Mac, we never learned. Kiji ships an opt-in Sentry that *promises* never to
send prompts. We do the same job while making the promise checkable:

1. **This module cannot send anything.** There is no network code here, and a
   test reads this file's own source and fails the build if any appears. The
   actual sending lives in ``crashsend.py``, so the guarantee on the code that
   touches your data survives no matter what the sending side grows into.
2. **The report is masked by the same engine that masks prompts**, before it
   is written. So a secret that leaked into an exception message is a token on
   *disk* — not merely absent from the network. We cannot receive what we
   never had.
3. **Paths are reduced to bare filenames** and the home directory is replaced
   with ``~``, because ``/Users/jane/...`` is the person's real name.
4. **Only allowlisted keys survive**, so no caller can smuggle a prompt or a
   request body in as "context".
5. **Off by default, asked once.** Nothing is sent until the person answers
   yes to one plain question, asked the first time something actually breaks.
   A no is written down and never asked again. What is sent is byte-for-byte
   the row they can read with ``omna crash``.

The claim "never your prompts" stops being a promise and becomes something
they can verify. That is the version worth selling.

Masking here uses the engine's own per-call numbering, NOT the stable
``MaskingSession`` — a crash must never mint registry entries, because those
are real values at rest.
"""

from __future__ import annotations

import json
import os
import platform
import sys
import traceback
from pathlib import Path
from urllib.parse import quote

from . import config

# Keep the file small and bounded; a crash loop must not fill the disk.
MAX_ROWS = 50
ISSUE_BASE = "https://github.com/gaurjin/omna-plugin/issues/new"

# The only keys a caller may add. Anything else is dropped, so "context" can
# never become a smuggling route for a prompt or a body.
ALLOWED_EXTRA = ("route", "door", "tool", "host")


def path() -> Path:
    return config.home() / "crashes.jsonl"


def _scrub(text: str) -> str:
    """Mask the text, then strip the home directory out of what is left."""
    text = str(text)
    home = str(Path.home())
    if home and home != "/":
        text = text.replace(home, "~")
    try:
        import omna_pii_mask

        # model=False → fast masking only. Irreversible per-call numbering, no
        # registry, no key, nothing persisted.
        return omna_pii_mask.mask(text, model=False)["masked"]
    except Exception:
        # If the engine is the thing that broke, we still must not write the
        # raw text out. An unmaskable message is reported as its shape only.
        return f"<unmaskable {len(text)}-character message withheld>"


def record(exc: BaseException, *, where: str, extra: dict | None = None) -> None:
    """Append one masked crash record. Never raises — a crash reporter that
    crashes turns one bug into two."""
    try:
        from .proxy import __version__ as plugin_version
    except Exception:
        plugin_version = "unknown"
    try:
        from .engine import engine_version

        eng = engine_version()
    except Exception:
        eng = "unknown"

    try:
        frames = []
        for f in traceback.extract_tb(exc.__traceback__):
            frames.append({
                # basename only: the directory path contains the username.
                "file": os.path.basename(f.filename or ""),
                "line": f.lineno,
                "fn": f.name,
            })
        row = {
            # Local bookkeeping only; stripped from anything that would be sent.
            "id": __import__("secrets").token_hex(8),
            "ts": __import__("datetime").datetime.now().astimezone().isoformat(timespec="seconds"),
            "where": str(where)[:32],
            "error": type(exc).__name__,
            "message": _scrub(str(exc))[:2000],
            "traceback": frames[-20:],
            "plugin": plugin_version,
            "engine": eng,
            "python": platform.python_version(),
            # Release string only ("15.2"), never the machine name or serial.
            "os": f"{platform.system()} {platform.release()}",
        }
        for k in ALLOWED_EXTRA:
            if extra and k in extra:
                row[k] = _scrub(extra[k])[:200]

        config.ensure_home()
        rows = _read(path())
        rows.append(row)
        _write_all(rows[-MAX_ROWS:])
    except Exception:
        return


def _write_all(rows: list[dict]) -> None:
    """Rewrite the whole file atomically at 0600. Small and capped, so a full
    rewrite is cheaper than tracking offsets."""
    config.ensure_home()
    p = path()
    tmp = p.with_suffix(".jsonl.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")
    os.replace(tmp, p)


def _read(p: Path) -> list[dict]:
    """Every readable line. One corrupt line skips that line, never the file
    (omna-workspace Lesson #86)."""
    out: list[dict] = []
    try:
        text = p.read_text()
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def tail(n: int = 20) -> list[dict]:
    return _read(path())[-n:]


# ------------------------------------------------------------------ consent
# The decision (owner, 2026-09-20): **off by default, asked once.**
#
# The first version of this made sending a command (`omna crash --send`) that
# nobody would ever run, so we would have learned nothing. The fix for that is
# a better ASK, not a different DEFAULT — turning it on by default would have
# made us more invasive than the competitor we are claiming to beat, which is
# incoherent. So the default stays off and we ask one clear question at the
# only moment the person cares: just after something broke.
#
# A "no" is final. It is written down and never asked again.
def should_ask() -> bool:
    """Is there something to ask about, and have we not asked yet?"""
    from .policy import Policy

    return Policy.load().crash_reports == "unset" and bool(unsent())


def may_send() -> bool:
    from .policy import Policy

    return Policy.load().crash_reports == "on"


def remember_choice(send: bool) -> None:
    from .policy import Policy

    pol = Policy.load()
    pol.crash_reports = "on" if send else "off"
    pol.save()


# --------------------------------------------------------------- the payload
def unsent() -> list[dict]:
    return [r for r in _read(path()) if not r.get("sent")]


def mark_sent(rows: list[dict]) -> None:
    """Flag these as sent WITHOUT deleting them — the local copy is the whole
    point, so the person can always check what left."""
    ids = {r.get("id") for r in rows if r.get("id")}
    if not ids:
        return
    all_rows = _read(path())
    for r in all_rows:
        if r.get("id") in ids:
            r["sent"] = True
    _write_all(all_rows)


def payload(rows: list[dict]) -> dict:
    """Exactly what would go over the wire, built from the rows already on disk.

    Nothing is gathered again at send time, so what the person read with
    ``omna crash`` is precisely what we would receive. The bookkeeping fields
    (``id``, ``sent``) are local only and are stripped.
    """
    return {
        "schema": 1,
        "crashes": [{k: v for k, v in r.items() if k not in ("id", "sent")} for r in rows],
    }


def clear() -> bool:
    try:
        path().unlink()
        return True
    except OSError:
        return False


def issue_url(row: dict) -> str:
    """A pre-filled GitHub issue for ONE already-masked report.

    Built from the same row the person just read on screen, so what they send
    is exactly what they saw — nothing is gathered again at send time.
    """
    frames = "\n".join(f"  {f.get('file')}:{f.get('line')} in {f.get('fn')}" for f in row.get("traceback", []))
    body = (
        f"**What broke:** `{row.get('error')}` in {row.get('where')}\n\n"
        f"**Message (masked by Omna before it was written to disk):**\n\n```\n{row.get('message')}\n```\n\n"
        f"**Where:**\n\n```\n{frames}\n```\n\n"
        f"**Versions:** plugin {row.get('plugin')} · engine {row.get('engine')} · "
        f"Python {row.get('python')} · {row.get('os')}\n\n"
        "_Sent by hand with `omna crash --send`. No prompt text, no unmasked values, "
        "no machine name — see `~/.omna/crashes.jsonl` for the exact bytes._\n"
    )
    title = f"crash: {row.get('error')} in {row.get('where')}"
    return f"{ISSUE_BASE}?title={quote(title)}&body={quote(body)}&labels=crash"


def install_excepthook(where: str) -> None:
    """Record anything that would otherwise die with a bare traceback.

    Chains to the previous hook, so the person still sees the normal Python
    error on their terminal — this only adds the local record.
    """
    previous = sys.excepthook

    def hook(exc_type, exc, tb):
        if not issubclass(exc_type, (KeyboardInterrupt, SystemExit)):
            record(exc, where=where)
        previous(exc_type, exc, tb)

    sys.excepthook = hook
