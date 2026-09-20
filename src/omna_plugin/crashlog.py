"""Crash reports a privacy buyer can actually audit (#132).

We were blind to failures in the field: when the plugin broke on someone's
Mac, we never learned. The obvious fix is what Kiji does — an opt-in Sentry
that promises never to send prompts. But for a company whose entire claim is
"your data does not leave this machine", a crash reporter that phones home is
the wrong shape even when it is off by default: the customer has to *trust*
the promise, and a security reviewer has one more outbound path to argue about.

So Omna does it the other way round, and it is strictly stronger:

1. **Nothing is ever sent.** There is no network code in this module at all,
   and a test asserts that by reading this file's own source. A crash is
   appended to ``~/.omna/crashes.jsonl`` (0600) and stays there.
2. **The report is masked by the same engine that masks prompts.** Every
   string is run through fast masking (L1+L2) before it is written, so a
   secret or an address that leaked into an exception message is a token in
   the file — not just absent from the network, absent from the *disk*.
3. **Paths are reduced to bare filenames** and the home directory is replaced
   with ``~``, because ``/Users/jane/...`` is the person's real name.
4. **Only allowlisted keys survive**, so no caller can smuggle a prompt or a
   request body in as "context".
5. **Sending is a person typing a command.** ``omna crash --send`` opens a
   GitHub issue pre-filled with the report they have already read.

The result: the person can `cat` the exact bytes that would ever reach us, and
the claim "never your prompts" stops being a promise and becomes something
they verified. That is the version of this feature worth selling.

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
        p = path()
        rows = _read(p)
        rows.append(row)
        rows = rows[-MAX_ROWS:]
        tmp = p.with_suffix(".jsonl.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            for r in rows:
                f.write(json.dumps(r) + "\n")
        os.replace(tmp, p)
    except Exception:
        return


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
