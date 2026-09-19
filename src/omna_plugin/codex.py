"""Wire Codex CLI to the proxy by editing its ``config.toml``.

Codex CLI reads a top-level ``openai_base_url`` key from ``~/.codex/config.toml``
(https://learn.chatgpt.com/docs/config-file/config-reference) to override the
built-in ``openai`` provider's address — verified 2026-09-19, since a wrong guess
here would mean Codex silently keeps talking to OpenAI directly, unmasked.

Edited as a single line, not round-tripped through a TOML library: a person may
have their own ``model_providers`` blocks and comments in this file, and a
generic parse-and-dump would reformat or drop them. Same shape as
``claude_code.py``: mark our line, back up the file once, uninstall removes only
what we added.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

from . import config

MARK = "# added by omna"
_KEY_RE = re.compile(r'^openai_base_url[ \t]*=.*$', re.MULTILINE)


def settings_file() -> Path:
    return Path.home() / ".codex" / "config.toml"


def _our_line(port: int) -> str:
    return f'openai_base_url = "{config.base_url(port)}/v1"  {MARK}'


def _is_ours(line: str) -> bool:
    return MARK in line


def init(path: Path, port: int = config.DEFAULT_PORT) -> dict:
    """Add/replace the ``openai_base_url`` line. Returns what changed."""
    changes = {"base_url": False, "backup": None}
    text = path.read_text() if path.exists() else ""
    new_line = _our_line(port)
    existing = _KEY_RE.search(text)
    if existing and not _is_ours(existing.group(0)):
        return changes  # someone set this deliberately; don't fight it silently
    if path.exists():
        backup = path.with_name(path.name + ".omna-backup")
        if not backup.exists():
            shutil.copyfile(path, backup)
            changes["backup"] = str(backup)
    if existing:
        if existing.group(0).strip() == new_line.strip():
            return changes  # idempotent: already set to exactly this
        text = _KEY_RE.sub(new_line, text, count=1)
    else:
        sep = "" if not text or text.endswith("\n") else "\n"
        text = f"{text}{sep}{new_line}\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    changes["base_url"] = True
    return changes


def uninstall(path: Path) -> dict:
    """Remove exactly what ``init`` added; leave everything else untouched."""
    changes = {"base_url": False, "backup": False}
    backup = path.with_name(path.name + ".omna-backup")
    if backup.exists():
        backup.unlink()
        changes["backup"] = True
    if not path.exists():
        return changes
    text = path.read_text()
    m = _KEY_RE.search(text)
    if m and _is_ours(m.group(0)):
        text = _KEY_RE.sub("", text, count=1)
        text = re.sub(r"\n{3,}", "\n\n", text)  # collapse the blank line left behind
        path.write_text(text)
        changes["base_url"] = True
    return changes


def status(path: Path) -> dict:
    if not path.exists():
        return {"file": str(path), "base_url": None}
    m = _KEY_RE.search(path.read_text())
    if not m:
        return {"file": str(path), "base_url": None}
    value = m.group(0).split("=", 1)[1].split(MARK)[0].strip().strip('"')
    return {"file": str(path), "base_url": value, "ours": _is_ours(m.group(0))}
