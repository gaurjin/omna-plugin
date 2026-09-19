"""Wire Claude Code to the proxy by editing its ``settings.json``.

Claude Code reads an ``env`` block from its settings, so we set
``ANTHROPIC_BASE_URL`` there (no shell-profile edits) and add a ``SessionStart``
hook that runs ``omna ensure`` so the proxy is started on demand. Both edits are
marked and reversible; ``uninstall`` removes only what ``init`` added.
"""

from __future__ import annotations

import json
import shutil
import sys
from pathlib import Path

from . import config

ENV_KEY = "ANTHROPIC_BASE_URL"
HOOK_MARK = "omna ensure"


def settings_file(scope: str = "user") -> Path:
    if scope == "project":
        return Path.cwd() / ".claude" / "settings.json"
    return Path.home() / ".claude" / "settings.json"


def _load(path: Path) -> dict:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text() or "{}")
    except ValueError as e:
        raise SystemExit(f"omna: {path} is not valid JSON ({e}); fix it first, nothing was changed")


def _omna_command() -> str:
    """Absolute command for the hook, so it works even if ~/.local/bin is not on PATH."""
    exe = shutil.which("omna")
    if exe:
        return f'"{exe}" ensure' if " " in exe else f"{exe} ensure"
    return f'"{sys.executable}" -m omna_plugin.cli ensure'


def _is_ours(hook: dict) -> bool:
    cmd = str(hook.get("command", "")).strip()
    return "omna" in cmd and cmd.endswith(" ensure")


def init(path: Path, port: int = config.DEFAULT_PORT) -> dict:
    """Add our env var + SessionStart hook. Returns what changed."""
    data = _load(path)
    changes = {"backup": None, "env": False, "hook": False}
    if path.exists():
        backup = path.with_name(path.name + ".omna-backup")
        if not backup.exists():
            shutil.copyfile(path, backup)
            changes["backup"] = str(backup)
    env = data.setdefault("env", {})
    url = config.base_url(port)
    if env.get(ENV_KEY) != url:
        env[ENV_KEY] = url
        changes["env"] = True
    hooks = data.setdefault("hooks", {})
    starts = hooks.setdefault("SessionStart", [])
    already = any(_is_ours(h) for entry in starts for h in entry.get("hooks", []))
    if not already:
        starts.append({"hooks": [{"type": "command", "command": _omna_command(), "timeout": 30}]})
        changes["hook"] = True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return changes


def uninstall(path: Path) -> dict:
    """Remove exactly what ``init`` added; leave everything else untouched."""
    changes = {"env": False, "hook": False, "backup": False}
    backup = path.with_name(path.name + ".omna-backup")
    if backup.exists():
        backup.unlink()
        changes["backup"] = True
    if not path.exists():
        return changes
    data = _load(path)
    env = data.get("env") or {}
    if isinstance(env.get(ENV_KEY), str) and env[ENV_KEY].startswith(f"http://{config.DEFAULT_HOST}:"):
        del env[ENV_KEY]
        changes["env"] = True
        if not env:
            data.pop("env", None)
    hooks = data.get("hooks") or {}
    starts = hooks.get("SessionStart") or []
    kept = []
    for entry in starts:
        inner = [h for h in entry.get("hooks", []) if not _is_ours(h)]
        if len(inner) != len(entry.get("hooks", [])):
            changes["hook"] = True
        if inner:
            entry = dict(entry, hooks=inner)
            kept.append(entry)
    if starts:
        if kept:
            hooks["SessionStart"] = kept
        else:
            hooks.pop("SessionStart", None)
        if not hooks:
            data.pop("hooks", None)
    path.write_text(json.dumps(data, indent=2) + "\n")
    return changes


def status(path: Path) -> dict:
    data = _load(path) if path.exists() else {}
    env = data.get("env") or {}
    starts = (data.get("hooks") or {}).get("SessionStart") or []
    return {
        "file": str(path),
        "base_url": env.get(ENV_KEY),
        "hook": any(_is_ours(h) for e in starts for h in e.get("hooks", [])),
    }
