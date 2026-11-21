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
PROXY_KEY = "HTTPS_PROXY"
CA_KEY = "NODE_EXTRA_CA_CERTS"
HOOK_MARK = "omna ensure"

# Client test 2026-11-21 (#22): Claude Code's Remote Control refuses to start
# when ANTHROPIC_BASE_URL points anywhere but api.anthropic.com ("Remote Control
# is only available when using Claude via api.anthropic.com"). On a Mac with the
# Mac-wide door, Claude Code is sent through that door instead (HTTPS_PROXY +
# Omna's local certificate): it still talks to api.anthropic.com, so Remote
# Control works, and /v1/messages is masked and restored exactly as before
# (verified live the same day). A proxy the person already set is never
# overwritten: then the API door (ANTHROPIC_BASE_URL) is used, as before.


def _door_url() -> str:
    return f"http://{config.DEFAULT_HOST}:{config.SYSTEM_PORT}"


def _ca_path() -> str:
    return str(config.ca_dir() / "mitmproxy-ca-cert.pem")


def _ours_base(v) -> bool:
    return isinstance(v, str) and v.startswith(f"http://{config.DEFAULT_HOST}:")


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
    return " ".join(f'"{p}"' if " " in p else p for p in config.self_command()) + " ensure"


def _is_ours(hook: dict) -> bool:
    cmd = str(hook.get("command", "")).strip()
    return "omna" in cmd and cmd.endswith(" ensure")


def init(path: Path, port: int = config.DEFAULT_PORT, system: bool = False) -> dict:
    """Add our env vars + SessionStart hook. Returns what changed.

    ``system``: the Mac-wide door is on — send Claude Code through it, so
    Remote Control keeps working (see the top of this file)."""
    data = _load(path)
    changes = {"backup": None, "env": False, "hook": False}
    if path.exists():
        backup = path.with_name(path.name + ".omna-backup")
        if not backup.exists():
            shutil.copyfile(path, backup)
            changes["backup"] = str(backup)
    env = data.setdefault("env", {})
    theirs = env.get(PROXY_KEY) not in (None, _door_url())
    if system and not theirs:
        want = {PROXY_KEY: _door_url(), CA_KEY: _ca_path()}
        if _ours_base(env.get(ENV_KEY)):
            del env[ENV_KEY]
            changes["env"] = True
    else:
        want = {ENV_KEY: config.base_url(port)}
        if env.get(PROXY_KEY) == _door_url():
            env.pop(PROXY_KEY, None)
            env.pop(CA_KEY, None)
            changes["env"] = True
    for k, v in want.items():
        if env.get(k) != v:
            env[k] = v
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
    if _ours_base(env.get(ENV_KEY)):
        del env[ENV_KEY]
        changes["env"] = True
    if env.get(PROXY_KEY) == _door_url():
        del env[PROXY_KEY]
        changes["env"] = True
    if env.get(CA_KEY) == _ca_path():
        del env[CA_KEY]
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
        "via_system": env.get(PROXY_KEY) == _door_url(),
        "wired": _ours_base(env.get(ENV_KEY)) or env.get(PROXY_KEY) == _door_url(),
        "hook": any(_is_ours(h) for e in starts for h in e.get("hooks", [])),
    }
