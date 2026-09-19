"""Wire Continue (the VS Code/JetBrains extension, and its CLI) to the proxy
by editing its own ``~/.continue/config.yaml``.

Unlike Claude Code/aider/Codex CLI, Continue has no single top-level "point
everywhere at this address" key — ``config.yaml`` holds a ``models:`` list of
whatever the person has already configured themselves
(https://docs.continue.dev/reference). Continue extensions also cannot read
shell environment variables at all (confirmed in Continue's own docs/FAQ), so
there is no env-var shortcut the way there was for aider's Anthropic side.

Given that, we don't invent a new model entry (we'd have to guess a model
name and assume they have a key for it) or rewrite the list. Instead: for
each of the person's OWN existing ``anthropic``/``openai`` model entries that
doesn't already have its own ``apiBase`` (someone already using a custom
gateway is left alone, same principle as everywhere else), add ``apiBase``
pointing at Omna. That redirects models they're already using, through the
gateway they already configured, without guessing at anything.

Uses ``ruamel.yaml`` (round-trip mode) rather than a plain parse/dump, so a
person's existing comments and formatting in this file survive — this file
is far more likely to be hand-edited than the JSON/TOML files the other
integrations touch.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from ruamel.yaml import YAML

from . import config

MARK_KEY = "_omnaManaged"
_TOUCHED_PROVIDERS = ("anthropic", "openai")


def config_file() -> Path:
    return Path.home() / ".continue" / "config.yaml"


def detected() -> bool:
    """True once Continue has been run at least once (it creates ~/.continue
    itself). There's no binary on PATH to check the way aider/Codex CLI have."""
    return config_file().exists()


def _yaml() -> YAML:
    y = YAML()
    y.preserve_quotes = True
    y.width = 4096  # don't rewrap long lines we didn't touch
    return y


def _api_base(provider: str, port: int) -> str:
    return config.base_url(port) + ("/v1" if provider == "openai" else "")


def status() -> dict:
    """Whether any model currently carries our marker — not a single on/off
    the way a top-level key would be, since this is a per-model setting."""
    path = config_file()
    if not path.exists():
        return {"file": str(path), "wired": False}
    try:
        data = _yaml().load(path.read_text())
    except Exception:
        return {"file": str(path), "wired": False}
    models = (data or {}).get("models") if isinstance(data, dict) else None
    wired = any(isinstance(m, dict) and m.get(MARK_KEY) for m in (models or []))
    return {"file": str(path), "wired": wired}


def init(port: int = config.DEFAULT_PORT) -> dict:
    """Add `apiBase` to the person's own anthropic/openai models that don't
    already have one. Never touches a model that's already pointed somewhere
    custom, and never invents a new model entry."""
    changes = {"models_wired": [], "backup": None}
    path = config_file()
    if not path.exists():
        return changes  # nothing configured yet — nothing of theirs to redirect
    yaml = _yaml()
    try:
        data = yaml.load(path.read_text())
    except Exception:
        changes["skipped"] = f"{path} could not be parsed as YAML — left it alone"
        return changes
    models = (data or {}).get("models") if isinstance(data, dict) else None
    if not models:
        return changes
    touched = False
    for m in models:
        if not isinstance(m, dict):
            continue
        provider = m.get("provider")
        if provider not in _TOUCHED_PROVIDERS:
            continue
        if "apiBase" in m and not m.get(MARK_KEY):
            continue  # someone set this deliberately; don't fight it silently
        new_base = _api_base(provider, port)
        if m.get("apiBase") == new_base and m.get(MARK_KEY):
            continue  # idempotent
        m["apiBase"] = new_base
        m[MARK_KEY] = True
        changes["models_wired"].append(m.get("name", provider))
        touched = True
    if not touched:
        return changes
    backup = path.with_name(path.name + ".omna-backup")
    if not backup.exists():
        shutil.copyfile(path, backup)
        changes["backup"] = str(backup)
    yaml.dump(data, path)
    return changes


def uninstall() -> dict:
    """Remove exactly the `apiBase`/marker pairs `init` added; leave every
    other model, and every model we skipped, exactly as it was."""
    changes = {"models_unwired": [], "backup": False}
    path = config_file()
    backup = path.with_name(path.name + ".omna-backup")
    if backup.exists():
        backup.unlink()
        changes["backup"] = True
    if not path.exists():
        return changes
    yaml = _yaml()
    try:
        data = yaml.load(path.read_text())
    except Exception:
        return changes
    models = (data or {}).get("models") if isinstance(data, dict) else None
    if not models:
        return changes
    touched = False
    for m in models:
        if isinstance(m, dict) and m.get(MARK_KEY):
            m.pop("apiBase", None)
            m.pop(MARK_KEY, None)
            changes["models_unwired"].append(m.get("name", m.get("provider")))
            touched = True
    if touched:
        yaml.dump(data, path)
    return changes
