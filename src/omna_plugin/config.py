"""Paths, ports and upstream URLs for the Omna plugin.

Everything lives under one directory (default ``~/.omna``; override with the
``OMNA_HOME`` environment variable, which the tests use to stay isolated).
"""

from __future__ import annotations

import os
from pathlib import Path

DEFAULT_PORT = 7788
SYSTEM_PORT = 7789
DEFAULT_HOST = "127.0.0.1"

# Where requests go after masking. Overridable so a company gateway (or a
# test's fake upstream) can sit behind the plugin.
ANTHROPIC_UPSTREAM = os.environ.get("OMNA_ANTHROPIC_UPSTREAM", "https://api.anthropic.com")
OPENAI_UPSTREAM = os.environ.get("OMNA_OPENAI_UPSTREAM", "https://api.openai.com")


def home() -> Path:
    """The plugin's state directory (registry, receipts, ruleset, pidfile).

    `omna uninstall` recursively deletes this whole directory, so an unset OR
    empty `OMNA_HOME` (`export OMNA_HOME=` in some shell profile) must both fall
    back to the default — `os.environ.get`'s default only covers unset, and
    `Path("")` resolves to the current directory, which would turn uninstall
    into `rm -rf` on wherever the command happened to be run from.
    """
    return Path(os.environ.get("OMNA_HOME") or (Path.home() / ".omna"))


def ensure_home() -> Path:
    """Create the state directory with owner-only permissions and return it."""
    h = home()
    h.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(h, 0o700)
    except OSError:
        pass
    return h


def registry_path() -> Path:
    return home() / "registry.json"


def ruleset_path() -> Path:
    return home() / "ruleset.json"


def receipts_path() -> Path:
    return home() / "receipts.jsonl"


def pid_path() -> Path:
    return home() / "omna.pid"


def log_path() -> Path:
    return home() / "proxy.log"


def menubar_log_path() -> Path:
    return home() / "menubar.log"


def policy_path() -> Path:
    return home() / "policy.json"


def ca_dir() -> Path:
    return home() / "ca"


def dashboard_token_path() -> Path:
    return home() / "dashboard.token"


def dashboard_token(create: bool = True) -> str:
    """The secret that `/omna/dashboard` requires (#134).

    The dashboard is loopback-only and shows counts, never values — but "only
    counts" is still your day: which tools you use, how much, when you stopped.
    Before this, any other program running as you could read it over HTTP
    without touching a single file.

    The token is a random string in ``~/.omna/dashboard.token`` (0600), so
    reading it needs the same file access that reading the registry would.
    That is the honest bar: it does not defend against something already
    running as you with disk access, and nothing local can.
    """
    import secrets

    p = dashboard_token_path()
    try:
        tok = p.read_text().strip()
        if tok:
            return tok
    except OSError:
        pass
    if not create:
        return ""
    ensure_home()
    tok = secrets.token_urlsafe(24)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(tok + "\n")
    return tok


def base_url(port: int = DEFAULT_PORT) -> str:
    return f"http://{DEFAULT_HOST}:{port}"
