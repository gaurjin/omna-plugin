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
    """The plugin's state directory (registry, receipts, ruleset, pidfile)."""
    return Path(os.environ.get("OMNA_HOME", Path.home() / ".omna"))


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


def base_url(port: int = DEFAULT_PORT) -> str:
    return f"http://{DEFAULT_HOST}:{port}"
