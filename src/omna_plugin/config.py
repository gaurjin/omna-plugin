"""Paths, ports and upstream URLs for the Omna plugin.

Everything lives under one directory (default ``~/.omna``; override with the
``OMNA_HOME`` environment variable, which the tests use to stay isolated).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

DEFAULT_PORT = 7788
SYSTEM_PORT = 7789
DEFAULT_HOST = "127.0.0.1"

# Where requests go after masking. Overridable so a company gateway (or a
# test's fake upstream) can sit behind the plugin.
ANTHROPIC_UPSTREAM = os.environ.get("OMNA_ANTHROPIC_UPSTREAM", "https://api.anthropic.com")
OPENAI_UPSTREAM = os.environ.get("OMNA_OPENAI_UPSTREAM", "https://api.openai.com")
# Where Codex signed in with a ChatGPT account talks to (its "/v1/…" paths map onto this).
CHATGPT_CODEX_UPSTREAM = os.environ.get("OMNA_CHATGPT_CODEX_UPSTREAM", "https://chatgpt.com/backend-api/codex")


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


def secret_counters_path() -> Path:
    """The highest stand-in number given to each kind of secret
    (``{"GITHUB_TOKEN": 3}``) — numbers only. Its own file so ``omna forget``
    never resets it: a number must not come to mean a second secret."""
    return home() / "secret_counters.json"


def ruleset_path() -> Path:
    return home() / "ruleset.json"


def receipts_path() -> Path:
    return home() / "receipts.jsonl"


def pid_path() -> Path:
    return home() / "omna.pid"


def restart_lock_path() -> Path:
    """The "restart in progress" note (#33b): holds the process number of the
    `omna` command that is restarting the service right now."""
    return home() / "restarting"


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


def tidy_no_proxy() -> None:
    """Rewrite NO_PROXY / no_proxy so httpx can read it (Muse QA B1, 2026-11-17).

    httpx raises ``InvalidURL`` on a bracketed IPv6 entry ("[::1]",
    "[fe80::1]:8080") or an IPv6 range ("::1/128") — `omna status` crashed,
    the installer exited 1 after a good install, and the proxy could not open
    its connection to the AI provider. Brackets, a port and a range on an IPv6
    entry are dropped ("::1"), which keeps that address off the proxy. Every
    other entry is left exactly as it is. Runs once, at the start of `omna`.
    """
    for key in ("NO_PROXY", "no_proxy"):
        raw = os.environ.get(key)
        if raw is None or ("[" not in raw and "::" not in raw and raw.count(":") < 2):
            continue
        out = []
        for part in raw.split(","):
            p = part.strip()
            m = re.fullmatch(r"\[([^\]]+)\](?::\d+)?(?:/\d+)?", p)
            if m:
                p = m.group(1)
            elif p.count(":") >= 2 and "/" in p and "://" not in p:
                p = p.split("/", 1)[0]
            if p:
                out.append(p)
        os.environ[key] = ",".join(out)


def base_url(port: int = DEFAULT_PORT) -> str:
    return f"http://{DEFAULT_HOST}:{port}"


def self_command() -> list[str]:
    """How to run this program again (background start, Claude Code's hook).

    The Homebrew build is one packaged program (PyInstaller, ``sys.frozen``):
    it IS the CLI and has no ``-m``. Before 0.6.10 it was handed
    ``-m omna_plugin.cli`` and every background start failed there."""
    if getattr(sys, "frozen", False):
        return [sys.executable]
    return [sys.executable, "-m", "omna_plugin.cli"]
