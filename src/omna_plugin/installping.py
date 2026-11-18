"""Install / uninstall count — the same two pings Omna for Chrome sends.

What it sends, and nothing else (one small JSON to omna.dev):
    {"device_id": <random id made on this computer>, "event": "install" | "uninstall",
     "version": <the curl command's version>, "source": "cli"}

No prompts, no masked or real values, no username, no hostname, no file path.
The random id lives in ``~/.omna/install_id`` and is only there so an
uninstall can be matched to its install; uninstall deletes it with the rest
of ``~/.omna``.

When it sends: once on the first ``omna init`` (running init again sends
nothing), and once on ``omna uninstall``. Turn it off with
``OMNA_NO_TELEMETRY=1`` or the standard ``DO_NOT_TRACK=1``.

Failure is always silent and quick: a count that cannot be delivered must
never slow down or break install or uninstall.
"""

from __future__ import annotations

import os
import uuid

import httpx

from . import config

ENDPOINT = "https://omna.dev/api/public/telemetry"
TIMEOUT = 3.0


def _off() -> bool:
    for name in ("OMNA_NO_TELEMETRY", "DO_NOT_TRACK"):
        v = (os.environ.get(name) or "").strip().lower()
        if v and v not in ("0", "false", "no", "off"):
            return True
    return False


def _id_path():
    return config.home() / "install_id"


def _read_id() -> str:
    try:
        return str(uuid.UUID(_id_path().read_text().strip()))
    except (OSError, ValueError):
        return ""


def _version() -> str:
    try:
        from .proxy import __version__

        return __version__
    except Exception:
        return "unknown"


def _send(device_id: str, event: str, endpoint: str | None) -> bool:
    try:
        r = httpx.post(
            endpoint or ENDPOINT,
            json={"device_id": device_id, "event": event, "version": _version(), "source": "cli"},
            timeout=TIMEOUT,
            headers={"user-agent": f"omna-plugin/{_version()}"},
        )
        return r.status_code // 100 == 2
    except Exception:
        return False


def send_install(endpoint: str | None = None) -> bool:
    """First ``omna init`` on this computer: make the random id, send "install".
    Returns True only when a ping went out (False if off, already counted, or failed)."""
    if _off() or _read_id():
        return False
    device_id = str(uuid.uuid4())
    try:
        config.ensure_home()
        p = _id_path()
        p.write_text(device_id + "\n")
        os.chmod(p, 0o600)
    except OSError:
        return False  # can't remember the id → don't count, or every init would count again
    return _send(device_id, "install", endpoint)


def send_uninstall(endpoint: str | None = None) -> bool:
    """``omna uninstall``: send "uninstall" with the id from install. Call it
    BEFORE ``~/.omna`` is deleted. No id (installed before this existed, or
    telemetry was off at install) → a fresh random id, so the count is still right."""
    if _off():
        return False
    return _send(_read_id() or str(uuid.uuid4()), "uninstall", endpoint)
