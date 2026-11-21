"""Install / uninstall count, and the daily "used it" count.

What it sends, and nothing else (small JSON to omna.dev):
    {"device_id": <random id made on this computer>, "event": "install" | "uninstall",
     "version": <the curl command's version>, "source": "cli"}
and, once a day per day of use (owner decision 2026-11-21):
    {..., "event": "daily_active", "day": "YYYY-MM-DD",
     "counts": {"EMAIL": 5, "API_KEY": 1}}   # how many of each type were masked that day
The counts are added up from the local receipts (which already hold counts
only). Never a value, a prompt, a host, an app name or a file path.

No prompts, no masked or real values, no username, no hostname, no file path.
The random id lives in ``~/.omna/install_id`` and is only there so an
uninstall can be matched to its install; uninstall deletes it with the rest
of ``~/.omna``.

When it sends: once on the first ``omna init`` (running init again sends
nothing), once on ``omna uninstall``, and while the proxy runs, at most once an
hour for today and yesterday when their totals changed. Turn it off with
``OMNA_NO_TELEMETRY=1`` or the standard ``DO_NOT_TRACK=1``.

Failure is always silent and quick: a count that cannot be delivered must
never slow down or break install or uninstall.
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import time
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


def _send(device_id: str, event: str, endpoint: str | None, extra: dict | None = None) -> bool:
    try:
        r = httpx.post(
            endpoint or ENDPOINT,
            json={"device_id": device_id, "event": event, "version": _version(), "source": "cli", **(extra or {})},
            timeout=TIMEOUT,
            headers={"user-agent": f"omna-plugin/{_version()} ({platform.system()})"},   # "Darwin"/"Linux": the dashboard's device type
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


# ---------------------------------------------------------------- daily use

def _sent_path():
    return config.home() / "usage_sent.json"


def daily_usage(days: set[str]) -> dict[str, dict[str, int]]:
    """For each day in ``days`` that had at least one request through the curl
    command, the masked counts by type (possibly empty). Chrome's records that
    join this chain and pause/resume ("control") records are not use."""
    from . import receipts

    out: dict[str, dict[str, int]] = {}
    fps: dict[str, dict[str, set]] = {}
    for rec in receipts.tail(0):
        if rec.get("product") != "curl" or rec.get("door") == "control":
            continue
        day = str(rec.get("ts", ""))[:10]
        if day not in days:
            continue
        bucket = out.setdefault(day, {})
        finds = [f for f in (rec.get("finds") or []) if isinstance(f, dict) and f.get("fp")]
        if finds:
            # Each value once a day, by its private fingerprint (client test
            # 2026-11-21: a conversation re-sends its history every turn, so
            # one email was counted on every turn).
            seen = fps.setdefault(day, {})
            for f in (rec.get("finds") or []):
                if isinstance(f, dict) and not f.get("fp") and f.get("entity") and isinstance(f.get("n"), int):
                    bucket[f["entity"]] = bucket.get(f["entity"], 0) + f["n"]   # no fingerprint: count as before
            for f in finds:
                kind = str(f.get("entity") or "")
                for fp in f["fp"]:
                    if kind and fp not in seen.setdefault(kind, set()):
                        seen[kind].add(fp)
                        bucket[kind] = bucket.get(kind, 0) + 1
            continue
        for kind, n in (rec.get("masked") or {}).items():
            if isinstance(n, int) and n > 0:
                bucket[kind] = bucket.get(kind, 0) + n
    return out


def send_daily(endpoint: str | None = None, today: str | None = None) -> int:
    """Send today's and yesterday's totals when they changed since last sent.
    Returns how many days were sent. Never raises."""
    if _off():
        return 0
    try:
        today = today or time.strftime("%Y-%m-%d")
        t = time.mktime(time.strptime(today, "%Y-%m-%d"))
        yesterday = time.strftime("%Y-%m-%d", time.localtime(t - 86_400 + 3_600))
        usage = daily_usage({today, yesterday})
        if not usage:
            return 0
        device_id = _read_id()
        if not device_id:   # installed before the install count, or with it off then
            device_id = str(uuid.uuid4())
            config.ensure_home()
            _id_path().write_text(device_id + "\n")
            os.chmod(_id_path(), 0o600)
        try:
            sent = json.loads(_sent_path().read_text())
        except (OSError, ValueError):
            sent = {}
        n = 0
        for day, counts in sorted(usage.items()):
            digest = hashlib.sha256(json.dumps(counts, sort_keys=True).encode()).hexdigest()[:16]
            if sent.get(day) == digest:
                continue
            if _send(device_id, "daily_active", endpoint, {"day": day, "counts": counts}):
                sent[day] = digest
                n += 1
        sent = {d: v for d, v in sent.items() if d >= yesterday}
        _sent_path().write_text(json.dumps(sent))
        return n
    except Exception:  # noqa: BLE001 - a count must never break the proxy
        return 0


def start_daily_loop(interval: float = 3600.0, first_delay: float = 60.0) -> None:
    """Background thread for the running proxy: send the daily totals a minute
    after start, then hourly. Daemon thread — dies with the proxy."""
    import threading

    if _off():   # also keeps test runs (OMNA_NO_TELEMETRY=1) from ever starting it
        return

    def _loop() -> None:
        time.sleep(first_delay)
        while True:
            send_daily()
            time.sleep(interval)

    threading.Thread(target=_loop, name="omna-daily-count", daemon=True).start()
