"""Local, hash-chained receipts: one line per request, counts only, never values.

Each record carries ``prev`` (the previous record's hash) and ``hash``
(SHA-256 over ``prev`` + the canonical JSON of the record without ``hash``).
Editing or deleting a line in the middle breaks the chain, which
``verify()`` reports. This is the free, local seed of the paid evidence report.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import time
from typing import Iterator

from . import config

GENESIS = "0" * 64

# The daemon runs the API door and the system door on separate OS threads
# sharing one Pipeline; both can call append() at once. This guards the
# read-last_hash-then-write sequence so the chain never forks.
_LOCK = threading.Lock()


def _canonical(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _hash(prev: str, rec: dict) -> str:
    return hashlib.sha256((prev + _canonical(rec)).encode()).hexdigest()


def _iter(path) -> Iterator[dict]:
    if not path.exists():
        return
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except ValueError:
                yield {"_corrupt": line}


def last_hash() -> str:
    h = GENESIS
    for rec in _iter(config.receipts_path()):
        h = rec.get("hash", h)
    return h


def append(record: dict) -> dict:
    """Append ``record`` (a dict of counts/metadata) and return it with the chain fields."""
    config.ensure_home()
    path = config.receipts_path()
    rec = dict(record)
    rec.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    with _LOCK:
        rec["prev"] = last_hash()
        rec["hash"] = _hash(rec["prev"], rec)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps(rec, sort_keys=True, separators=(",", ":")) + "\n")
    return rec


def tail(n: int = 20) -> list[dict]:
    recs = list(_iter(config.receipts_path()))
    return recs[-n:] if n else recs


def count() -> int:
    return sum(1 for _ in _iter(config.receipts_path()))


def verify() -> tuple[bool, int, str]:
    """Return (ok, records_checked, message)."""
    prev = GENESIS
    n = 0
    for rec in _iter(config.receipts_path()):
        n += 1
        if "_corrupt" in rec:
            return False, n, f"line {n} is not valid JSON"
        if rec.get("prev") != prev:
            return False, n, f"line {n}: prev does not match the previous hash"
        if rec.get("hash") != _hash(prev, rec):
            return False, n, f"line {n}: hash does not match its contents"
        prev = rec["hash"]
    return True, n, "chain intact"


def summary(records: list[dict]) -> dict[str, int]:
    """Aggregate masked/redacted counts across records."""
    out: dict[str, int] = {}
    for r in records:
        for k, v in (r.get("masked") or {}).items():
            out[k] = out.get(k, 0) + v
    return out
