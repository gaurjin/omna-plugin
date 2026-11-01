"""Local, hash-chained receipts: one line per request, counts only, never values.

Each record carries ``prev`` (the previous record's hash) and ``hash``
(SHA-256 over ``prev`` + the canonical JSON of the record without ``hash``).
Editing or deleting a line in the middle breaks the chain, which
``verify()`` reports. This is the free, local seed of the paid evidence report.

**At rest:** each line is sealed individually with AES-256-GCM (key in the
macOS Keychain, its own key — not the registry's, so ``omna forget`` cannot
make the evidence trail unreadable). Per-LINE rather than whole-file because
the file is append-only and rewriting it on every request would be both slow
and a chance to corrupt the chain.

There are no real values in a receipt, so why bother? Because "counts only" is
still your working day: which AI tools you use, which providers, when, how
much. That is worth the same protection as the dashboard (#134).

The chain is computed over the DECRYPTED record, so ``verify()`` is unchanged
and an old plaintext file keeps verifying — ``_iter`` reads both forms.

**One record format for both products (MASTER #184, format 1).** The curl
command and Omna for Chrome write the same record, built from the masking
engine's (omna-pii-mask) L6 events — never from counters of their own:

* ``v`` 1, ``ts``, ``product`` ("curl" | "chrome"), ``engine`` (the masking
  engine's build fingerprint);
* ``finds``: the L6 events grouped — one item per (entity, layer, risk,
  action) with ``n`` (how many) and ``fp`` (the distinct value fingerprints,
  keyed per computer, sorted; see ``fingerprint_key``). Never a value;
* the totals a report shows (``masked`` per kind, ``secrets``, ``pii``,
  ``by_layer``) are WORKED OUT from ``finds`` (``totals_of``), so they cannot
  drift from what was found;
* ``prev`` / ``hash``: SHA-256 over ``prev`` + the canonical JSON (sorted
  keys, no spaces, non-ASCII escaped as backslash-u + 4 hex — Python's ``json.dumps``
  default) of the record without ``hash``. No floats anywhere in a record, so
  every language writes the same bytes. ``tests/fixtures/record_vectors.json``
  is shared with Omna for Chrome's tests: both must produce these hashes.

Omna for Chrome hands its records to ``POST /omna/record`` while the curl
command runs; they join this chain as ``product: "chrome"``, door "chrome".
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import threading
import time
from typing import Iterator

from . import config, vault

GENESIS = "0" * 64

# The daemon runs the API door and the system door on separate OS threads
# sharing one Pipeline; both can call append() at once. This guards the
# read-last_hash-then-write sequence so the chain never forks.
_LOCK = threading.Lock()

# What one receipt costs (architecture review, MASTER #178): finding the last
# hash decrypted EVERY earlier line, and the key was fetched from the Keychain
# (a separate program) for every request — the curl command got slower with
# every request it had ever handled. Now the chain head is remembered with the
# file's size and time; if another program appended since, only the file's
# last lines are read. The key is fetched once per receipts file.
_HEAD: dict[str, tuple[tuple[int, int], str]] = {}   # path -> (stamp, last hash)
_KEYS: dict[str, bytes | None] = {}
_TAIL_BYTES = 64 * 1024


FORMAT = 1

# The secret behind every L6 value fingerprint on this computer (#184). An
# unkeyed hash of a short value (a 9-digit ID) can be reversed by hashing every
# possible value; keyed, it cannot without this key. Derived from the receipts
# key (Keychain) so there is nothing new to store; without a Keychain, a
# random key file next to the receipts (0600).
_FP_KEYS: dict[str, bytes] = {}


def fingerprint_key() -> bytes:
    home = str(config.home())
    if home in _FP_KEYS:
        return _FP_KEYS[home]
    base = _key(cached=True)
    if base:
        key = hmac.new(base, b"omna-l6-fingerprint-v1", hashlib.sha256).digest()
    else:
        config.ensure_home()
        path = config.home() / "fingerprint.key"
        try:
            key = path.read_bytes()
        except OSError:
            key = b""
        if len(key) != 32:
            key = os.urandom(32)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as f:
                f.write(key)
    _FP_KEYS[home] = key
    return key


_FIND_KEYS = ("entity", "layer", "risk", "action")


def finds_of(events: list[dict], action: str | None = None) -> list[dict]:
    """Group L6 events (the masking engine's ``mask()["audit"]`` items, or
    ``detect()`` spans, which carry the same fields) into a record's ``finds``.
    ``action`` overrides the engine's (a picture's values are blacked out)."""
    groups: dict[tuple, dict] = {}
    for e in events:
        k = (str(e.get("entity", "")), str(e.get("layer", "")), str(e.get("risk", "")),
             action or str(e.get("action", "")))
        g = groups.setdefault(k, {"n": 0, "fp": set()})
        g["n"] += 1
        if e.get("span_hash"):
            g["fp"].add(str(e["span_hash"]))
    return [dict(zip(_FIND_KEYS, k), n=g["n"], fp=sorted(g["fp"])) for k, g in sorted(groups.items())]


def merge_finds(*lists: list[dict]) -> list[dict]:
    groups: dict[tuple, dict] = {}
    for items in lists:
        for f in items:
            k = tuple(f[x] for x in _FIND_KEYS)
            g = groups.setdefault(k, {"n": 0, "fp": set()})
            g["n"] += int(f["n"])
            g["fp"].update(f.get("fp") or ())
    return [dict(zip(_FIND_KEYS, k), n=g["n"], fp=sorted(g["fp"])) for k, g in sorted(groups.items())]


def totals_of(finds: list[dict]) -> dict:
    """The totals a record shows, worked out from its finds. A secret is what
    the secrets layer (L2) caught — the rule the curl command always used."""
    masked: dict[str, int] = {}
    by_layer: dict[str, int] = {}
    secrets = pii = 0
    for f in finds:
        n = int(f["n"])
        masked[f["entity"]] = masked.get(f["entity"], 0) + n
        by_layer[f["layer"]] = by_layer.get(f["layer"], 0) + n
        if f["layer"] == "L2":
            secrets += n
        else:
            pii += n
    return {"masked": masked, "secrets": secrets, "pii": pii, "by_layer": by_layer}


def valid_finds(value) -> list[dict] | None:
    """``finds`` from an untrusted sender (Omna for Chrome over a local port),
    or None when the shape is anything but exact."""
    if not isinstance(value, list) or len(value) > 500:
        return None
    out = []
    for f in value:
        if not isinstance(f, dict) or set(f) != {*_FIND_KEYS, "n", "fp"}:
            return None
        if not all(isinstance(f[k], str) and 0 < len(f[k]) <= 64 for k in _FIND_KEYS):
            return None
        if not isinstance(f["n"], int) or isinstance(f["n"], bool) or not 0 < f["n"] <= 1_000_000:
            return None
        fp = f["fp"]
        if (not isinstance(fp, list) or len(fp) > 1000
                or not all(isinstance(x, str) and len(x) == 16 and all(c in "0123456789abcdef" for c in x) for x in fp)):
            return None
        out.append({**{k: f[k] for k in _FIND_KEYS}, "n": f["n"], "fp": sorted(set(fp))})
    return merge_finds(out)


def _canonical(rec: dict) -> str:
    body = {k: v for k, v in rec.items() if k != "hash"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"))


def _hash(prev: str, rec: dict) -> str:
    return hashlib.sha256((prev + _canonical(rec)).encode()).hexdigest()


def _key(cached: bool = False) -> bytes | None:
    """The receipts key. ``cached``: the writing path, which asks the Keychain
    once per file; reading always asks, so a deleted key shows as unreadable."""
    path = str(config.receipts_path())
    if not cached:
        return vault.load_key(create=True, account=vault.RECEIPTS_ACCOUNT)
    if path not in _KEYS:
        _KEYS[path] = vault.load_key(create=True, account=vault.RECEIPTS_ACCOUNT)
    return _KEYS[path]


def _stamp(path) -> tuple[int, int] | None:
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_mtime_ns, st.st_size)


def _open_line(line: str, key: bytes | None) -> dict:
    if vault.is_sealed(line):
        try:
            return vault.open_sealed(line, key)
        except vault.RegistryLocked:
            return {"_corrupt": "sealed line could not be opened"}
    try:
        return json.loads(line)
    except ValueError:
        return {"_corrupt": line}


def _iter(path) -> Iterator[dict]:
    """Every record, sealed or plaintext.

    Reads both forms so a file written before encryption existed keeps working
    and keeps verifying. A line we cannot open is surfaced as ``_corrupt``, the
    same as unparseable JSON, so `verify()` reports it instead of skipping it —
    a receipt you cannot read is exactly as bad as one that was tampered with.
    """
    if not path.exists():
        return
    key = None
    key_loaded = False
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if vault.is_sealed(line) and not key_loaded:
                key, key_loaded = _key(), True
            yield _open_line(line, key)


def _scan_last_hash(path) -> str:
    """The hash of the last record that has one, reading the file from its end."""
    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(max(0, size - _TAIL_BYTES))
            chunk = f.read()
    except OSError:
        return GENESIS
    lines = chunk.decode("utf-8", "replace").splitlines()
    if size > _TAIL_BYTES:
        lines = lines[1:]   # the first one may be cut in half
    key = None
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        if key is None and vault.is_sealed(line):
            key = _key(cached=True)
        h = _open_line(line, key).get("hash")
        if h:
            return h
    if size > _TAIL_BYTES:
        h = GENESIS   # nothing usable at the end: the slow, whole-file answer
        for rec in _iter(path):
            h = rec.get("hash", h)
        return h
    return GENESIS


def last_hash() -> str:
    path = config.receipts_path()
    stamp = _stamp(path)
    if stamp is None:
        return GENESIS
    cached = _HEAD.get(str(path))
    if cached and cached[0] == stamp:
        return cached[1]
    h = _scan_last_hash(path)
    _HEAD[str(path)] = (stamp, h)
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
        key = _key(cached=True)
        line = (vault.seal(rec, key) if key
                else json.dumps(rec, sort_keys=True, separators=(",", ":")))
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        stamp = _stamp(path)
        if stamp is not None:
            _HEAD[str(path)] = (stamp, rec["hash"])
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
