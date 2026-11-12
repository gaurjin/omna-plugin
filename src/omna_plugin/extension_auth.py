"""A shared secret between the curl command and Omna for Chrome, handed over
through Chrome's own native-messaging channel (security review 2026-11-11,
finding 6; owner's choice "A").

Omna for Chrome sends what the person types (smart masking) and pictures (to
read their text) to 127.0.0.1:7788. Nothing proved who answered there: when
the curl command was not running, any other program could take the port,
receive the typed text and answer "nothing found" — and any program could
call the extension-only endpoints, or fool `omna ensure`.

Now:
- ``~/.omna/extension.token`` holds a random secret (0600).
- Chrome hands it ONLY to Omna for Chrome: a native-messaging host manifest
  (``dev.omna.curl``) lists the extension IDs allowed to ask, and Chrome checks
  the caller itself. A stranger program cannot ask Chrome for it.
- Every extension-only call carries the secret (``x-omna-token``), checked
  in constant time.
- Before the extension sends any text, the curl command must PROVE it holds
  the secret: ``/omna/health?nonce=…`` answers ``proof = HMAC-SHA256(secret,
  nonce)``. A squatter on the port cannot, so the extension sends it nothing
  and keeps masking in the browser. `omna ensure` checks the same proof.

The secret is readable by the person's own account (like everything in
``~/.omna``); this protects against OTHER programs that merely reach the port,
which is what the review found. Chrome reads native-messaging manifests only
at start-up: after the first registration Chrome must be quit and reopened.
"""

from __future__ import annotations

import hmac
import json
import os
import secrets
import shlex
import struct
import sys
from hashlib import sha256
from pathlib import Path

from . import config

HOST_NAME = "dev.omna.curl"
HEADER = "x-omna-token"
# The published Omna for Chrome (Chrome Web Store).
STORE_EXTENSION_ID = "nnkjconloimokalfdghmhifcangdbmnc"
_NONCE_MAX = 128


# ------------------------------------------------------------------ the secret
def token_path() -> Path:
    return config.home() / "extension.token"


def read_token() -> str | None:
    try:
        t = token_path().read_text().strip()
    except OSError:
        return None
    return t or None


def ensure_token() -> str:
    """The secret, made once (64 hex characters, 0600)."""
    t = read_token()
    if t:
        return t
    config.ensure_home()
    t = secrets.token_hex(32)
    p = token_path()
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(t + "\n")
    os.chmod(p, 0o600)
    return t


def proof(token: str, nonce: str) -> str:
    """What only the holder of ``token`` can answer to ``nonce``."""
    return hmac.new(token.encode(), nonce.encode(), sha256).hexdigest()


def valid_nonce(nonce: str | None) -> bool:
    return bool(nonce) and len(nonce) <= _NONCE_MAX and all(c in "0123456789abcdef" for c in nonce)


def header_ok(value: str | None) -> bool:
    """Does a request's ``x-omna-token`` match the secret? No secret on this
    machine yet means nobody can pass (fail closed)."""
    t = read_token()
    return bool(t) and bool(value) and hmac.compare_digest(t.encode(), value.encode())


# ------------------------------------------------------- Chrome's trusted channel
def _browser_roots() -> list[Path]:
    """Where Chromium-family browsers look for native-messaging hosts, for the
    browsers present on this machine. A function so tests can redirect it."""
    home = Path.home()
    if sys.platform == "darwin":
        base = home / "Library" / "Application Support"
        roots = [base / "Google" / "Chrome", base / "Google" / "Chrome Beta", base / "Chromium",
                 base / "BraveSoftware" / "Brave-Browser", base / "Microsoft Edge"]
    else:
        base = home / ".config"
        roots = [base / "google-chrome", base / "google-chrome-beta", base / "chromium",
                 base / "BraveSoftware" / "Brave-Browser", base / "microsoft-edge"]
    return [r for r in roots if r.is_dir()]


def _manifest_paths() -> list[Path]:
    return [r / "NativeMessagingHosts" / f"{HOST_NAME}.json" for r in _browser_roots()]


def _mac_app_dev_ids() -> Path:
    """The Mac app keeps the same list (#76). A function so tests can redirect it."""
    return Path.home() / "Library" / "Application Support" / "Omna" / "dev_extension_ids"


def allowed_extension_ids() -> list[str]:
    """The store build, plus any unpacked development build listed one ID per
    line in ``~/.omna/dev_extension_ids`` (or the Mac app's same-named file):
    an unpacked build's ID is derived from its folder, so it differs."""
    ids = [STORE_EXTENSION_ID]
    for f in (config.home() / "dev_extension_ids", _mac_app_dev_ids()):
        try:
            for line in f.read_text().splitlines():
                x = line.strip()
                if len(x) == 32 and x.isalpha() and x.islower() and x not in ids:
                    ids.append(x)
        except OSError:
            pass
    return ids


def _launcher() -> Path:
    """Chrome starts a single program with no arguments of ours, so a small
    script runs this program's ``native-host`` command — with OMNA_HOME baked
    in, so it reads the secret of THIS install."""
    return config.home() / "native-host"


def register() -> list[str]:
    """Write the launcher and one manifest per browser present. Returns the
    manifest paths written (only those that changed). Idempotent."""
    ensure_token()
    launcher = _launcher()
    script = ("#!/bin/sh\n# Omna: hands the curl command's secret to Omna for Chrome (finding 6).\n"
              f"OMNA_HOME={shlex.quote(str(config.home()))} exec "
              + " ".join(shlex.quote(c) for c in config.self_command()) + ' native-host "$@"\n')
    if not launcher.exists() or launcher.read_text() != script:
        launcher.write_text(script)
    os.chmod(launcher, 0o700)
    manifest = json.dumps({
        "name": HOST_NAME,
        "description": "Omna: lets Omna for Chrome prove it is talking to the curl command",
        "path": str(launcher),
        "type": "stdio",
        "allowed_origins": [f"chrome-extension://{i}/" for i in allowed_extension_ids()],
    }, indent=2) + "\n"
    written = []
    for m in _manifest_paths():
        try:
            if m.exists() and m.read_text() == manifest:
                continue
            m.parent.mkdir(parents=True, exist_ok=True)
            m.write_text(manifest)
            written.append(str(m))
        except OSError:
            continue
    return written


def unregister() -> list[str]:
    removed = []
    for m in _manifest_paths():
        try:
            m.unlink()
            removed.append(str(m))
        except OSError:
            pass
    try:
        _launcher().unlink()
    except OSError:
        pass
    return removed


def registered() -> list[str]:
    return [str(m) for m in _manifest_paths() if m.exists()]


# ------------------------------------------------------------- the host itself
def _read_message(stream) -> dict | None:
    head = stream.read(4)
    if len(head) < 4:
        return None
    (n,) = struct.unpack("=I", head)
    if n > 64 * 1024:
        return None
    try:
        msg = json.loads(stream.read(n).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return msg if isinstance(msg, dict) else None


def _write_message(stream, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    stream.write(struct.pack("=I", len(data)) + data)
    stream.flush()


def native_host_main(argv: list[str], stdin=None, stdout=None) -> int:
    """``omna native-host``: Chrome runs this for Omna for Chrome's
    ``sendNativeMessage``. Chrome passes the caller's origin as the first
    argument; Chrome already checked it against the manifest, and this checks
    it again. Answers ``{"token": …}`` to ``{"get": "token"}``, then exits."""
    stdin = stdin or sys.stdin.buffer
    stdout = stdout or sys.stdout.buffer
    origin = next((a for a in argv if a.startswith("chrome-extension://")), "")
    allowed = {f"chrome-extension://{i}/" for i in allowed_extension_ids()}
    msg = _read_message(stdin)
    if origin not in allowed:
        _write_message(stdout, {"error": "not allowed"})
        return 1
    if not msg or msg.get("get") != "token":
        _write_message(stdout, {"error": "unknown request"})
        return 1
    _write_message(stdout, {"token": ensure_token()})
    return 0
