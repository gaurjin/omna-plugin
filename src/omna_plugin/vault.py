"""At-rest protection for the token registry.

``registry.json`` is the one file the plugin writes that holds real values —
the address behind an EMAIL token, the name behind a PERSON token. Until now it
was protected by file permissions alone (``0600``), which stops other people
logged into the same Mac and nothing else: not a stolen laptop without
FileVault, not a cloud backup that sweeps the file up in the clear, not any
other program running as you.

So the file is now sealed with AES-256-GCM. The key is 32 random bytes kept in
the macOS Keychain, never on disk beside the file it protects. GCM also
authenticates, so a file someone edited fails to open instead of quietly
handing back changed mappings.

**When there is no Keychain** (Linux, CI, a headless box, or
``OMNA_REGISTRY_ENCRYPTION=off``) the registry stays plaintext-at-0600, exactly
as it behaved before. That is a deliberate choice: refusing to run would turn a
privacy upgrade into an outage. ``omna status`` says so in plain words every
time, so nobody is encrypted-by-assumption.

``OMNA_REGISTRY_ENCRYPTION=off`` means "do not touch the Keychain at all". An
already-encrypted registry is then unreadable, and the session says so rather
than silently starting a new one.
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Keychain coordinates. One generic password, owned by /usr/bin/security, which
# can read its own items back without prompting the person every time.
SERVICE = "omna"
ACCOUNT = "registry-key"

ALGORITHM = "aes-256-gcm"
KEY_BYTES = 32
NONCE_BYTES = 12
# Bound into the ciphertext, so an envelope cannot be replayed as a different
# kind of file later.
AAD = b"omna-registry-v2"

_SECURITY = "/usr/bin/security"
_OFF = {"off", "0", "false", "no"}


class RegistryLocked(Exception):
    """The registry is encrypted and we cannot open it (key missing or wrong)."""


# ------------------------------------------------------------------- keychain
# These three are the only places that talk to the real machine, so tests swap
# them for a dict instead of writing into the owner's actual Keychain.
def _kc_supported() -> bool:
    return sys.platform == "darwin" and (Path(_SECURITY).exists() or shutil.which("security") is not None)


def _kc_read(account: str) -> str | None:
    try:
        p = subprocess.run(
            [_SECURITY, "find-generic-password", "-s", SERVICE, "-a", account, "-w"],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if p.returncode != 0:
        return None
    return p.stdout.strip() or None


def _kc_write(account: str, value: str) -> None:
    # The value goes in on stdin, NOT as an argument: anything on the command
    # line is visible to every other process on the machine via `ps`, and this
    # value is the key to the registry. `security` asks for it twice.
    subprocess.run(
        [_SECURITY, "add-generic-password", "-s", SERVICE, "-a", account, "-U", "-w"],
        input=f"{value}\n{value}\n", capture_output=True, text=True, timeout=10, check=True,
    )


def _kc_delete(account: str) -> bool:
    try:
        p = subprocess.run(
            [_SECURITY, "delete-generic-password", "-s", SERVICE, "-a", account],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return p.returncode == 0


def encryption_disabled() -> bool:
    return (os.environ.get("OMNA_REGISTRY_ENCRYPTION") or "").strip().lower() in _OFF


def keychain_supported() -> bool:
    """Can we keep a key on this machine at all?"""
    return not encryption_disabled() and _kc_supported()


def new_key() -> bytes:
    return os.urandom(KEY_BYTES)


def load_key(create: bool = False) -> bytes | None:
    """The registry key, or None if this machine cannot hold one.

    ``create=True`` mints one on first use. Never raises: a Keychain that is
    locked, missing or refusing means "no key", which the caller turns into
    today's plaintext behaviour plus a loud status line.
    """
    if not keychain_supported():
        return None
    stored = _kc_read(ACCOUNT)
    if stored:
        try:
            raw = base64.b64decode(stored, validate=True)
        except (ValueError, TypeError):
            raw = b""
        if len(raw) == KEY_BYTES:
            return raw
        # Something is in the slot but it is not one of our keys. Refuse to
        # overwrite it — that could be the only copy of a real key, and losing
        # it costs the person every stable token they have.
        return None
    if not create:
        return None
    key = new_key()
    try:
        _kc_write(ACCOUNT, base64.b64encode(key).decode())
    except (OSError, subprocess.SubprocessError):
        return None
    return key


def delete_key() -> bool:
    """Remove the key from the Keychain (``omna forget`` / ``omna uninstall``).

    Honours the off-switch exactly like every other function here, because
    ``OMNA_REGISTRY_ENCRYPTION=off`` has to mean *no Keychain access at all* —
    otherwise a test run or a CI job would reach into the developer's own login
    keychain. The cost is that someone who turns encryption off and then
    uninstalls leaves an unused key behind; an unused key opens nothing.
    """
    if not keychain_supported():
        return False
    return _kc_delete(ACCOUNT)


# ------------------------------------------------------------------- envelope
def seal(data: dict, key: bytes) -> str:
    nonce = os.urandom(NONCE_BYTES)
    ct = AESGCM(key).encrypt(nonce, json.dumps(data).encode("utf-8"), AAD)
    return json.dumps({
        "omna_registry": 2,
        "enc": ALGORITHM,
        "nonce": base64.b64encode(nonce).decode(),
        "ct": base64.b64encode(ct).decode(),
    })


def open_sealed(text: str, key: bytes | None) -> dict:
    """Unseal an envelope, or raise RegistryLocked. Never returns partial data."""
    if key is None:
        raise RegistryLocked("no key available")
    try:
        env = json.loads(text)
        nonce = base64.b64decode(env["nonce"], validate=True)
        ct = base64.b64decode(env["ct"], validate=True)
    except (ValueError, TypeError, KeyError) as e:
        raise RegistryLocked(f"registry envelope is malformed: {e}") from e
    try:
        plain = AESGCM(key).decrypt(nonce, ct, AAD)
    except InvalidTag as e:
        raise RegistryLocked("wrong key, or the file was modified") from e
    try:
        out = json.loads(plain)
    except ValueError as e:
        raise RegistryLocked(f"registry contents are malformed: {e}") from e
    if not isinstance(out, dict):
        raise RegistryLocked("registry contents are not an object")
    return out


def is_sealed(text: str) -> bool:
    try:
        env = json.loads(text)
    except ValueError:
        return False
    return isinstance(env, dict) and "enc" in env and "ct" in env


def file_state(path: Path) -> str:
    """'missing' | 'plaintext' | 'encrypted' — readable without any key.

    Used by ``omna status``, which must be able to say what protects the file
    without minting a key or unlocking anything.
    """
    try:
        text = path.read_text()
    except OSError:
        return "missing"
    return "encrypted" if is_sealed(text) else "plaintext"
