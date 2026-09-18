from __future__ import annotations

from pathlib import Path

SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
CA_NAME = "Omna Local Certificate Authority"


def _dq(value: str) -> str:
    """Escape a value for safe interpolation inside a double-quoted POSIX shell string."""
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$")


def trust_command(cert: Path) -> str:
    return f'security add-trusted-cert -d -r trustRoot -k {SYSTEM_KEYCHAIN} "{_dq(str(cert))}"'


def untrust_commands(cert: Path) -> list[str]:
    return [f'security remove-trusted-cert -d "{_dq(str(cert))}"',
            f'security delete-certificate -c "{CA_NAME}" {SYSTEM_KEYCHAIN} || true']
