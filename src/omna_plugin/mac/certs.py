from __future__ import annotations

from pathlib import Path

SYSTEM_KEYCHAIN = "/Library/Keychains/System.keychain"
CA_NAME = "Omna Local Certificate Authority"


def trust_command(cert: Path) -> str:
    return f'security add-trusted-cert -d -r trustRoot -k {SYSTEM_KEYCHAIN} "{cert}"'


def untrust_commands(cert: Path) -> list[str]:
    return [f'security remove-trusted-cert -d "{cert}"',
            f'security delete-certificate -c "{CA_NAME}" {SYSTEM_KEYCHAIN} || true']
