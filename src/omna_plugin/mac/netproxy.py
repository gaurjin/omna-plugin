from __future__ import annotations

import subprocess


def _dq(value: str) -> str:
    """Escape a value for safe interpolation inside a double-quoted POSIX shell string.

    These strings end up in a batch run as ``sudo sh <script>`` — a network service
    name comes from ``networksetup -listallnetworkservices``, which a user can rename
    to almost anything, so it must never be trusted unescaped in a root-privileged
    shell command.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"').replace("`", "\\`").replace("$", "\\$")


def parse_services(text: str) -> list[str]:
    out = []
    for line in text.splitlines()[1:]:
        line = line.strip()
        if line and not line.startswith("*"):
            out.append(line)
    return out


def list_services() -> list[str]:
    r = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True, check=False)
    return parse_services(r.stdout)


def pac_on_commands(services: list[str], pac_url: str) -> list[str]:
    cmds = []
    for s in services:
        cmds.append(f'networksetup -setautoproxyurl "{_dq(s)}" "{_dq(pac_url)}"')
        cmds.append(f'networksetup -setautoproxystate "{_dq(s)}" on')
    return cmds


def pac_off_commands(services: list[str]) -> list[str]:
    # Turning the state off alone leaves the PAC URL itself sitting in Network
    # settings (visible, though inert, in System Settings > Network > service >
    # Details > Proxies) — clear it too so uninstall leaves nothing to find.
    cmds = []
    for s in services:
        cmds.append(f'networksetup -setautoproxystate "{_dq(s)}" off')
        cmds.append(f'networksetup -setautoproxyurl "{_dq(s)}" ""')
    return cmds


def current_pac(service: str) -> tuple[str, bool]:
    r = subprocess.run(["networksetup", "-getautoproxyurl", service], capture_output=True, text=True, check=False)
    url, enabled = "", False
    for line in r.stdout.splitlines():
        if line.startswith("URL:"):
            url = line[4:].strip()
        if line.startswith("Enabled:"):
            enabled = line.split(":", 1)[1].strip().lower() == "yes"
    return url, enabled
