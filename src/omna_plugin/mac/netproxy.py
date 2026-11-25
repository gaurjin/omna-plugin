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


def parse_services(text: str, *, include_disabled: bool = False) -> list[str]:
    """A disabled service is listed as ``*Name``. Setup skips it; uninstall takes it too,
    because a service switched off after `omna init` still holds Omna's setting."""
    out = []
    for line in text.splitlines()[1:]:
        line = line.strip()
        if line.startswith("*"):
            if not include_disabled:
                continue
            line = line[1:].strip()
        if line:
            out.append(line)
    return out


def list_services(*, include_disabled: bool = False) -> list[str]:
    r = subprocess.run(["networksetup", "-listallnetworkservices"], capture_output=True, text=True, check=False)
    return parse_services(r.stdout, include_disabled=include_disabled)


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
    # It is cleared with a single space, never "": networksetup rejects an empty
    # URL with "The parameters were not valid." (#49, checked on macOS 2026-11-22).
    # Order matters: setting the URL turns auto-proxy back ON, so "off" must come
    # last (checked on a real Mac 2026-11-24: off-then-URL left "Enabled: Yes").
    cmds = []
    for s in services:
        cmds.append(f'networksetup -setautoproxyurl "{_dq(s)}" " "')
        cmds.append(f'networksetup -setautoproxystate "{_dq(s)}" off')
    return cmds


def current_pac(service: str) -> tuple[str, bool]:
    r = subprocess.run(["networksetup", "-getautoproxyurl", service], capture_output=True, text=True, check=False, timeout=5)
    url, enabled = "", False
    for line in r.stdout.splitlines():
        if line.startswith("URL:"):
            url = line[4:].strip()
        if line.startswith("Enabled:"):
            enabled = line.split(":", 1)[1].strip().lower() == "yes"
    return url, enabled
