from __future__ import annotations

import subprocess


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
        cmds.append(f'networksetup -setautoproxyurl "{s}" "{pac_url}"')
        cmds.append(f'networksetup -setautoproxystate "{s}" on')
    return cmds


def pac_off_commands(services: list[str]) -> list[str]:
    return [f'networksetup -setautoproxystate "{s}" off' for s in services]


def current_pac(service: str) -> tuple[str, bool]:
    r = subprocess.run(["networksetup", "-getautoproxyurl", service], capture_output=True, text=True, check=False)
    url, enabled = "", False
    for line in r.stdout.splitlines():
        if line.startswith("URL:"):
            url = line[4:].strip()
        if line.startswith("Enabled:"):
            enabled = line.split(":", 1)[1].strip().lower() == "yes"
    return url, enabled
