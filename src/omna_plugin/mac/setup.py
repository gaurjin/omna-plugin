"""`omna init` on a Mac: create the CA, trust it, point the system at the PAC, keep the
daemon alive across reboots. The two privileged actions run as ONE `sudo sh` batch so
the person types their password once, and the batch is printed before it runs."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

from .. import config
from ..system_door import ensure_ca
from . import app_bundle, certs, launchd, netproxy


def plan(*, services: list[str], cert: Path, pac_url: str) -> list[str]:
    return [certs.trust_command(cert), *netproxy.pac_on_commands(services, pac_url)]


def revert_plan(*, services: list[str], cert: Path) -> list[str]:
    return [*netproxy.pac_off_commands(services), *certs.untrust_commands(cert)]


def _run_batch(lines: list[str], why: str) -> int:
    script = config.home() / "setup.sh"
    fd = os.open(script, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o700)
    with os.fdopen(fd, "w") as f:
        f.write("set -e\n" + "\n".join(lines) + "\n")
    print(f"omna: {why} — these {len(lines)} commands will run as administrator (one password prompt):")
    for l in lines:
        print("      " + l)
    return subprocess.run(["sudo", "sh", str(script)], check=False).returncode


def apply(api_port: int = config.DEFAULT_PORT) -> dict:
    cert = ensure_ca(config.ca_dir())
    services = netproxy.list_services()
    pac_url = f"{config.base_url(api_port)}/omna/proxy.pac"
    rc = _run_batch(plan(services=services, cert=cert, pac_url=pac_url), "certificate + system proxy")
    omna_bin = Path(shutil.which("omna") or sys.argv[0]).resolve()
    plist = launchd.install(omna_bin)
    menubar_plist = launchd.install(omna_bin, label=launchd.MENUBAR_LABEL, args=["menubar"], log=config.menubar_log_path())
    app_path = app_bundle.install(omna_bin)
    return {
        "cert": str(cert),
        "services": services,
        "pac_url": pac_url,
        "sudo_rc": rc,
        "launchd": str(plist),
        "menubar_launchd": str(menubar_plist),
        "app_bundle": str(app_path),
    }


def revert() -> dict:
    cert = config.ca_dir() / "mitmproxy-ca-cert.pem"
    services = netproxy.list_services()
    launchd.remove()
    launchd.remove(label=launchd.MENUBAR_LABEL)
    app_bundle.disable_login_item()
    app_bundle.remove()
    rc = _run_batch(revert_plan(services=services, cert=cert), "remove certificate + system proxy") if cert.exists() else 0
    return {"services": services, "sudo_rc": rc}


def status() -> dict:
    cert = config.ca_dir() / "mitmproxy-ca-cert.pem"
    services = netproxy.list_services()
    return {"cert_exists": cert.exists(), "pac": {s: netproxy.current_pac(s) for s in services}, "launchd": launchd.is_loaded()}
