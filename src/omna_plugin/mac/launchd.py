from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .. import config

LABEL = "dev.omna.plugin"


def plist_path() -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{LABEL}.plist"


def plist_text(omna_bin: Path, log: Path) -> str:
    path_env = f"/usr/bin:/bin:/usr/sbin:/sbin:{omna_bin.parent}"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key><array><string>{omna_bin}</string><string>start</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>{path_env}</string></dict>
</dict>
</plist>
"""


def _domain() -> str:
    return f"gui/{os.getuid()}"


def install(omna_bin: Path) -> Path:
    p = plist_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(plist_text(omna_bin, config.log_path()))
    subprocess.run(["launchctl", "bootout", f"{_domain()}/{LABEL}"], capture_output=True, check=False)
    subprocess.run(["launchctl", "bootstrap", _domain(), str(p)], check=False)
    return p


def remove() -> None:
    subprocess.run(["launchctl", "bootout", f"{_domain()}/{LABEL}"], capture_output=True, check=False)
    plist_path().unlink(missing_ok=True)


def restart() -> None:
    subprocess.run(["launchctl", "kickstart", "-k", f"{_domain()}/{LABEL}"], capture_output=True, check=False)


def is_loaded() -> bool:
    r = subprocess.run(["launchctl", "print", f"{_domain()}/{LABEL}"], capture_output=True, check=False)
    return r.returncode == 0
