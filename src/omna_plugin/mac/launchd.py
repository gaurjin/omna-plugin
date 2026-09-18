from __future__ import annotations

import os
import subprocess
from pathlib import Path
from xml.sax.saxutils import escape as _xml_escape

from .. import config

LABEL = "dev.omna.plugin"
MENUBAR_LABEL = "dev.omna.plugin.menubar"


def plist_path(label: str = LABEL) -> Path:
    return Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"


def plist_text(omna_bin: Path, log: Path, *, label: str = LABEL, args: list[str] | None = None) -> str:
    path_env = f"/usr/bin:/bin:/usr/sbin:/sbin:{omna_bin.parent}"
    omna_bin_x, log_x, path_env_x = (_xml_escape(str(v)) for v in (omna_bin, log, path_env))
    arg_strs = "".join(f"<string>{_xml_escape(a)}</string>" for a in (args or ["start"]))
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{_xml_escape(label)}</string>
  <key>ProgramArguments</key><array><string>{omna_bin_x}</string>{arg_strs}</array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{log_x}</string>
  <key>StandardErrorPath</key><string>{log_x}</string>
  <key>EnvironmentVariables</key><dict><key>PATH</key><string>{path_env_x}</string></dict>
</dict>
</plist>
"""


def _domain() -> str:
    return f"gui/{os.getuid()}"


def install(omna_bin: Path, *, label: str = LABEL, args: list[str] | None = None, log: Path | None = None) -> Path:
    p = plist_path(label)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(plist_text(omna_bin, log or config.log_path(), label=label, args=args))
    subprocess.run(["launchctl", "bootout", f"{_domain()}/{label}"], capture_output=True, check=False)
    subprocess.run(["launchctl", "bootstrap", _domain(), str(p)], check=False)
    return p


def remove(label: str = LABEL) -> None:
    subprocess.run(["launchctl", "bootout", f"{_domain()}/{label}"], capture_output=True, check=False)
    plist_path(label).unlink(missing_ok=True)


def restart(label: str = LABEL) -> None:
    subprocess.run(["launchctl", "kickstart", "-k", f"{_domain()}/{label}"], capture_output=True, check=False)


def is_loaded(label: str = LABEL) -> bool:
    r = subprocess.run(["launchctl", "print", f"{_domain()}/{label}"], capture_output=True, check=False)
    return r.returncode == 0
