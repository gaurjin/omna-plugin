"""Wire VS Code's own AI chat (GitHub Copilot Chat, Cline, and similar
extensions that read VS Code's own proxy setting) to the system door.

Two things had to be verified before writing any of this, both confirmed live
on 2026-09-19 against VS Code's own bundled Node runtime
(``ELECTRON_RUN_AS_NODE=1``), not assumed from docs:

1. Door 2's Mac-wide "route AI traffic through Omna" setting does not reach
   VS Code on its own — VS Code has its own, separate ``http.proxy`` setting
   extensions opt into, unrelated to the macOS system proxy.
2. Even once pointed at the system door, VS Code's extension host (the
   process that actually makes the network calls — not the visible chat
   window, which is a separate Chromium renderer) does not automatically
   trust a certificate added to the macOS System Keychain the way Door 2
   already does for browsers. A plain HTTPS request through Omna's
   certificate failed with "unable to verify the first certificate" until
   ``NODE_EXTRA_CA_CERTS`` was set; ``launchctl setenv`` (the standard way to
   hand an environment variable to a GUI-launched app on macOS) was then
   confirmed, via ``ps`` on the real, launchd-launched extension host
   process, to actually reach it.

Two independent pieces follow from that:
- ``settings.json``: ``http.proxy`` pointed at the system door
  (``127.0.0.1:<system_port>``). A real JSON parse/modify/write — VS Code's
  own Settings UI writes clean JSON, and if the file has comments (JSONC) we
  can't safely round-trip it without risking corrupting it, so we leave it
  untouched and say so rather than guess at a text edit.
- ``NODE_EXTRA_CA_CERTS``: set for the current login session immediately
  (``launchctl setenv``) AND persisted across reboots via a small one-shot
  LaunchAgent that reruns the same command at every login — ``launchctl
  setenv`` itself does not survive a restart on its own. This is
  machine-wide for any Node/Electron app, not VS Code-specific — a side
  effect that's consistent with Door 2 already trusting Omna's certificate
  machine-wide, not a new category of exposure.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from .. import config
from . import launchd

APP_PATH = Path("/Applications/Visual Studio Code.app")
PROXY_KEY = "http.proxy"
MARK_KEY = "_omna_managed_http_proxy"
CA_ENV_LABEL = "dev.omna.plugin.node-ca-trust"


def installed() -> bool:
    return APP_PATH.exists()


def settings_file() -> Path:
    return Path.home() / "Library" / "Application Support" / "Code" / "User" / "settings.json"


def _proxy_url(system_port: int) -> str:
    return f"http://{config.DEFAULT_HOST}:{system_port}"


def init_proxy_setting(system_port: int = config.SYSTEM_PORT) -> dict:
    """Point VS Code's own ``http.proxy`` at the system door. Skips (rather
    than guesses) if the file has comments/trailing commas we can't safely
    round-trip, or if the key is already set to something we didn't set."""
    path = settings_file()
    changes = {"proxy": False, "backup": None, "skipped": None}
    text = path.read_text() if path.exists() else "{}"
    try:
        data = json.loads(text) if text.strip() else {}
    except ValueError:
        changes["skipped"] = f"{path} has comments or trailing commas — edit it by hand"
        return changes
    if PROXY_KEY in data and not data.get(MARK_KEY):
        changes["skipped"] = f"{PROXY_KEY!r} is already set in {path} — left it alone"
        return changes
    new_url = _proxy_url(system_port)
    if data.get(PROXY_KEY) == new_url and data.get(MARK_KEY):
        return changes  # idempotent: already set to exactly this
    if path.exists():
        backup = path.with_name(path.name + ".omna-backup")
        if not backup.exists():
            shutil.copyfile(path, backup)
            changes["backup"] = str(backup)
    data[PROXY_KEY] = new_url
    data[MARK_KEY] = True
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=4) + "\n")
    changes["proxy"] = True
    return changes


def revert_proxy_setting() -> dict:
    """Undo exactly what ``init_proxy_setting`` did.

    A pop-the-two-keys-and-redump would keep ``json.dumps``'s reformatting of
    every OTHER key permanently, even after uninstall. Instead: if a backup
    exists (the file already had content before we touched it), restore it
    byte-for-byte — the exact original formatting back, not a reconstruction.
    If there's no backup, ``init_proxy_setting`` created this file from
    nothing (starting from ``{}``), so it contains only our two keys; delete
    it outright rather than leave an empty shell behind."""
    changes = {"proxy": False, "backup": False}
    path = settings_file()
    backup = path.with_name(path.name + ".omna-backup")
    if backup.exists():
        is_ours = True
        if path.exists():
            try:
                is_ours = bool(json.loads(path.read_text()).get(MARK_KEY))
            except ValueError:
                is_ours = False  # can't tell — don't clobber someone's newer edit
        if is_ours:
            shutil.copyfile(backup, path)
            changes["proxy"] = True
        backup.unlink()
        changes["backup"] = True
        return changes
    if not path.exists():
        return changes
    try:
        data = json.loads(path.read_text())
    except ValueError:
        return changes
    if data.get(MARK_KEY):
        path.unlink()
        changes["proxy"] = True
    return changes


def _current_node_ca_cert() -> str | None:
    r = subprocess.run(["launchctl", "getenv", "NODE_EXTRA_CA_CERTS"], capture_output=True, text=True)
    val = r.stdout.strip()
    return val or None


def enable_node_ca_trust(cert_path: Path) -> dict:
    """Trust Omna's certificate for every Node/Electron GUI app's own network
    calls, not just what the macOS System Keychain already covers — applied
    now (this login session) and persisted at every future login. Never
    overwrites a NODE_EXTRA_CA_CERTS someone already set themselves (e.g. a
    corporate CA bundle other Node tools rely on)."""
    current = _current_node_ca_cert()
    if current and current != str(cert_path):
        return {"applied": False, "skipped": f"NODE_EXTRA_CA_CERTS is already set to {current!r} — left it alone"}
    subprocess.run(["launchctl", "setenv", "NODE_EXTRA_CA_CERTS", str(cert_path)], capture_output=True)
    launchd.install_oneshot(CA_ENV_LABEL, ["/bin/launchctl", "setenv", "NODE_EXTRA_CA_CERTS", str(cert_path)])
    return {"applied": True, "skipped": None}


def disable_node_ca_trust(cert_path: Path) -> None:
    # The LaunchAgent is unambiguously ours (its own distinct label) and is
    # always removed. The live value is only unset if it still matches what
    # we set — never blow away a value someone else has since taken over.
    if _current_node_ca_cert() == str(cert_path):
        subprocess.run(["launchctl", "unsetenv", "NODE_EXTRA_CA_CERTS"], capture_output=True)
    launchd.remove(CA_ENV_LABEL)
