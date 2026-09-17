"""``omna`` command line.

    omna start [-d] [--port N] [--smart]   run the proxy (foreground, or -d in the background)
    omna stop                              stop the background proxy
    omna ensure                            start the background proxy if it is not running (used by the Claude Code hook)
    omna status                            is it running, what is wired, what was caught today
    omna log [-n 20] [--verify]            the local receipts (counts only, never values)
    omna mask [TEXT|-] [--smart]           mask a piece of text and print it
    omna allow VALUE                       never mask this exact value again (false positive)
    omna forget                            wipe the token registry (tokens will renumber)
    omna init [--project]                  wire Claude Code (settings.json env + SessionStart hook)
    omna uninstall [--project]             undo init
    omna version
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from datetime import date

import httpx

from . import claude_code, config, receipts


def _health(port: int) -> dict | None:
    try:
        r = httpx.get(f"{config.base_url(port)}/omna/health", timeout=1.0)
        if r.status_code == 200:
            return r.json()
    except httpx.HTTPError:
        pass
    return None


def _spawn(port: int, smart: bool) -> int:
    config.ensure_home()
    log = open(config.log_path(), "ab")
    cmd = [sys.executable, "-m", "omna_plugin.cli", "start", "--port", str(port)] + (["--smart"] if smart else [])
    p = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True, close_fds=True)
    config.pid_path().write_text(str(p.pid))
    return p.pid


def _wait_healthy(port: int, seconds: float) -> dict | None:
    deadline = time.time() + seconds
    while time.time() < deadline:
        h = _health(port)
        if h:
            return h
        time.sleep(0.2)
    return None


def cmd_start(a) -> int:
    if _health(a.port):
        print(f"omna: already running on {config.base_url(a.port)}")
        return 0
    if a.daemon:
        pid = _spawn(a.port, a.smart)
        h = _wait_healthy(a.port, 60 if a.smart else 10)
        if h:
            print(f"omna: running in the background on {config.base_url(a.port)} (pid {pid}, engine {h['engine']})")
            return 0
        print(f"omna: failed to start; see {config.log_path()}", file=sys.stderr)
        return 1
    from .proxy import run

    run(port=a.port, smart=a.smart)
    return 0


def cmd_ensure(a) -> int:
    # Used by the Claude Code SessionStart hook: must be quiet on success
    # (anything printed becomes context for the model).
    if _health(a.port):
        return 0
    _spawn(a.port, a.smart)
    return 0 if _wait_healthy(a.port, 10) else 1


def cmd_stop(a) -> int:
    p = config.pid_path()
    if not p.exists():
        if _health(a.port):
            print("omna: a proxy is running but was not started by `omna start -d`; stop it where you started it")
            return 1
        print("omna: not running")
        return 0
    pid = int(p.read_text().strip() or 0)
    try:
        os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    p.unlink(missing_ok=True)
    print("omna: stopped")
    return 0


def _today_counts() -> dict[str, int]:
    today = date.today().isoformat()
    return receipts.summary([r for r in receipts.tail(0) if str(r.get("ts", "")).startswith(today)])


def _fmt_counts(c: dict[str, int]) -> str:
    return " ".join(f"{k}×{v}" for k, v in sorted(c.items())) or "-"


def cmd_status(a) -> int:
    from .engine import engine_version
    from .proxy import __version__

    h = _health(a.port)
    print(f"omna plugin {__version__}  engine {engine_version()}")
    if h:
        print(f"proxy:        running on {config.base_url(a.port)}  (smart masking {'on' if h['smart'] else 'off'}, {h['requests_this_run']} requests this run)")
    else:
        print(f"proxy:        NOT running  → `omna start -d`")
    cc = claude_code.status(claude_code.settings_file("user"))
    wired = cc["base_url"] == config.base_url(a.port)
    print(f"claude code:  {'wired' if wired else 'not wired'} ({cc['file']}){'  hook ok' if cc['hook'] else ''}{'' if wired else '  → `omna init`'}")
    ok, n, msg = receipts.verify()
    print(f"receipts:     {n} total, {msg}; today: {_fmt_counts(_today_counts())}")
    print(f"registry:     {config.registry_path()} ({'exists' if config.registry_path().exists() else 'empty'})")
    print("what leaves this machine: the masked request, to the AI provider you were already using. Nothing goes to Omna.")
    return 0


def cmd_log(a) -> int:
    if a.verify:
        ok, n, msg = receipts.verify()
        print(f"{'OK' if ok else 'BROKEN'}: {n} receipts, {msg}")
        return 0 if ok else 1
    rows = receipts.tail(a.n)
    if not rows:
        print("no receipts yet")
        return 0
    if a.json:
        for r in rows:
            print(json.dumps(r, sort_keys=True))
        return 0
    print(f"{'time':<20} {'route':<28} {'st':>3} {'ms':>6}  masked")
    for r in rows:
        ts = str(r.get("ts", ""))[:19].replace("T", " ")
        print(f"{ts:<20} {str(r.get('route',''))[:28]:<28} {r.get('status',''):>3} {r.get('ms',''):>6}  {_fmt_counts(r.get('masked') or {})}")
    return 0


def cmd_mask(a) -> int:
    from .engine import MaskingSession

    text = sys.stdin.read() if (a.text is None or a.text == "-") else a.text
    s = MaskingSession(smart=a.smart)
    r = s.mask_text(text)
    sys.stdout.write(r.masked)
    if not r.masked.endswith("\n"):
        sys.stdout.write("\n")
    if a.counts:
        print(f"masked: {_fmt_counts(r.counts)}", file=sys.stderr)
    return 0


def cmd_allow(a) -> int:
    from .engine import MaskingSession

    MaskingSession().allow(a.value)
    print(f"omna: will not mask {a.value!r} again (ruleset {config.ruleset_path()}). Restart the proxy to apply.")
    return 0


def cmd_forget(a) -> int:
    from .engine import MaskingSession

    MaskingSession().forget()
    print("omna: token registry wiped. Restart the proxy to apply.")
    return 0


def cmd_init(a) -> int:
    path = claude_code.settings_file("project" if a.project else "user")
    ch = claude_code.init(path, a.port)
    print(f"omna: Claude Code wired via {path}")
    if ch["backup"]:
        print(f"      backup of your previous settings: {ch['backup']}")
    print(f"      env {claude_code.ENV_KEY}={config.base_url(a.port)}  ·  SessionStart hook `omna ensure`")
    print("      other tools: export ANTHROPIC_BASE_URL / OPENAI_BASE_URL to the same address (aider, SDKs, Codex CLI).")
    return 0


def cmd_uninstall(a) -> int:
    path = claude_code.settings_file("project" if a.project else "user")
    ch = claude_code.uninstall(path)
    print(f"omna: removed {'env var ' if ch['env'] else ''}{'hook ' if ch['hook'] else ''}from {path}" if any(ch.values()) else f"omna: nothing to remove in {path}")
    return 0


def cmd_version(a) -> int:
    from .engine import engine_version
    from .proxy import __version__

    print(f"omna-plugin {__version__} (engine {engine_version()})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="omna", description="Omna — mask secrets and PII before a prompt leaves your machine.")
    sub = p.add_subparsers(dest="cmd", required=True)

    def add_port(sp):
        sp.add_argument("--port", type=int, default=config.DEFAULT_PORT)

    s = sub.add_parser("start", help="run the masking proxy"); add_port(s)
    s.add_argument("-d", "--daemon", action="store_true", help="run in the background")
    s.add_argument("--smart", action="store_true", help="also run the on-device Contextual model (L3); slower, catches prose names")
    s.set_defaults(fn=cmd_start)
    s = sub.add_parser("stop", help="stop the background proxy"); add_port(s); s.set_defaults(fn=cmd_stop)
    s = sub.add_parser("ensure", help="start the background proxy if needed"); add_port(s)
    s.add_argument("--smart", action="store_true"); s.set_defaults(fn=cmd_ensure)
    s = sub.add_parser("status"); add_port(s); s.set_defaults(fn=cmd_status)
    s = sub.add_parser("log", help="show local receipts")
    s.add_argument("-n", type=int, default=20); s.add_argument("--verify", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_log)
    s = sub.add_parser("mask", help="mask a piece of text")
    s.add_argument("text", nargs="?"); s.add_argument("--smart", action="store_true"); s.add_argument("--counts", action="store_true")
    s.set_defaults(fn=cmd_mask)
    s = sub.add_parser("allow", help="never mask this value again"); s.add_argument("value"); s.set_defaults(fn=cmd_allow)
    s = sub.add_parser("forget", help="wipe the token registry"); s.set_defaults(fn=cmd_forget)
    s = sub.add_parser("init", help="wire Claude Code"); add_port(s)
    s.add_argument("--project", action="store_true", help="write ./.claude/settings.json instead of ~/.claude/settings.json")
    s.set_defaults(fn=cmd_init)
    s = sub.add_parser("uninstall", help="undo init"); s.add_argument("--project", action="store_true"); s.set_defaults(fn=cmd_uninstall)
    s = sub.add_parser("version"); s.set_defaults(fn=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
