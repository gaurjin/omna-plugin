"""``omna`` command line.

    omna start [-d] [--port N] [--smart]   run the proxy (foreground, or -d in the background)
    omna stop                              stop the background proxy
    omna ensure                            start the background proxy if it is not running (used by the Claude Code hook)
    omna status                            is it running, what is wired, what was caught today
    omna log [-n 20] [--verify]            the local receipts (counts only, never values)
    omna mask [TEXT|-] [--smart]           mask a piece of text and print it
    omna allow VALUE                       never mask this exact value again (false positive)
    omna forget                            wipe the token registry (tokens will renumber)
    omna report [--days 7] [--json|--html F] weekly summary from the receipts
    omna init [--project] [--no-system]    wire Claude Code (settings.json env + SessionStart hook);
                                            on a Mac, also trust the certificate + set the system proxy
    omna uninstall [--project]             undo init (Claude Code + Mac system proxy/certificate)
    omna menubar                           a status icon: on/off, what's covered, Uninstall (auto-starts on a Mac)
    omna tools                             show tool policy (on/off)
    omna enable TOOL / omna disable TOOL   turn a tool on/off (claude-code, aider, codex also wire/unwire it)
    omna apps                              show app policy (mask/bypass)
    omna bypass app NAME                   never mask this app's traffic (still receipted)
    omna mask app NAME                     mask this app's traffic (the default)
    omna capture app NAME                  Stage 3: deep-capture an app that ignores the system proxy
    omna hosts [add|remove HOST]           show/add/remove the hostnames counted as AI
    omna version
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

import httpx

from . import aider, claude_code, codex, config, continue_dev, receipts
from .policy import Policy


def _health(port: int) -> dict | None:
    try:
        r = httpx.get(f"{config.base_url(port)}/omna/health", timeout=1.0)
        if r.status_code == 200:
            return r.json()
    except httpx.HTTPError:
        pass
    return None


def _spawn(port: int, smart: bool, no_restore_secrets: bool = False) -> int:
    config.ensure_home()
    log = open(config.log_path(), "ab")
    cmd = [sys.executable, "-m", "omna_plugin.cli", "start", "--port", str(port)] + (["--smart"] if smart else []) + (["--no-restore-secrets"] if no_restore_secrets else [])
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


def _restart_daemon(a=None) -> None:
    """Called after every policy save. Real behavior (never exercised by a test,
    which always monkeypatches this by name — see the safety rule): if the Mac
    launchd job is installed, kick it; else if a background (`-d`) proxy is
    tracked by a pidfile, stop it and re-spawn it detached with the SAME
    smart/restore_secrets it was already running with; else — including a
    foreground instance that answers health checks but owns no pidfile, which
    this process cannot safely restart from the outside — do nothing but say so."""
    from .mac import launchd

    if launchd.plist_path().exists():
        launchd.restart()
        return
    port = getattr(a, "port", None) or config.DEFAULT_PORT
    p = config.pid_path()
    if not p.exists():
        if _health(port):
            print(f"omna: a proxy is running in the foreground on {config.base_url(port)}; restart it yourself to apply the new policy")
        return
    h = _health(port) or {}
    smart = bool(h.get("smart", False))
    no_restore_secrets = not h.get("restore_secrets", True)
    try:
        os.kill(int(p.read_text().strip() or 0), signal.SIGTERM)
    except (ProcessLookupError, ValueError):
        pass
    p.unlink(missing_ok=True)
    _spawn(port, smart, no_restore_secrets)
    if not _wait_healthy(port, 60 if smart else 10):
        print(f"omna: policy saved, but the proxy did not come back up; see {config.log_path()}", file=sys.stderr)


def _save_policy(pol: Policy, a=None) -> None:
    pol.save()
    _restart_daemon(a)
    print("omna: policy saved; restarting → omna restart")


def cmd_start(a) -> int:
    if _health(a.port):
        print(f"omna: already running on {config.base_url(a.port)}")
        return 0
    if a.daemon:
        pid = _spawn(a.port, a.smart, a.no_restore_secrets)
        h = _wait_healthy(a.port, 60 if a.smart else 10)
        if h:
            print(f"omna: running in the background on {config.base_url(a.port)} (pid {pid}, engine {h['engine']})")
            return 0
        print(f"omna: failed to start; see {config.log_path()}", file=sys.stderr)
        return 1
    from . import daemon

    daemon.run(api_port=a.port, smart=a.smart, restore_secrets=not a.no_restore_secrets)
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


def _today_receipts() -> list[dict]:
    today = date.today().isoformat()
    return [r for r in receipts.tail(0) if str(r.get("ts", "")).startswith(today)]


def _today_counts() -> dict[str, int]:
    return receipts.summary(_today_receipts())


def _fmt_counts(c: dict[str, int]) -> str:
    return " ".join(f"{k}×{v}" for k, v in sorted(c.items())) or "-"


def _doors_line(h: dict | None) -> str:
    # Deliberately simple: on/off per door from /omna/health's `doors` dict.
    # A "(PAC on Wi-Fi)" style detail from mac.setup.status() was considered but
    # dropped — that reads real network state via `networksetup` on every
    # `omna status`, which is unnecessary work for a status line (see report).
    doors = (h or {}).get("doors") or {"api": False, "system": False, "deep": False}
    return "doors:        api {} · system {} · deep {}".format(
        *("on" if doors.get(k) else "off" for k in ("api", "system", "deep"))
    )


def _apps_today_line(pol: Policy, recs_today: list[dict]) -> str:
    counts: dict[str, int] = {}
    for r in recs_today:
        app = r.get("app")
        if app:
            counts[app] = counts.get(app, 0) + 1
    parts = []
    for app in sorted(counts):
        suffix = " (bypassed)" if pol.app_action(app) == "bypass" else ""
        parts.append(f"{app} ×{counts[app]}{suffix}")
    for app in sorted(pol.apps):
        if app not in counts:
            parts.append(f"{app} — not seen")
    return "apps today:   " + (" · ".join(parts) if parts else "none seen yet")


def _refused_line(recs_today: list[dict]) -> str:
    counts: dict[tuple[str, str], int] = {}
    for r in recs_today:
        if r.get("note") == "tls-refused":
            key = (r.get("app") or "unknown app", r.get("host") or "?")
            counts[key] = counts.get(key, 0) + 1
    if not counts:
        return "refused:      none today"
    parts = [f'{app} → {host} ×{n} (pinned)  → omna bypass app "{app}"' for (app, host), n in sorted(counts.items())]
    return "refused:      " + " · ".join(parts)


def cmd_status(a) -> int:
    from .engine import engine_version
    from .proxy import __version__

    h = _health(a.port)
    print(f"omna plugin {__version__}  engine {engine_version()}")
    if h:
        print(f"proxy:        running on {config.base_url(a.port)}  (smart masking {'on' if h['smart'] else 'off'}, secrets {'restored locally, never on disk' if h.get('restore_secrets', True) else 'redacted for good'}, {h['requests_this_run']} requests this run)")
    else:
        print(f"proxy:        NOT running  → `omna start -d`")
    cc = claude_code.status(claude_code.settings_file("user"))
    wired = cc["base_url"] == config.base_url(a.port)
    print(f"claude code:  {'wired' if wired else 'not wired'} ({cc['file']}){'  hook ok' if cc['hook'] else ''}{'' if wired else '  → `omna init`'}")
    if h:
        last = h.get("extension_last_seen")
        if last and (time.time() - last) < 120:
            print(f"extension:    connected (v{h.get('extension_version') or '?'})")
        else:
            print("extension:    not connected  → install from the Chrome Web Store")
    if shutil.which("aider"):
        ast = aider.status()
        aw = ast["openai_base"] == f"{config.base_url(a.port)}/v1" or ast["anthropic_base"] == config.base_url(a.port)
        print(f"aider:        {'wired' if aw else 'not wired'}{'' if aw else '  → `omna enable aider`'}")
    if shutil.which("codex"):
        xst = codex.status(codex.settings_file())
        xw = xst["base_url"] == f"{config.base_url(a.port)}/v1"
        print(f"codex cli:    {'wired' if xw else 'not wired'}{'' if xw else '  → `omna enable codex`'}")
    if continue_dev.detected():
        cst = continue_dev.status()
        print(f"continue:     {'wired' if cst['wired'] else 'not wired'}{'' if cst['wired'] else '  → `omna enable continue`'}")
    pol = Policy.load()
    if pol.org or pol.dept:
        print(f"enrolled:     {pol.org or '(no org)'} / {pol.dept or '(no department)'}  (device {pol.device_id})")
    ok, n, msg = receipts.verify()
    off_note = "  (OFF — nothing new is being logged)" if not pol.reports_enabled else ""
    print(f"receipts:     {n} total, {msg}; today: {_fmt_counts(_today_counts())}{off_note}")
    print(f"registry:     {config.registry_path()} ({'exists' if config.registry_path().exists() else 'empty'})")
    recs_today = _today_receipts()
    print(_doors_line(h))
    print(_apps_today_line(pol, recs_today))
    print(_refused_line(recs_today))
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
    # `a.text` is a list (nargs="*") so that `omna mask app NAME` (set an app's
    # policy action to "mask") and the original `omna mask TEXT [--smart] [--counts]`
    # (mask a piece of text) can share one subcommand name — see the report for why.
    args: list[str] = a.text
    if len(args) == 2 and args[0] == "app":
        name = args[1]
        pol = Policy.load()
        pol.set_app(name, "mask")
        _save_policy(pol, a)
        print(f'omna: {name!r} → mask (default: every request from this app is masked)')
        return 0

    from .engine import MaskingSession

    if not args:
        text = sys.stdin.read()
    elif len(args) == 1:
        text = sys.stdin.read() if args[0] == "-" else args[0]
    else:
        text = " ".join(args)
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


def _auto_wire_other_tools(port: int) -> None:
    """Wire aider and Codex CLI too, but only if they're actually installed —
    `omna init` shouldn't scatter config files for tools the person doesn't use.
    Never let one tool's failure (e.g. a read-only config file) stop `omna init`
    before it reaches the Mac system-proxy + certificate setup that follows."""
    if shutil.which("aider"):
        try:
            ch = aider.init(port)
            bits = []
            if ch["openai_base"]:
                bits.append(f"openai-api-base in {aider.conf_file()}")
            if ch["anthropic_base"]:
                bits.append(f"ANTHROPIC_BASE_URL in {aider.env_file()}")
            if bits:
                print(f"omna: aider wired — {' · '.join(bits)}")
        except OSError as e:
            print(f"omna: WARNING — could not wire aider ({e}); everything else continues")
    if shutil.which("codex"):
        try:
            ch = codex.init(codex.settings_file(), port)
            if ch["base_url"]:
                print(f"omna: Codex CLI wired via {codex.settings_file()}")
        except OSError as e:
            print(f"omna: WARNING — could not wire Codex CLI ({e}); everything else continues")
    if continue_dev.detected():
        try:
            ch = continue_dev.init(port)
            if ch["models_wired"]:
                print(f"omna: Continue wired — {', '.join(ch['models_wired'])} in {continue_dev.config_file()}")
        except OSError as e:
            print(f"omna: WARNING — could not wire Continue ({e}); everything else continues")


def cmd_init(a) -> int:
    path = claude_code.settings_file("project" if a.project else "user")
    ch = claude_code.init(path, a.port)
    print(f"omna: Claude Code wired via {path}")
    if ch["backup"]:
        print(f"      backup of your previous settings: {ch['backup']}")
    print(f"      env {claude_code.ENV_KEY}={config.base_url(a.port)}  ·  SessionStart hook `omna ensure`")
    _auto_wire_other_tools(a.port)
    print("      other tools: export ANTHROPIC_BASE_URL / OPENAI_BASE_URL to the same address (Cursor BYOK, SDKs).")
    if a.no_system:
        print("      Mac system proxy + certificate: skipped (--no-system) — Claude Code only.")
    elif sys.platform == "darwin":
        from .mac import setup as mac_setup

        res = mac_setup.apply(api_port=a.port)
        print("      Mac: system proxy + certificate installed — every AI app on this Mac is masked, not just Claude Code.")
        print("      Mac: a menu-bar icon now shows Omna's status — click it any time to see what's covered, or to uninstall.")
        print("      Mac: quit the icon any time and re-open \"Omna Plugin\" from Spotlight — turn on its Launch at Login to skip that step.")
        vs = res.get("vscode")
        if vs is not None:
            skip = vs.get("skipped")
            if vs.get("proxy") and not skip:
                print("      Mac: VS Code wired too — Copilot Chat, Cline, and similar extensions are masked.")
            elif skip:
                print(f"      Mac: WARNING — VS Code was NOT fully wired ({skip}); its AI chat may not be masked.")
    # Printed whether the Mac setup just ran or was intentionally skipped (--no-system
    # or a non-Mac platform); Claude Code is wired either way, which is the sense in
    # which Omna is "active" here.
    print("Omna is active. Everything you send to an AI from this Mac is masked. `omna status` any time.")
    return 0


def cmd_menubar(a) -> int:
    from . import menubar

    return menubar.run(a.port)


def cmd_uninstall(a) -> int:
    path = claude_code.settings_file("project" if a.project else "user")
    ch = claude_code.uninstall(path)
    print(f"omna: removed {'env var ' if ch['env'] else ''}{'hook ' if ch['hook'] else ''}{'backup file ' if ch['backup'] else ''}from {path}" if any(ch.values()) else f"omna: nothing to remove in {path}")
    ach = aider.uninstall()
    if ach["openai_base"] or ach["anthropic_base"]:
        print(f"omna: removed aider's Omna settings from {aider.conf_file()} / {aider.env_file()}")
    cch = codex.uninstall(codex.settings_file())
    if cch["base_url"]:
        print(f"omna: removed Codex CLI's Omna setting from {codex.settings_file()}")
    xch = continue_dev.uninstall()
    if xch["models_unwired"]:
        print(f"omna: removed Continue's Omna setting from {', '.join(xch['models_unwired'])}")
    if sys.platform == "darwin":
        from .mac import setup as mac_setup

        res = mac_setup.revert()
        print("      Mac: system proxy + certificate removed, menu-bar app and Launch at Login removed.")
        if not res.get("home_removed", True):
            print(f"      Mac: WARNING — could not delete {config.home()} ({res['home_error']}); "
                  f"registry/receipts may still hold real values, remove it by hand.")
    return 0


def cmd_tools(a) -> int:
    pol = Policy.load()
    if not pol.tools:
        print("omna: no tools configured")
        return 0
    for name, state in sorted(pol.tools.items()):
        print(f"{name:<15} {state}")
    return 0


def _set_tool(a, state: str) -> int:
    pol = Policy.load()
    pol.tools[a.tool] = state
    if a.tool == "claude-code":
        path = claude_code.settings_file("user")
        if state == "on":
            claude_code.init(path, a.port)
        else:
            claude_code.uninstall(path)
    elif a.tool == "aider":
        if state == "off":
            aider.uninstall()
        elif shutil.which("aider"):
            aider.init(a.port)
        else:
            print("omna: aider not found on PATH — install it first, then `omna enable aider`")
            return 1
    elif a.tool == "codex":
        path = codex.settings_file()
        if state == "off":
            codex.uninstall(path)
        elif shutil.which("codex"):
            codex.init(path, a.port)
        else:
            print("omna: codex not found on PATH — install it first, then `omna enable codex`")
            return 1
    elif a.tool == "continue":
        if state == "off":
            continue_dev.uninstall()
        elif continue_dev.detected():
            continue_dev.init(a.port)
        else:
            print(f"omna: no Continue config found at {continue_dev.config_file()} — "
                  f"run Continue at least once (it creates this file itself), then `omna enable continue`")
            return 1
    _save_policy(pol, a)
    print(f"omna: {a.tool} → {state}")
    return 0


def cmd_enable(a) -> int:
    return _set_tool(a, "on")


def cmd_disable(a) -> int:
    return _set_tool(a, "off")


def cmd_apps(a) -> int:
    pol = Policy.load()
    if not pol.apps:
        print("omna: no apps configured (default action for every app is mask)")
        return 0
    for name, action in sorted(pol.apps.items()):
        print(f"{name:<24} {action}")
    return 0


def cmd_bypass(a) -> int:
    pol = Policy.load()
    pol.set_app(a.name, "bypass")
    _save_policy(pol, a)
    print(f'omna: {a.name!r} → bypass (never masked; still receipted)')
    return 0


def cmd_capture(a) -> int:
    pol = Policy.load()
    if a.name not in pol.deep_apps:
        pol.deep_apps.append(a.name)
    pol.doors["deep"] = True
    _save_policy(pol, a)
    print(f'omna: {a.name!r} → deep capture (Stage 3)')
    return 0


def cmd_hosts(a) -> int:
    pol = Policy.load()
    if a.action is None:
        for h in pol.hosts:
            print(h)
        return 0
    if not a.host:
        print("omna: `omna hosts add|remove HOST` needs a HOST", file=sys.stderr)
        return 1
    if a.action == "add":
        pol.add_host(a.host)
        _save_policy(pol, a)
        print(f"omna: added {a.host}")
    else:
        pol.remove_host(a.host)
        _save_policy(pol, a)
        print(f"omna: removed {a.host}")
    return 0


def cmd_enroll(a) -> int:
    pol = Policy.load()
    if a.forget:
        pol.unenroll()
        pol.save()
        print("omna: this machine is no longer tagged with an organisation or department.")
        return 0
    if not a.org and not a.dept:
        if pol.org or pol.dept:
            print(f"organisation: {pol.org or '(none)'}")
            print(f"department:   {pol.dept or '(none)'}")
            print(f"device id:    {pol.device_id or '(none)'}")
        else:
            print("omna: this machine is not enrolled.")
            print("  omna enroll --org \"Acme Inc\" --dept engineering")
        return 0
    pol.enroll(org=a.org or "", dept=a.dept or "")
    pol.save()
    print(f"omna: enrolled as {pol.org or '(no org)'} / {pol.dept or '(no department)'} (device {pol.device_id}).")
    print("  Nothing is sent anywhere. `omna report --export FILE` writes a counts-only file you can hand in.")
    return 0


def cmd_report(a) -> int:
    from . import report

    if getattr(a, "merge", None):
        shares = []
        for path in a.merge:
            try:
                shares.append(json.loads(Path(path).read_text()))
            except FileNotFoundError:
                print(f"omna: no such file: {path}", file=sys.stderr)
                return 1
            except json.JSONDecodeError as e:
                print(f"omna: {path} is not valid JSON ({e})", file=sys.stderr)
                return 1
        try:
            merged = report.merge(shares)
        except ValueError as e:
            print(f"omna: {e}", file=sys.stderr)
            return 1
        print(report.to_json(merged) if a.json else report.render_merge_text(merged))
        return 0

    d = report.build(days=a.days)
    if getattr(a, "export", None):
        payload = report.share(d)
        if not payload["org"] and not payload["dept"]:
            print(
                "omna: this machine isn't enrolled, so the export has no organisation or department.\n"
                "  Run `omna enroll --org \"Acme Inc\" --dept engineering` first if it should be grouped.",
                file=sys.stderr,
            )
        Path(a.export).write_text(report.to_json(payload) + "\n")
        print(f"omna: counts-only export written to {a.export}")
        return 0
    if a.json:
        print(report.to_json(d))
        return 0
    if a.html:
        page = report.render_html(d)
        with open(a.html, "w", encoding="utf-8") as f:
            f.write(page)
        print(f"omna: report written to {a.html}")
        return 0
    print(report.render_text(d))
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
    s.add_argument("--no-restore-secrets", action="store_true", help="redact secrets for good (engine default) instead of numbered tokens restored locally; breaks edits to lines that contain a key")
    s.set_defaults(fn=cmd_start)
    s = sub.add_parser("stop", help="stop the background proxy"); add_port(s); s.set_defaults(fn=cmd_stop)
    s = sub.add_parser("ensure", help="start the background proxy if needed"); add_port(s)
    s.add_argument("--smart", action="store_true"); s.set_defaults(fn=cmd_ensure)
    s = sub.add_parser("status"); add_port(s); s.set_defaults(fn=cmd_status)
    s = sub.add_parser("log", help="show local receipts")
    s.add_argument("-n", type=int, default=20); s.add_argument("--verify", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_log)
    s = sub.add_parser("mask", help="mask a piece of text, or `mask app NAME` to set an app's action to mask")
    s.add_argument("text", nargs="*"); s.add_argument("--smart", action="store_true"); s.add_argument("--counts", action="store_true")
    add_port(s)
    s.set_defaults(fn=cmd_mask)
    s = sub.add_parser("allow", help="never mask this value again"); s.add_argument("value"); s.set_defaults(fn=cmd_allow)
    s = sub.add_parser("forget", help="wipe the token registry"); s.set_defaults(fn=cmd_forget)
    s = sub.add_parser("init", help="wire Claude Code (and, on a Mac, the system proxy + certificate)"); add_port(s)
    s.add_argument("--project", action="store_true", help="write ./.claude/settings.json instead of ~/.claude/settings.json")
    s.add_argument("--no-system", dest="no_system", action="store_true", help="skip the Mac system-wide proxy + certificate; Claude Code only")
    s.set_defaults(fn=cmd_init)
    s = sub.add_parser("uninstall", help="undo init (Claude Code + Mac system proxy/certificate)"); s.add_argument("--project", action="store_true"); s.set_defaults(fn=cmd_uninstall)
    s = sub.add_parser("menubar", help="a status icon: on/off, what's covered, Uninstall"); add_port(s); s.set_defaults(fn=cmd_menubar)
    s = sub.add_parser("report", help="weekly summary from the receipts (text, --json, --html FILE, --export FILE, --merge FILES)")
    s.add_argument("--days", type=int, default=7); s.add_argument("--json", action="store_true"); s.add_argument("--html", metavar="FILE")
    s.add_argument("--export", metavar="FILE", help="write a counts-only file safe to hand to a company admin")
    s.add_argument("--merge", nargs="+", metavar="FILE", help="add up exported files into a company + per-department view")
    s.set_defaults(fn=cmd_report)
    s = sub.add_parser("enroll", help="tag this machine with an organisation/department for company reports")
    s.add_argument("--org", default="", help="organisation name")
    s.add_argument("--dept", default="", help="department name")
    s.add_argument("--forget", action="store_true", help="remove the tags and the device id")
    s.set_defaults(fn=cmd_enroll)
    s = sub.add_parser("tools", help="show tool policy (on/off)"); s.set_defaults(fn=cmd_tools)
    s = sub.add_parser("enable", help="turn a tool on (claude-code, aider, codex also wire it)"); s.add_argument("tool"); add_port(s); s.set_defaults(fn=cmd_enable)
    s = sub.add_parser("disable", help="turn a tool off (claude-code, aider, codex also unwire it)"); s.add_argument("tool"); add_port(s); s.set_defaults(fn=cmd_disable)
    s = sub.add_parser("apps", help="show app policy (mask/bypass)"); s.set_defaults(fn=cmd_apps)
    s = sub.add_parser("bypass", help="`bypass app NAME` — never mask this app's traffic"); add_port(s)
    s.add_argument("kind", choices=["app"]); s.add_argument("name"); s.set_defaults(fn=cmd_bypass)
    s = sub.add_parser("capture", help="`capture app NAME` — Stage 3 deep-capture for an app that ignores the system proxy"); add_port(s)
    s.add_argument("kind", choices=["app"]); s.add_argument("name"); s.set_defaults(fn=cmd_capture)
    s = sub.add_parser("hosts", help="show, or add/remove, the hostnames counted as AI"); add_port(s)
    s.add_argument("action", nargs="?", choices=["add", "remove"]); s.add_argument("host", nargs="?")
    s.set_defaults(fn=cmd_hosts)
    s = sub.add_parser("version"); s.set_defaults(fn=cmd_version)
    return p


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    return a.fn(a)


if __name__ == "__main__":
    sys.exit(main())
