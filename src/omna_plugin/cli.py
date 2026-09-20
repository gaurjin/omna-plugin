"""``omna`` command line.

    omna start [-d] [--port N] [--smart]   run the proxy (foreground, or -d in the background)
    omna stop                              stop the background proxy
    omna ensure                            start the background proxy if it is not running (used by the Claude Code hook)
    omna status                            is it running, what is wired, what was caught today
    omna log [-n 20] [--verify]            the local receipts (counts only, never values)
    omna mask [TEXT|-] [--smart]           mask a piece of text and print it
    omna allow VALUE                       never mask this exact value again (false positive)
    omna forget                            wipe the token registry (tokens will renumber)
    omna crash [--show N|--send|--always|--never]  what broke here; masked on disk, sent only if you said yes
    omna verify-model                      check the on-device model against its pinned hash
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

from . import aider, claude_code, codex, config, continue_dev, crashlog, receipts
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


def _registry_line() -> str:
    """The one line that answers "where do my real values live, encrypted?".

    This is the first question a security-minded buyer asks, so it never hides
    behind a word like "exists" — it names the protection, or says plainly that
    there isn't any.
    """
    from .engine import registry_status

    r = registry_status()
    path, n, state = r["path"], r["entries"], r["at_rest"]
    if state == "empty":
        return f"registry:     {path} (empty — no values stored yet)"
    held = f"{n} value{'' if n == 1 else 's'}"
    if state == "encrypted":
        return f"registry:     {path} ({held}, encrypted — the key is in your macOS Keychain)"
    if state == "locked":
        return (f"registry:     {path} (encrypted, but the key is GONE from your Keychain — masking still\n"
                f"              works, tokens are renumbering, and nothing new is being saved."
                f"  → `omna forget` to start fresh)")
    soon = "  (the proxy will encrypt it the next time it starts)" if r["keychain"] else \
           "  (no macOS Keychain here, so file permissions are the only protection — turn FileVault on)"
    return f"registry:     {path} ({held}, NOT ENCRYPTED){soon}"


def cmd_status(a) -> int:
    from .engine import engine_version
    from .proxy import __version__

    h = _health(a.port)
    print(f"omna plugin {__version__}  engine {engine_version()}")
    if h:
        speed = f", {h['avg_mask_ms_this_run']} ms average to mask" if h.get("avg_mask_ms_this_run") else ""
        print(f"proxy:        running on {config.base_url(a.port)}  (smart masking {'on' if h['smart'] else 'off'}, secrets {'restored locally, never on disk' if h.get('restore_secrets', True) else 'redacted for good'}, {h['requests_this_run']} requests this run{speed})")
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
    print(_registry_line())
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
    print("omna: token registry wiped, and its key removed from your Keychain. Restart the proxy to apply.")
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


def cmd_dashboard(a) -> int:
    """Open the live dashboard in the browser. The daemon serves it, so it has
    to be running — say so plainly rather than opening a dead tab."""
    import webbrowser

    if not _health(a.port):
        print(f"omna: the proxy isn't running, so there's nothing to show yet.", file=sys.stderr)
        print("  start it with `omna start -d`, then run this again.", file=sys.stderr)
        return 1
    # The dashboard is token-protected (#134). The token lives in a 0600 file,
    # so this command is the easy path and reading the file is the manual one.
    url = f"{config.base_url(a.port)}/omna/dashboard?k={config.dashboard_token()}"
    print(f"omna: opening the dashboard on {config.base_url(a.port)}")
    if not webbrowser.open(url):
        print(f"  (couldn't open a browser — paste this in yourself: {url})")
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


def cmd_crash(a) -> int:
    """What broke on THIS machine, and who (if anyone) has seen it.

    The local copy is always the source of truth: sending never deletes it, so
    the person can check afterwards exactly what left.
    """
    from . import crashsend

    if a.always or a.never:
        crashlog.remember_choice(bool(a.always))
        if a.always:
            n = crashsend.send_pending()
            print(f"omna: crash reports will be sent automatically."
                  + (f" Sent {n} pending." if n else ""))
        else:
            print("omna: crash reports will never be sent. They stay in "
                  f"{crashlog.path()} for you to read.")
        return 0

    if a.clear:
        crashlog.clear()
        print("omna: crash log cleared.")
        return 0

    rows = crashlog.tail(200)
    if not rows:
        print("omna: no crashes recorded. Nothing has been sent anywhere.")
        return 0

    if a.show or a.issue:
        n = a.show or len(rows)
        if not 1 <= n <= len(rows):
            print(f"omna: there are {len(rows)} crashes; pick 1..{len(rows)}", file=sys.stderr)
            return 1
        row = rows[n - 1]
        if a.issue:
            url = crashlog.issue_url(row)
            print("omna: this opens a GitHub issue pre-filled with the report below.")
            print("      It is already masked, and it is exactly what you see here — nothing")
            print("      is collected again at send time. Close the tab to send nothing.\n")
            _print_crash(row)
            if sys.platform == "darwin":
                subprocess.run(["open", url], check=False)
                print("\nomna: opened your browser. Review it before you submit.")
            else:
                print(f"\n{url}")
            return 0
        _print_crash(row)
        return 0

    if a.send:
        pending = crashlog.unsent()
        if not pending:
            print("omna: nothing pending — everything here has already been sent.")
            return 0
        n = crashsend.send_now(pending)
        if n:
            print(f"omna: sent {n} report(s). Your local copy is unchanged — `omna crash` still shows them.")
            return 0
        print("omna: could not reach omna.dev; nothing was sent. It stays pending and will retry.",
              file=sys.stderr)
        return 1

    print(f"{'#':>3}  {'when':<20} {'where':<12} {'sent':<5} what")
    for i, r in enumerate(rows, 1):
        ts = str(r.get("ts", ""))[:19].replace("T", " ")
        sent = "yes" if r.get("sent") else "no"
        print(f"{i:>3}  {ts:<20} {str(r.get('where',''))[:12]:<12} {sent:<5} {r.get('error','')}")

    pol = Policy.load()
    setting = {"on": "sent automatically", "off": "never sent",
               "unset": "not sent — you have not been asked yet"}[pol.crash_reports]
    print(f"\nStored in {crashlog.path()}, masked by Omna's own engine before it was written.")
    print(f"Right now these are: {setting}.")
    print("  omna crash --show N   read one in full")
    print("  omna crash --send     send the pending ones now")
    print("  omna crash --always / --never   change the answer")
    print("  omna crash --issue    open a pre-filled GitHub issue instead")
    return 0


def _print_crash(r: dict) -> None:
    print(f"when:     {r.get('ts')}")
    print(f"where:    {r.get('where')}")
    print(f"error:    {r.get('error')}")
    print(f"message:  {r.get('message')}")
    print(f"versions: plugin {r.get('plugin')} · engine {r.get('engine')} · Python {r.get('python')} · {r.get('os')}")
    print("trace:")
    for f in r.get("traceback", []):
        print(f"    {f.get('file')}:{f.get('line')} in {f.get('fn')}")


def cmd_verify_model(a) -> int:
    """Re-hash the on-device Contextual model and compare it to what this
    engine was built against (#135).

    The model is the thing that decides what counts as private data, so a
    swapped one could simply stop detecting. This is the command a security
    review runs; it does the full hash every time, never a cached answer.
    """
    import omna_pii_mask

    if not hasattr(omna_pii_mask, "verify_model"):
        print("omna: this engine build has no model verification "
              f"(engine {omna_pii_mask.version()}). Upgrade the engine wheel to use it.", file=sys.stderr)
        return 1
    rows = omna_pii_mask.verify_model()
    missing = [r for r in rows if r["detail"] == "not downloaded"]
    bad = [r for r in rows if not r["ok"] and r not in missing]
    for r in rows:
        mark = "ok  " if r["ok"] else "FAIL"
        print(f"{mark}  {r['file']:<24} {r['detail']}")
    if len(missing) == len(rows):
        print("\nomna: the model isn't downloaded yet — nothing to verify. It arrives on the first\n"
              "      `--smart` run, and every file is checked against its pinned hash as it streams in.")
        return 0
    if bad:
        print(f"\nomna: {len(bad)} file(s) FAILED. That means the model on this machine is not the one\n"
              "      Omna was built against. Delete the model cache and let it download again.")
        return 1
    print("\nomna: every model file matches the hash this engine was built against.")
    return 0


def cmd_tls(a) -> int:
    """Show or change how Omna verifies the AI provider on the way OUT.

    Worth a command of its own because this is the leg people forget: Omna
    opens your request, so if something could impersonate the provider to
    Omna, it would receive a masked prompt AND your real API key.
    """
    from . import upstream_tls

    pol = Policy.load()

    if a.action == "strict" or a.action == "default":
        pol.tls_strict = (a.action == "strict")
        _save_policy(pol, a)
        if pol.tls_strict:
            print("omna: providers are now verified against the certifi bundle, not this\n"
                  "      machine's trust store — so the certificate `omna init` installed for\n"
                  "      the inbound side cannot vouch for a provider on the outbound side.")
        else:
            print("omna: back to the default — providers are verified against this machine's trust store.")
        return 0

    if a.action == "pin":
        if not a.host:
            print("omna: which host? e.g. `omna tls pin api.anthropic.com`", file=sys.stderr)
            return 1
        host = a.host.lower()
        try:
            pins = upstream_tls.fetch_pins(host)
        except OSError as e:
            print(f"omna: could not reach {host}: {e}", file=sys.stderr)
            return 1
        if not pins:
            print(f"omna: {host} presented no certificate to pin", file=sys.stderr)
            return 1
        print(f"omna: {host} is currently presenting these public keys, leaf first:")
        for i, pin in enumerate(pins):
            print(f"  [{i}] {pin}" + ("   <- leaf (rotates most often)" if i == 0 else
                                      "   <- intermediate (safer to pin)"))
        if not a.save:
            print("\nNothing was saved. Add `--save` to pin, and read this first:")
            print("  Pinning means Omna REFUSES to send if the certificate stops matching.")
            print("  Providers rotate certificates. When they do, you must run this again")
            print("  or Omna will stop working against that host. Pin the intermediate if")
            print("  you can — it survives leaf rotation.")
            return 0
        pol.tls_pins[host] = pins
        _save_policy(pol, a)
        print(f"\nomna: pinned {len(pins)} key(s) for {host}. Remove with `omna tls unpin {host}`.")
        return 0

    if a.action == "unpin":
        if not a.host:
            print("omna: which host?", file=sys.stderr)
            return 1
        if pol.tls_pins.pop(a.host.lower(), None) is None:
            print(f"omna: {a.host} was not pinned")
            return 0
        _save_policy(pol, a)
        print(f"omna: unpinned {a.host}")
        return 0

    # no action: show the state
    mode = "strict (certifi bundle)" if pol.tls_strict else "this machine's trust store (default)"
    print(f"outbound verification: {mode}")
    if pol.tls_pins:
        print("pinned hosts:")
        for host, pins in sorted(pol.tls_pins.items()):
            print(f"  {host}: {len(pins)} key(s)")
        print("\nA pinned host stops working if its certificate rotates. Re-run")
        print("`omna tls pin <host> --save` when that happens.")
    else:
        print("pinned hosts: none  (pinning is off by default — an unattended pin is a time bomb)")
    print("\n  omna tls strict          verify providers against certifi, not your trust store")
    print("  omna tls default         back to your machine's trust store")
    print("  omna tls pin HOST        show the live keys for HOST (add --save to pin them)")
    print("  omna tls unpin HOST      remove a pin")
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
    s = sub.add_parser("dashboard", help="open the live dashboard in your browser")
    add_port(s); s.set_defaults(fn=cmd_dashboard)
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
    s = sub.add_parser("crash", help="what broke on this machine (kept locally; sent only if you said yes)")
    s.add_argument("--show", type=int, metavar="N", help="print crash N in full")
    s.add_argument("--send", action="store_true", help="send the pending reports now")
    s.add_argument("--issue", action="store_true", help="open a GitHub issue pre-filled with the report instead")
    s.add_argument("--always", action="store_true", help="send crash reports automatically from now on")
    s.add_argument("--never", action="store_true", help="never send crash reports (they stay on this machine)")
    s.add_argument("--clear", action="store_true", help="delete the local crash log")
    s.set_defaults(fn=cmd_crash)
    s = sub.add_parser("verify-model", help="re-hash the on-device model and check it against its pinned hash")
    s.set_defaults(fn=cmd_verify_model)
    s = sub.add_parser("tls", help="how Omna verifies the AI provider on the way out")
    s.add_argument("action", nargs="?", choices=["strict", "default", "pin", "unpin"])
    s.add_argument("host", nargs="?")
    s.add_argument("--save", action="store_true", help="actually store the pins that `pin` shows")
    add_port(s); s.set_defaults(fn=cmd_tls)
    s = sub.add_parser("version"); s.set_defaults(fn=cmd_version)
    return p


def maybe_ask_about_crashes(cmd: str) -> None:
    """Ask the one crash-reporting question, at the right moment or not at all.

    Four gates, all of which must pass (#132):
      - something actually broke and has not been sent;
      - we have never asked (a "no" is final);
      - there is a real terminal — never prompt a script, a hook, or a daemon;
      - this is not `ensure`, which the Claude Code SessionStart hook runs, and
        which must stay silent because anything it prints becomes model context.
    After a yes, anything still pending is sent immediately.
    """
    if cmd in ("ensure", "menubar", "start"):
        return
    try:
        if not (sys.stdin.isatty() and sys.stderr.isatty()):
            return
        if not crashlog.should_ask():
            if crashlog.may_send():
                from . import crashsend

                crashsend.send_pending()
            return
        from . import crashsend

        if crashsend.ask_and_remember(crashlog.unsent()):
            crashsend.send_pending()
    except Exception:
        return  # consent plumbing must never break a command


def main(argv: list[str] | None = None) -> int:
    a = build_parser().parse_args(argv)
    try:
        rc = a.fn(a)
        maybe_ask_about_crashes(a.cmd)
        return rc
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException as e:
        # Record it locally (masked, never sent — see crashlog.py) and then let
        # it surface exactly as it would have, so nothing is swallowed.
        crashlog.record(e, where=f"cli:{a.cmd}")
        print(f"omna: this crashed. It was recorded locally — run `omna crash` to see it "
              f"(nothing was sent anywhere).", file=sys.stderr)
        raise


if __name__ == "__main__":
    sys.exit(main())
