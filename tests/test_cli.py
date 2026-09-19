import pytest

from omna_plugin.cli import main
from omna_plugin.cli import _restart_daemon as _real_restart_daemon  # captured before the autouse fixture below can patch it
from omna_plugin.policy import Policy


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture(autouse=True)
def no_restart(monkeypatch):
    """Every policy-changing command calls _restart_daemon; never let it touch
    launchd/subprocess for real during a test — see the safety rule in the task."""
    calls = []
    monkeypatch.setattr("omna_plugin.cli._restart_daemon", lambda a=None: calls.append(a))
    return calls


@pytest.fixture(autouse=True)
def _continue_not_detected(monkeypatch):
    # Same regression class as aider/codex/vscode (2026-09-19): continue_dev's
    # paths are real per-tool dotfiles under Path.home(), not OMNA_HOME —
    # never let a test touch this machine's actual ~/.continue for real.
    monkeypatch.setattr("omna_plugin.cli.continue_dev.detected", lambda: False)


def test_mask_command(capsys):
    assert main(["mask", "key AKIAIOSFODNN7EXAMPLE mail a@example.com", "--counts"]) == 0
    out, err = capsys.readouterr()
    assert "[SECRET_AWS_KEY_1]" in out and "AKIAIOSFODNN7EXAMPLE" not in out and "a@example.com" not in out
    assert "AWS_KEY×1" in err and "EMAIL×1" in err


def test_mask_from_stdin(capsys, monkeypatch):
    import io
    monkeypatch.setattr("sys.stdin", io.StringIO("ssn 123-45-6789\n"))
    assert main(["mask", "-"]) == 0
    out, _ = capsys.readouterr()
    assert "123-45-6789" not in out and out.endswith("\n")


def test_allow_then_mask(capsys):
    main(["allow", "a@example.com"])
    capsys.readouterr()
    main(["mask", "mail a@example.com"])
    out, _ = capsys.readouterr()
    assert out.strip() == "mail a@example.com"


def test_version_and_log_empty(capsys):
    assert main(["version"]) == 0
    assert "omna-plugin" in capsys.readouterr()[0]
    assert main(["log"]) == 0
    assert "no receipts" in capsys.readouterr()[0]
    assert main(["log", "--verify"]) == 0


# ---------------------------------------------------------------- tools (Task 9)

def test_tools_empty_by_default_shows_claude_code(capsys):
    assert main(["tools"]) == 0
    out, _ = capsys.readouterr()
    assert "claude-code" in out and "on" in out


def test_enable_and_disable_claude_code_calls_claude_code_init_and_uninstall(monkeypatch, no_restart):
    calls = []
    monkeypatch.setattr("omna_plugin.claude_code.init", lambda path, port=None: calls.append(("init", path, port)) or {"backup": None})
    monkeypatch.setattr("omna_plugin.claude_code.uninstall", lambda path: calls.append(("uninstall", path)) or {"env": True, "hook": True})

    assert main(["enable", "claude-code"]) == 0
    assert Policy.load().tools["claude-code"] == "on"
    assert calls and calls[-1][0] == "init"
    assert no_restart, "enable must call _restart_daemon"

    assert main(["disable", "claude-code"]) == 0
    assert Policy.load().tools["claude-code"] == "off"
    assert calls[-1][0] == "uninstall"


def test_enable_an_unrecognised_tool_only_touches_policy(monkeypatch, no_restart):
    # A tool name omna doesn't specifically wire (e.g. Cursor) is policy-only.
    monkeypatch.setattr("omna_plugin.claude_code.init", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call init for cursor")))
    monkeypatch.setattr("omna_plugin.claude_code.uninstall", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call uninstall for cursor")))
    assert main(["enable", "cursor"]) == 0
    assert Policy.load().tools["cursor"] == "on"
    assert main(["disable", "cursor"]) == 0
    assert Policy.load().tools["cursor"] == "off"


def test_enable_aider_or_codex_refuses_when_not_on_path(monkeypatch, capsys):
    # Real regression: this used to write straight to the developer's actual
    # ~/.aider.conf.yml and ~/.env with no shutil.which() guard and no way to
    # sandbox real per-tool dotfiles the way OMNA_HOME sandboxes Omna's own
    # state — reproduced live on 2026-09-19, confirmed no data was lost, this
    # test is what should have caught it.
    monkeypatch.setattr("omna_plugin.cli.shutil.which", lambda name: None)
    monkeypatch.setattr("omna_plugin.aider.init", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not touch real dotfiles")))
    monkeypatch.setattr("omna_plugin.codex.init", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not touch real dotfiles")))

    assert main(["enable", "aider"]) == 1
    assert "not found on PATH" in capsys.readouterr().out
    assert Policy.load().tools.get("aider") != "on"

    assert main(["enable", "codex"]) == 1
    assert "not found on PATH" in capsys.readouterr().out
    assert Policy.load().tools.get("codex") != "on"


def test_enable_aider_and_codex_wire_when_on_path(monkeypatch):
    monkeypatch.setattr("omna_plugin.cli.shutil.which", lambda name: f"/usr/local/bin/{name}")
    calls = []
    monkeypatch.setattr("omna_plugin.aider.init", lambda port: calls.append(("aider", port)))
    monkeypatch.setattr("omna_plugin.codex.init", lambda path, port: calls.append(("codex", port)))

    assert main(["enable", "aider"]) == 0
    assert main(["enable", "codex"]) == 0

    assert ("aider", 7788) in calls
    assert ("codex", 7788) in calls
    assert Policy.load().tools["aider"] == "on"
    assert Policy.load().tools["codex"] == "on"


def test_disable_aider_and_codex_always_runs_even_when_not_on_path(monkeypatch):
    # Uninstall must work regardless of whether the tool is currently
    # installed, so someone can clean up after uninstalling the tool itself.
    monkeypatch.setattr("omna_plugin.cli.shutil.which", lambda name: None)
    calls = []
    monkeypatch.setattr("omna_plugin.aider.uninstall", lambda: calls.append("aider"))
    monkeypatch.setattr("omna_plugin.codex.uninstall", lambda path: calls.append("codex"))

    assert main(["disable", "aider"]) == 0
    assert main(["disable", "codex"]) == 0

    assert calls == ["aider", "codex"]


def test_enable_continue_refuses_when_not_detected(monkeypatch, capsys):
    monkeypatch.setattr("omna_plugin.cli.continue_dev.detected", lambda: False)
    monkeypatch.setattr("omna_plugin.continue_dev.init", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not touch real config")))

    assert main(["enable", "continue"]) == 1
    assert "no Continue config found" in capsys.readouterr().out
    assert Policy.load().tools.get("continue") != "on"


def test_enable_continue_wires_when_detected(monkeypatch):
    monkeypatch.setattr("omna_plugin.cli.continue_dev.detected", lambda: True)
    calls = []
    monkeypatch.setattr("omna_plugin.continue_dev.init", lambda port: calls.append(("continue", port)))

    assert main(["enable", "continue"]) == 0

    assert ("continue", 7788) in calls
    assert Policy.load().tools["continue"] == "on"


def test_disable_continue_always_runs_even_when_not_detected(monkeypatch):
    monkeypatch.setattr("omna_plugin.cli.continue_dev.detected", lambda: False)
    calls = []
    monkeypatch.setattr("omna_plugin.continue_dev.uninstall", lambda: calls.append("continue"))

    assert main(["disable", "continue"]) == 0

    assert calls == ["continue"]


# ---------------------------------------------------------------- apps / bypass / mask app / capture

def test_apps_empty_says_so(capsys):
    assert main(["apps"]) == 0
    out, _ = capsys.readouterr()
    assert "no apps" in out.lower()


def test_bypass_app_sets_policy(no_restart):
    assert main(["bypass", "app", "Cursor"]) == 0
    pol = Policy.load()
    assert pol.app_action("Cursor") == "bypass"
    assert pol.apps["Cursor"] == "bypass"
    assert no_restart


def test_mask_app_sets_policy_to_mask(no_restart):
    # First bypass, then flip it back to mask via the app-policy form of `omna mask`.
    main(["bypass", "app", "Claude"])
    assert main(["mask", "app", "Claude"]) == 0
    pol = Policy.load()
    assert pol.app_action("Claude") == "mask"


def test_mask_free_text_still_works_unchanged(capsys):
    # The pre-existing behavior test, kept verbatim, plus the exact same call
    # through the now-nargs="*" positional.
    assert main(["mask", "key AKIAIOSFODNN7EXAMPLE mail a@example.com", "--counts"]) == 0
    out, err = capsys.readouterr()
    assert "[SECRET_AWS_KEY_1]" in out and "AKIAIOSFODNN7EXAMPLE" not in out and "a@example.com" not in out
    assert "AWS_KEY×1" in err and "EMAIL×1" in err


def test_mask_unquoted_multiword_text_starting_with_app_is_not_misrouted(capsys):
    # Regression: nargs="*" used to treat ANY len(args) >= 2 starting with "app" as
    # the app-policy form, so unquoted text like `omna mask app is down` silently set
    # a bogus app policy ("is" -> mask) instead of masking the text. Only an EXACT
    # 2-token ["app", NAME] now takes that branch; anything else falls through to
    # free-text masking (joined with spaces), which is always safe.
    assert main(["mask", "app", "is", "down"]) == 0
    out, _ = capsys.readouterr()
    assert out.strip() == "app is down"
    assert "is" not in Policy.load().apps


def test_capture_app_sets_deep_apps_and_deep_door(no_restart):
    assert main(["capture", "app", "Slack"]) == 0
    pol = Policy.load()
    assert "Slack" in pol.deep_apps
    assert pol.doors["deep"] is True


# ---------------------------------------------------------------- hosts

def test_hosts_list_shows_defaults(capsys):
    assert main(["hosts"]) == 0
    out, _ = capsys.readouterr()
    assert "api.anthropic.com" in out


def test_hosts_add_and_remove(no_restart):
    assert main(["hosts", "add", "example-ai.internal"]) == 0
    assert "example-ai.internal" in Policy.load().hosts
    assert main(["hosts", "remove", "example-ai.internal"]) == 0
    assert "example-ai.internal" not in Policy.load().hosts


# ---------------------------------------------------------------- init / uninstall now touch the Mac setup

def test_init_calls_mac_setup_apply_on_darwin_unless_no_system(monkeypatch, capsys):
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr("omna_plugin.claude_code.init", lambda path, port=None: {"backup": None})
    calls = []
    monkeypatch.setattr("omna_plugin.mac.setup.apply", lambda api_port=None: calls.append(api_port) or {"sudo_rc": 0})

    assert main(["init"]) == 0
    assert calls == [7788]
    out, _ = capsys.readouterr()
    assert out.strip().splitlines()[-1] == "Omna is active. Everything you send to an AI from this Mac is masked. `omna status` any time."


def test_init_no_system_skips_mac_setup_apply(monkeypatch, capsys):
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr("omna_plugin.claude_code.init", lambda path, port=None: {"backup": None})
    monkeypatch.setattr("omna_plugin.mac.setup.apply", lambda api_port=None: (_ for _ in ()).throw(AssertionError("must not run Mac setup with --no-system")))

    assert main(["init", "--no-system"]) == 0
    out, _ = capsys.readouterr()
    assert out.strip().splitlines()[-1] == "Omna is active. Everything you send to an AI from this Mac is masked. `omna status` any time."


def test_uninstall_calls_mac_setup_revert(monkeypatch):
    monkeypatch.setattr("sys.platform", "darwin")
    monkeypatch.setattr("omna_plugin.claude_code.uninstall", lambda path: {"env": False, "hook": False})
    calls = []
    monkeypatch.setattr("omna_plugin.mac.setup.revert", lambda: calls.append(True) or {"sudo_rc": 0})

    assert main(["uninstall"]) == 0
    assert calls == [True]


# ---------------------------------------------------------------- status shows doors / apps / refused

def test_status_shows_doors_apps_and_refused_lines(capsys, monkeypatch):
    from omna_plugin import receipts as receipts_mod
    from datetime import date

    pol = Policy.load()
    pol.set_app("Claude", "bypass")
    pol.save()

    today = date.today().isoformat() + "T00:00:00"
    receipts_mod.append({"ts": today, "app": "Google Chrome", "masked": {}})
    receipts_mod.append({"ts": today, "app": "Google Chrome", "masked": {}})
    receipts_mod.append({"ts": today, "app": "Claude", "masked": {}})
    receipts_mod.append({"ts": today, "app": "Claude Desktop", "host": "api.anthropic.com", "note": "tls-refused", "masked": {}})

    assert main(["status"]) == 0
    out, _ = capsys.readouterr()
    assert "doors:" in out
    assert "apps today:" in out and "Google Chrome" in out and "×2" in out
    assert "refused:" in out and "Claude Desktop" in out and "api.anthropic.com" in out and "bypass app" in out


def test_doors_line_shows_all_off_when_proxy_not_running():
    # Regression: used to fall back to {"api": True, ...} when /omna/health couldn't
    # be reached at all, printing "api on" directly under "proxy: NOT running".
    from omna_plugin.cli import _doors_line

    assert _doors_line(None) == "doors:        api off · system off · deep off"


# ---------------------------------------------------------------- _restart_daemon's real logic

def test_restart_daemon_kicks_launchd_when_installed(monkeypatch):
    calls = []
    monkeypatch.setattr("omna_plugin.mac.launchd.plist_path", lambda: type("P", (), {"exists": lambda self: True})())
    monkeypatch.setattr("omna_plugin.mac.launchd.restart", lambda: calls.append("restart"))

    _real_restart_daemon()
    assert calls == ["restart"]


def test_restart_daemon_respawns_with_the_same_smart_and_secrets_mode(monkeypatch, tmp_path):
    monkeypatch.setattr("omna_plugin.mac.launchd.plist_path", lambda: tmp_path / "missing.plist")
    pidfile = tmp_path / "omna.pid"
    pidfile.write_text("4242")
    monkeypatch.setattr("omna_plugin.config.pid_path", lambda: pidfile)
    monkeypatch.setattr("omna_plugin.cli._health", lambda port: {"smart": True, "restore_secrets": False})
    killed = []
    monkeypatch.setattr("os.kill", lambda pid, sig: killed.append(pid))
    spawned = []
    monkeypatch.setattr("omna_plugin.cli._spawn", lambda port, smart, no_restore_secrets=False: spawned.append((port, smart, no_restore_secrets)))

    _real_restart_daemon()
    assert killed == [4242]
    assert not pidfile.exists()
    assert spawned == [(7788, True, True)]   # same smart=on, same restore_secrets=off (no_restore_secrets=True) it was already running with


def test_restart_daemon_does_not_double_spawn_a_foreground_instance(monkeypatch, tmp_path, capsys):
    # Regression: a foreground `omna start` (no -d) answers health checks but owns
    # no pidfile. The old code spawned a second process against the same port
    # anyway; it must instead do nothing but say so.
    monkeypatch.setattr("omna_plugin.mac.launchd.plist_path", lambda: tmp_path / "missing.plist")
    monkeypatch.setattr("omna_plugin.config.pid_path", lambda: tmp_path / "no-such-pidfile")
    monkeypatch.setattr("omna_plugin.cli._health", lambda port: {"smart": False, "restore_secrets": True})
    monkeypatch.setattr("omna_plugin.cli._spawn", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not spawn a second instance")))

    _real_restart_daemon()
    out, _ = capsys.readouterr()
    assert "foreground" in out and "restart it yourself" in out


def test_restart_daemon_warns_when_the_respawned_proxy_never_comes_up(monkeypatch, tmp_path, capsys):
    # Regression: the respawn's own health was never checked, so a proxy that
    # failed to come back (e.g. the old process still held the port) looked
    # identical to a successful restart — nothing told the operator to look.
    monkeypatch.setattr("omna_plugin.mac.launchd.plist_path", lambda: tmp_path / "missing.plist")
    pidfile = tmp_path / "omna.pid"
    pidfile.write_text("4242")
    monkeypatch.setattr("omna_plugin.config.pid_path", lambda: pidfile)
    monkeypatch.setattr("omna_plugin.cli._health", lambda port: {"smart": False, "restore_secrets": True})
    monkeypatch.setattr("os.kill", lambda pid, sig: None)
    monkeypatch.setattr("omna_plugin.cli._spawn", lambda port, smart, no_restore_secrets=False: 4243)
    monkeypatch.setattr("omna_plugin.cli._wait_healthy", lambda port, seconds: None)

    _real_restart_daemon()
    out, err = capsys.readouterr()
    assert "did not come back up" in err
