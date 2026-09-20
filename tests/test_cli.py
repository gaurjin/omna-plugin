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


# ---------------------------------------------------------------- status extension line

def _fake_health(extension_last_seen, extension_version=None):
    return {
        "ok": True,
        "smart": False,
        "restore_secrets": True,
        "requests_this_run": 0,
        "extension_last_seen": extension_last_seen,
        "extension_version": extension_version,
    }


def test_status_shows_extension_connected_when_recently_seen(capsys, monkeypatch):
    # No CLI-output-testing pattern in this repo mocks `_health` directly elsewhere,
    # but it's the same monkeypatch-a-collaborator style as `no_restart`/`_continue_not_detected`
    # above, applied to the one function cmd_status calls to reach the proxy.
    now = 1_000_000.0
    monkeypatch.setattr("omna_plugin.cli.time.time", lambda: now)
    monkeypatch.setattr("omna_plugin.cli._health", lambda port: _fake_health(now - 5, "0.6.0"))

    assert main(["status"]) == 0
    out, _ = capsys.readouterr()
    assert "extension:    connected (v0.6.0)" in out


def test_status_shows_extension_not_connected_when_stale(capsys, monkeypatch):
    now = 1_000_000.0
    monkeypatch.setattr("omna_plugin.cli.time.time", lambda: now)
    # Older than the 120s freshness window used by cmd_status.
    monkeypatch.setattr("omna_plugin.cli._health", lambda port: _fake_health(now - 121, "0.5.0"))

    assert main(["status"]) == 0
    out, _ = capsys.readouterr()
    assert "extension:    not connected  → install from the Chrome Web Store" in out


def test_status_shows_extension_not_connected_when_never_seen(capsys, monkeypatch):
    now = 1_000_000.0
    monkeypatch.setattr("omna_plugin.cli.time.time", lambda: now)
    monkeypatch.setattr("omna_plugin.cli._health", lambda port: _fake_health(None))

    assert main(["status"]) == 0
    out, _ = capsys.readouterr()
    assert "extension:    not connected  → install from the Chrome Web Store" in out


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


# ---------------------------------------------------------------- enrolment
def test_enroll_sets_org_dept_and_mints_a_device_id(capsys):
    main(["enroll", "--org", "Acme Inc", "--dept", "engineering"])
    pol = Policy.load()
    assert pol.org == "Acme Inc"
    assert pol.dept == "engineering"
    assert len(pol.device_id) == 16  # token_hex(8)
    out, _ = capsys.readouterr()
    assert "Acme Inc" in out and "engineering" in out


def test_enroll_keeps_the_same_device_id_when_only_the_department_changes():
    main(["enroll", "--org", "Acme Inc", "--dept", "engineering"])
    first = Policy.load().device_id
    main(["enroll", "--dept", "sales"])
    pol = Policy.load()
    assert pol.device_id == first, "re-tagging a machine must not look like a new machine"
    assert pol.org == "Acme Inc", "--dept alone must not clear the org"
    assert pol.dept == "sales"


def test_enroll_forget_clears_the_device_id_too():
    main(["enroll", "--org", "Acme Inc"])
    assert Policy.load().device_id
    main(["enroll", "--forget"])
    pol = Policy.load()
    assert pol.org == "" and pol.dept == "" and pol.device_id == ""


def test_enroll_with_no_args_reports_not_enrolled(capsys):
    main(["enroll"])
    out, _ = capsys.readouterr()
    assert "not enrolled" in out


def test_status_shows_enrolment_when_tagged(monkeypatch, capsys):
    monkeypatch.setattr("omna_plugin.cli._health", lambda port: None)
    main(["enroll", "--org", "Acme Inc", "--dept", "engineering"])
    capsys.readouterr()
    main(["status"])
    out, _ = capsys.readouterr()
    assert "enrolled:" in out and "Acme Inc" in out and "engineering" in out


def test_report_export_then_merge_roundtrip(tmp_path, capsys):
    """The whole company story end to end: two machines export, an admin merges."""
    import json as _json
    from omna_plugin import receipts

    receipts.append({"route": "/v1/messages", "upstream": "api.anthropic.com", "status": 200, "masked": {"EMAIL": 2}, "secrets": 0, "pii": 2, "ms": 10, "mask_ms": 2, "tokens": ["EMAIL_1", "EMAIL_2"]})
    main(["enroll", "--org", "Acme Inc", "--dept", "engineering"])
    a = tmp_path / "machine-a.json"
    main(["report", "--export", str(a)])
    assert a.exists()
    payload = _json.loads(a.read_text())
    assert payload["format"] == "omna-share-1" and payload["dept"] == "engineering"

    # A second machine, different department, written by hand from the first.
    b = tmp_path / "machine-b.json"
    other = dict(payload, device_id="otherdevice", dept="sales", requests=7)
    b.write_text(_json.dumps(other))

    capsys.readouterr()
    main(["report", "--merge", str(a), str(b)])
    out, _ = capsys.readouterr()
    assert "engineering" in out and "sales" in out and "2 machines" in out


def test_report_export_warns_when_the_machine_is_not_enrolled(tmp_path, capsys):
    main(["report", "--export", str(tmp_path / "x.json")])
    _, err = capsys.readouterr()
    assert "isn't enrolled" in err


def test_report_merge_on_a_missing_file_fails_cleanly(tmp_path, capsys):
    rc = main(["report", "--merge", str(tmp_path / "nope.json")])
    _, err = capsys.readouterr()
    assert rc == 1 and "no such file" in err


# ---------------------------------------------- registry at rest (#131), in status
def _kc_fake(monkeypatch):
    from omna_plugin import vault
    store: dict[str, str] = {}
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION", raising=False)
    monkeypatch.setattr(vault, "_kc_supported", lambda: True)
    monkeypatch.setattr(vault, "_kc_read", lambda a: store.get(a))
    monkeypatch.setattr(vault, "_kc_write", lambda a, v: store.__setitem__(a, v))
    monkeypatch.setattr(vault, "_kc_delete", lambda a: store.pop(a, None) is not None)
    return store


def test_status_registry_line_says_encrypted(monkeypatch, capsys):
    from omna_plugin.cli import _registry_line
    from omna_plugin.engine import MaskingSession

    _kc_fake(monkeypatch)
    MaskingSession().mask_text("mail a@example.com")
    line = _registry_line()
    assert "encrypted" in line and "Keychain" in line and "1 value" in line


def test_status_registry_line_says_not_encrypted_without_a_keychain(capsys):
    from omna_plugin.cli import _registry_line
    from omna_plugin.engine import MaskingSession

    # The whole suite runs with encryption off: this is the Linux/CI wording.
    MaskingSession().mask_text("mail a@example.com")
    line = _registry_line()
    assert "NOT ENCRYPTED" in line and "FileVault" in line


def test_status_registry_line_is_loud_when_the_key_is_gone(monkeypatch):
    from omna_plugin.cli import _registry_line
    from omna_plugin.engine import MaskingSession

    store = _kc_fake(monkeypatch)
    MaskingSession().mask_text("mail a@example.com")
    store.clear()
    line = _registry_line()
    assert "key is GONE" in line and "omna forget" in line


def test_status_registry_line_when_nothing_is_stored():
    from omna_plugin.cli import _registry_line

    assert "empty" in _registry_line()


def test_forget_wipes_the_key_too(monkeypatch, capsys):
    from omna_plugin.engine import MaskingSession

    store = _kc_fake(monkeypatch)
    MaskingSession().mask_text("mail a@example.com")
    assert store
    main(["forget"])
    assert store == {}
    assert "Keychain" in capsys.readouterr()[0]


# -------------------------------------------------------- crash log (#132)
def test_crash_command_is_empty_and_says_nothing_was_sent(capsys):
    main(["crash"])
    out = capsys.readouterr()[0]
    assert "no crashes" in out and "Nothing has been sent anywhere" in out


def test_crash_listing_states_the_current_answer(capsys):
    from omna_plugin import crashlog

    try:
        raise ValueError("x")
    except ValueError as e:
        crashlog.record(e, where="cli")

    main(["crash"])
    assert "you have not been asked yet" in capsys.readouterr()[0]

    main(["crash", "--never"])
    capsys.readouterr()
    main(["crash"])
    assert "never sent" in capsys.readouterr()[0]


def test_never_and_always_are_remembered(capsys):
    from omna_plugin.policy import Policy

    main(["crash", "--never"])
    assert Policy.load().crash_reports == "off"
    assert "never be sent" in capsys.readouterr()[0]
    main(["crash", "--always"])
    assert Policy.load().crash_reports == "on"


def test_a_crashing_command_is_recorded_and_then_still_raises(monkeypatch, capsys):
    """The crash log must never swallow the error — the person still sees the
    normal Python failure, we just also keep a masked local copy."""
    import pytest as _pytest

    from omna_plugin import crashlog

    monkeypatch.setattr("omna_plugin.cli.cmd_version", lambda a: (_ for _ in ()).throw(RuntimeError("boom in version")))
    with _pytest.raises(RuntimeError):
        main(["version"])
    err = capsys.readouterr()[1]
    assert "omna crash" in err
    rows = crashlog.tail(5)
    assert rows[-1]["error"] == "RuntimeError" and rows[-1]["where"] == "cli:version"


def test_crash_show_and_clear(capsys):
    from omna_plugin import crashlog

    try:
        raise ValueError("a problem")
    except ValueError as e:
        crashlog.record(e, where="cli")
    main(["crash"])
    assert "ValueError" in capsys.readouterr()[0]
    main(["crash", "--show", "1"])
    assert "a problem" in capsys.readouterr()[0]
    main(["crash", "--clear"])
    assert crashlog.tail(5) == []
