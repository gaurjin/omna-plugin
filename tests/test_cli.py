import pytest

from omna_plugin.cli import main
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


def test_enable_other_tool_only_touches_policy(monkeypatch, no_restart):
    # Neither claude_code.init nor .uninstall should be touched for a non-claude-code tool.
    monkeypatch.setattr("omna_plugin.claude_code.init", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call init for aider")))
    monkeypatch.setattr("omna_plugin.claude_code.uninstall", lambda *a, **k: (_ for _ in ()).throw(AssertionError("must not call uninstall for aider")))
    assert main(["enable", "aider"]) == 0
    assert Policy.load().tools["aider"] == "on"
    assert main(["disable", "aider"]) == 0
    assert Policy.load().tools["aider"] == "off"


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
