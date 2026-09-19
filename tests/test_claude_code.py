import json

from omna_plugin import claude_code, config


def test_init_creates_settings_and_uninstall_reverts(tmp_path):
    p = tmp_path / ".claude" / "settings.json"
    ch = claude_code.init(p)
    assert ch["env"] and ch["hook"] and ch["backup"] is None
    data = json.loads(p.read_text())
    assert data["env"]["ANTHROPIC_BASE_URL"] == config.base_url()
    hook = data["hooks"]["SessionStart"][0]["hooks"][0]
    assert hook["type"] == "command" and hook["command"].endswith(" ensure")
    assert claude_code.status(p)["hook"] is True
    # idempotent
    ch2 = claude_code.init(p)
    assert not ch2["env"] and not ch2["hook"]
    assert len(json.loads(p.read_text())["hooks"]["SessionStart"]) == 1
    ch3 = claude_code.uninstall(p)
    assert ch3["env"] and ch3["hook"]
    assert json.loads(p.read_text()) == {}


def test_init_preserves_other_settings_and_backs_up(tmp_path):
    p = tmp_path / "settings.json"
    before = {
        "model": "claude-opus-5",
        "env": {"FOO": "bar"},
        "hooks": {"SessionStart": [{"hooks": [{"type": "command", "command": "echo hi"}]}], "Stop": [{"hooks": []}]},
        "permissions": {"allow": ["Bash(git *)"]},
    }
    p.write_text(json.dumps(before))
    ch = claude_code.init(p, port=7799)
    assert ch["backup"] == str(tmp_path / "settings.json.omna-backup")
    assert json.loads((tmp_path / "settings.json.omna-backup").read_text()) == before
    data = json.loads(p.read_text())
    assert data["model"] == "claude-opus-5" and data["env"]["FOO"] == "bar" and data["permissions"] == before["permissions"]
    assert data["env"]["ANTHROPIC_BASE_URL"] == "http://127.0.0.1:7799"
    assert len(data["hooks"]["SessionStart"]) == 2
    backup = tmp_path / "settings.json.omna-backup"
    assert backup.exists()
    ch2 = claude_code.uninstall(p)
    after = json.loads(p.read_text())
    assert after == before
    assert ch2["backup"] is True
    assert not backup.exists()  # leave no trace — the backup served its purpose


def test_uninstall_removes_a_leftover_backup_even_with_nothing_else_to_undo(tmp_path):
    # A backup from a previous init can outlive that init's own env/hook edits
    # (e.g. they were hand-reverted, or a prior uninstall predates this fix).
    # Uninstall must still clean it up, not just report "nothing to remove".
    p = tmp_path / "settings.json"
    p.write_text("{}")
    (tmp_path / "settings.json.omna-backup").write_text('{"old": true}')

    ch = claude_code.uninstall(p)

    assert ch["backup"] is True
    assert not ch["env"] and not ch["hook"]
    assert not (tmp_path / "settings.json.omna-backup").exists()
