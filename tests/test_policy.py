from omna_plugin import policy


def test_defaults_include_the_big_ai_hosts(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    assert "api.anthropic.com" in p.hosts
    assert "chatgpt.com" in p.hosts
    assert p.tools == {"claude-code": "on"}
    assert p.doors == {"api": True, "system": True, "deep": False}


def test_is_ai_host_matches_exact_and_subdomains(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    assert p.is_ai_host("claude.ai")
    assert p.is_ai_host("api.claude.ai")
    assert p.is_ai_host("CHATGPT.COM")
    assert not p.is_ai_host("notclaude.ai")
    assert not p.is_ai_host("github.com")


def test_save_and_reload_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    p.set_app("Cursor", "bypass")
    p.add_host("api.example-ai.com")
    p.tools["claude-code"] = "off"
    p.save()
    q = policy.Policy.load()
    assert q.apps == {"Cursor": "bypass"}
    assert "api.example-ai.com" in q.hosts
    assert q.tools["claude-code"] == "off"
    assert (tmp_path / "policy.json").stat().st_mode & 0o777 == 0o600


def test_pac_names_only_ai_hosts_and_the_system_door(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    pac = p.pac(system_port=7789)
    assert 'return "PROXY 127.0.0.1:7789"' in pac
    assert 'return "DIRECT"' in pac
    assert '"claude.ai"' in pac
    assert "github.com" not in pac


def test_allow_hosts_regexes_match_host_port_and_sni(tmp_path, monkeypatch):
    import re
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    rx = [re.compile(r, re.IGNORECASE) for r in policy.Policy.load().allow_hosts()]
    assert any(r.search("claude.ai:443") for r in rx)
    assert any(r.search("api.claude.ai:443") for r in rx)
    assert not any(r.search("notclaude.ai:443") for r in rx)
    assert not any(r.search("github.com:443") for r in rx)


def test_app_action_defaults_to_mask(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    assert p.app_action("Google Chrome") == "mask"
    p.set_app("Cursor", "bypass")
    assert p.app_action("Cursor") == "bypass"
    assert p.app_action("cursor") == "bypass"  # case-insensitive


def test_save_guarantees_0600_even_with_preexisting_tmp_file(tmp_path, monkeypatch):
    """Regression test for Bug 1: save() must guarantee 0600 permissions.

    If the .tmp file exists at loose permissions (0644), save() must still
    ensure the final policy.json is 0600, not inherit the tmp file's mode.
    """
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    policy_path = tmp_path / "policy.json"
    tmp_path_file = tmp_path / "policy.json.tmp"

    # Pre-create tmp file at loose permissions
    tmp_path_file.write_text("{}")
    tmp_path_file.chmod(0o644)

    # Now call save()
    p.save()

    # Verify final file is 0600, not 0644
    assert policy_path.stat().st_mode & 0o777 == 0o600


def test_load_gracefully_handles_structurally_wrong_json(tmp_path, monkeypatch):
    """Regression test for Bug 2: load() must handle malformed policy.json.

    If policy.json contains valid-but-wrong-shaped JSON (e.g. {"doors": []}),
    load() must fall back to defaults instead of crashing with AttributeError/TypeError.
    """
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    policy_path = tmp_path / "policy.json"

    # Write valid JSON but with wrong structure (doors is list, not dict)
    policy_path.write_text('{"doors": []}')

    # Should not raise; should return defaults
    p = policy.Policy.load()
    assert p.version == 1
    assert p.hosts == policy.DEFAULT_HOSTS
    assert p.tools == {"claude-code": "on"}
    assert p.apps == {}
    assert p.deep_apps == []
    assert p.doors == {"api": True, "system": True, "deep": False}


def test_reports_enabled_defaults_true_and_round_trips(tmp_path, monkeypatch):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    p = policy.Policy.load()
    assert p.reports_enabled is True
    p.reports_enabled = False
    p.save()
    reloaded = policy.Policy.load()
    assert reloaded.reports_enabled is False


def test_default_hosts_covers_the_major_chat_ai_sites():
    # A spot-check, not exhaustive: these are the sites a real person is
    # likely to paste sensitive text into. Added 2026-09-19 after the owner
    # asked specifically about coverage beyond the original short list.
    for host in ["meta.ai", "chat.qwen.ai", "poe.com", "character.ai", "pi.ai"]:
        assert host in policy.DEFAULT_HOSTS
