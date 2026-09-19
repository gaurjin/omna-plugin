from omna_plugin import codex, config


def test_init_creates_config_and_uninstall_reverts(tmp_path):
    p = tmp_path / ".codex" / "config.toml"
    ch = codex.init(p, port=7799)
    assert ch["base_url"] and ch["backup"] is None
    text = p.read_text()
    assert 'openai_base_url = "http://127.0.0.1:7799/v1"' in text
    assert codex.status(p)["base_url"] == "http://127.0.0.1:7799/v1"
    # idempotent
    ch2 = codex.init(p, port=7799)
    assert not ch2["base_url"]
    ch3 = codex.uninstall(p)
    assert ch3["base_url"]
    assert "openai_base_url" not in p.read_text()


def test_init_preserves_other_toml_content_and_backs_up(tmp_path):
    p = tmp_path / "config.toml"
    before = (
        '# my own notes\n'
        'model = "gpt-5"\n\n'
        '[model_providers.custom]\n'
        'name = "Custom"\n'
        'base_url = "https://example.com/v1"\n'
    )
    p.write_text(before)
    ch = codex.init(p, port=7799)
    assert ch["backup"] == str(p.with_name("config.toml.omna-backup"))
    assert p.with_name("config.toml.omna-backup").read_text() == before
    text = p.read_text()
    assert "[model_providers.custom]" in text
    assert 'model = "gpt-5"' in text
    assert 'openai_base_url = "http://127.0.0.1:7799/v1"' in text
    codex.uninstall(p)
    after = p.read_text()
    assert after.strip() == before.strip()
    assert not p.with_name("config.toml.omna-backup").exists()


def test_init_replaces_a_previous_omna_value_when_the_port_changes(tmp_path):
    p = tmp_path / "config.toml"
    codex.init(p, port=7788)
    codex.init(p, port=9999)
    text = p.read_text()
    assert text.count("openai_base_url") == 1
    assert '"http://127.0.0.1:9999/v1"' in text


def test_init_never_overwrites_a_value_it_did_not_set(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('openai_base_url = "https://someone-elses-proxy.example.com"\n')
    ch = codex.init(p, port=7799)
    assert not ch["base_url"] and ch["backup"] is None
    assert "someone-elses-proxy" in p.read_text()
    assert not p.with_name("config.toml.omna-backup").exists()


def test_uninstall_never_touches_a_value_it_did_not_set(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('openai_base_url = "https://someone-elses-proxy.example.com"\n')
    ch = codex.uninstall(p)
    assert not ch["base_url"]
    assert "someone-elses-proxy" in p.read_text()


def test_uninstall_on_a_missing_file_does_not_raise(tmp_path):
    ch = codex.uninstall(tmp_path / "does-not-exist" / "config.toml")
    assert not ch["base_url"] and not ch["backup"]
