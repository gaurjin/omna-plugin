from omna_plugin import aider


def test_init_wires_both_files_and_uninstall_reverts(monkeypatch, tmp_path):
    conf, env = tmp_path / ".aider.conf.yml", tmp_path / ".env"
    monkeypatch.setattr(aider, "conf_file", lambda: conf)
    monkeypatch.setattr(aider, "env_file", lambda: env)

    ch = aider.init(port=7799)

    assert ch["openai_base"] and ch["anthropic_base"]
    assert 'openai-api-base: "http://127.0.0.1:7799/v1"' in conf.read_text()
    assert "# added by omna\nANTHROPIC_BASE_URL=http://127.0.0.1:7799" in env.read_text()
    st = aider.status()
    assert st["openai_base"] == "http://127.0.0.1:7799/v1"
    assert st["anthropic_base"] == "http://127.0.0.1:7799"

    ch2 = aider.uninstall()
    assert ch2["openai_base"] and ch2["anthropic_base"]
    assert "openai-api-base" not in conf.read_text()
    assert "ANTHROPIC_BASE_URL" not in env.read_text()


def test_init_is_idempotent(monkeypatch, tmp_path):
    conf, env = tmp_path / ".aider.conf.yml", tmp_path / ".env"
    monkeypatch.setattr(aider, "conf_file", lambda: conf)
    monkeypatch.setattr(aider, "env_file", lambda: env)

    aider.init(port=7799)
    ch2 = aider.init(port=7799)

    assert not ch2["openai_base"] and not ch2["anthropic_base"]


def test_init_preserves_other_content_and_backs_up(monkeypatch, tmp_path):
    conf, env = tmp_path / ".aider.conf.yml", tmp_path / ".env"
    conf.write_text("dark-mode: true\nmodel: claude-opus-5\n")
    env.write_text("SOME_OTHER_KEY=value\n")
    monkeypatch.setattr(aider, "conf_file", lambda: conf)
    monkeypatch.setattr(aider, "env_file", lambda: env)

    ch = aider.init(port=7799)

    assert ch["openai_backup"] == str(conf.with_name(conf.name + ".omna-backup"))
    assert ch["anthropic_backup"] == str(env.with_name(env.name + ".omna-backup"))
    assert "dark-mode: true" in conf.read_text()
    assert "model: claude-opus-5" in conf.read_text()
    assert "SOME_OTHER_KEY=value" in env.read_text()

    aider.uninstall()
    assert "dark-mode: true" in conf.read_text() and "openai-api-base" not in conf.read_text()
    assert "SOME_OTHER_KEY=value" in env.read_text() and "ANTHROPIC_BASE_URL" not in env.read_text()
    assert not conf.with_name(conf.name + ".omna-backup").exists()
    assert not env.with_name(env.name + ".omna-backup").exists()


def test_never_overwrites_an_openai_api_base_it_did_not_set(monkeypatch, tmp_path):
    conf, env = tmp_path / ".aider.conf.yml", tmp_path / ".env"
    conf.write_text('openai-api-base: "https://someones-own-gateway.example.com"\n')
    monkeypatch.setattr(aider, "conf_file", lambda: conf)
    monkeypatch.setattr(aider, "env_file", lambda: env)

    ch = aider.init(port=7799)

    assert not ch["openai_base"] and ch["openai_backup"] is None
    assert "someones-own-gateway" in conf.read_text()
    assert not conf.with_name(conf.name + ".omna-backup").exists()


def test_never_overwrites_an_anthropic_base_url_it_did_not_set(monkeypatch, tmp_path):
    conf, env = tmp_path / ".aider.conf.yml", tmp_path / ".env"
    env.write_text("ANTHROPIC_BASE_URL=https://someones-own-gateway.example.com\n")
    monkeypatch.setattr(aider, "conf_file", lambda: conf)
    monkeypatch.setattr(aider, "env_file", lambda: env)

    ch = aider.init(port=7799)

    assert not ch["anthropic_base"]
    assert "someones-own-gateway" in env.read_text()


def test_uninstall_on_missing_files_does_not_raise(monkeypatch, tmp_path):
    monkeypatch.setattr(aider, "conf_file", lambda: tmp_path / "nope.yml")
    monkeypatch.setattr(aider, "env_file", lambda: tmp_path / "nope.env")
    ch = aider.uninstall()
    assert not any(ch.values())
