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


# ---- Security review 2026-11-11, finding 8 --------------------------------
# Omna's line was appended at the END of config.toml. When the file ended with
# a [section], the line landed inside it, Codex ignored it and talked to
# OpenAI directly — while `omna status` said "wired". Codex only reads
# openai_base_url at the top level, and only for its built-in "openai"
# provider. Both write and status now read the file the way Codex does.
import tomllib  # noqa: E402

import pytest  # noqa: E402

URL = "http://127.0.0.1:7799/v1"
WITH_SECTIONS = (
    'model = "gpt-5"\n\n'
    '[projects."/Users/someone/code/app"]\n'
    'trust_level = "trusted"\n\n'
    '[mcp_servers.github]\n'
    'command = "npx"\n'
    'args = ["-y", "server-github"]\n'
)


def _top(p):
    return tomllib.loads(p.read_text()).get("openai_base_url")


def test_the_line_lands_at_the_top_level_when_the_file_ends_with_a_section(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(WITH_SECTIONS)
    ch = codex.init(p, port=7799)
    assert ch["base_url"]
    t = tomllib.loads(p.read_text())
    assert t.get("openai_base_url") == URL                     # what Codex reads
    assert "openai_base_url" not in t["mcp_servers"]["github"]   # not swallowed by a section
    assert t["projects"]["/Users/someone/code/app"]["trust_level"] == "trusted"
    st = codex.status(p)
    assert st["base_url"] == URL and st["routed"]
    codex.uninstall(p)
    assert p.read_text().strip() == WITH_SECTIONS.strip()


def test_a_line_an_older_omna_left_inside_a_section_is_moved_to_the_top(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text(WITH_SECTIONS + 'openai_base_url = "http://127.0.0.1:7788/v1"  # added by omna\n')
    assert not codex.status(p)["routed"]   # status no longer believes the misplaced line
    codex.init(p, port=7799)
    assert _top(p) == URL
    assert p.read_text().count("openai_base_url") == 1
    assert "openai_base_url" not in tomllib.loads(p.read_text())["mcp_servers"]["github"]


def test_a_multiline_array_at_the_top_does_not_confuse_the_placement(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('notify = [\n  "say",\n]\n[tui]\nstyle = "dark"\n')
    codex.init(p, port=7799)
    assert _top(p) == URL and tomllib.loads(p.read_text())["notify"] == ["say"]


def test_a_value_inside_someone_elses_section_does_not_block_wiring(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('[profiles.work]\nopenai_base_url = "https://work-gateway.example.com/v1"\n')
    assert codex.init(p, port=7799)["base_url"]
    t = tomllib.loads(p.read_text())
    assert t["openai_base_url"] == URL
    assert t["profiles"]["work"]["openai_base_url"] == "https://work-gateway.example.com/v1"


@pytest.mark.parametrize("cfg,provider", [
    ('model_provider = "azure"\n[model_providers.azure]\nbase_url = "https://x.openai.azure.com/openai"\n', "azure"),
    ('model_provider = "oss"\n', "oss"),
    ('profile = "work"\n[profiles.work]\nmodel_provider = "bedrock"\n', "bedrock"),
])
def test_status_is_not_routed_when_codex_uses_another_provider(tmp_path, cfg, provider):
    p = tmp_path / "config.toml"
    p.write_text(cfg)
    codex.init(p, port=7799)
    st = codex.status(p)
    assert st["base_url"] == URL           # the line is there ...
    assert st["provider"] == provider      # ... but Codex talks to this provider
    assert not st["routed"] and provider in st["problem"]


def test_status_names_a_file_codex_cannot_read(tmp_path):
    p = tmp_path / "config.toml"
    p.write_text('model = "gpt-5\n')       # broken TOML: Codex refuses it too
    st = codex.status(p)
    assert not st["routed"] and st["problem"]


def test_init_leaves_a_file_it_cannot_read_untouched(tmp_path):
    p = tmp_path / "config.toml"
    broken = 'model = "gpt-5\n'
    p.write_text(broken)
    ch = codex.init(p, port=7799)
    assert not ch["base_url"] and ch.get("problem")
    assert p.read_text() == broken
