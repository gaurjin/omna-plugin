from omna_plugin import continue_dev


def test_no_op_when_config_file_does_not_exist(monkeypatch, tmp_path):
    monkeypatch.setattr(continue_dev, "config_file", lambda: tmp_path / "config.yaml")
    ch = continue_dev.init(port=7799)
    assert ch["models_wired"] == [] and ch["backup"] is None


def test_wires_existing_anthropic_and_openai_models_without_an_api_base(monkeypatch, tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        "name: My Config\n"
        "version: 1.0.0\n"
        "schema: v1\n"
        "models:\n"
        "  - name: Claude\n"
        "    provider: anthropic\n"
        "    model: claude-sonnet-5\n"
        "  - name: GPT\n"
        "    provider: openai\n"
        "    model: gpt-5\n"
    )
    monkeypatch.setattr(continue_dev, "config_file", lambda: p)

    ch = continue_dev.init(port=7799)

    assert sorted(ch["models_wired"]) == ["Claude", "GPT"]
    text = p.read_text()
    assert "apiBase: http://127.0.0.1:7799\n" in text  # anthropic: bare
    assert "apiBase: http://127.0.0.1:7799/v1\n" in text  # openai: /v1
    assert ch["backup"] == str(p.with_name("config.yaml.omna-backup"))


def test_preserves_comments_and_unrelated_models(monkeypatch, tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        "name: My Config  # my project\n"
        "version: 1.0.0\n"
        "schema: v1\n"
        "models:\n"
        "  # my favorite local model, do not touch\n"
        "  - name: Local Llama\n"
        "    provider: ollama\n"
        "    model: llama3\n"
        "  - name: Claude\n"
        "    provider: anthropic\n"
        "    model: claude-sonnet-5\n"
    )
    monkeypatch.setattr(continue_dev, "config_file", lambda: p)

    continue_dev.init(port=7799)

    text = p.read_text()
    assert "# my project" in text
    assert "# my favorite local model, do not touch" in text
    assert "provider: ollama" in text and "apiBase" not in text.split("provider: ollama")[1].split("\n\n")[0].split("- name: Claude")[0]


def test_never_overwrites_a_model_apiBase_it_did_not_set(monkeypatch, tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        "name: My Config\nversion: 1.0.0\nschema: v1\n"
        "models:\n"
        "  - name: Claude via corp gateway\n"
        "    provider: anthropic\n"
        "    model: claude-sonnet-5\n"
        "    apiBase: https://corp-gateway.example.com\n"
    )
    monkeypatch.setattr(continue_dev, "config_file", lambda: p)

    ch = continue_dev.init(port=7799)

    assert ch["models_wired"] == [] and ch["backup"] is None
    assert "corp-gateway.example.com" in p.read_text()


def test_ignores_models_with_other_providers(monkeypatch, tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        "name: My Config\nversion: 1.0.0\nschema: v1\n"
        "models:\n"
        "  - name: Local\n"
        "    provider: ollama\n"
        "    model: llama3\n"
    )
    monkeypatch.setattr(continue_dev, "config_file", lambda: p)

    ch = continue_dev.init(port=7799)

    assert ch["models_wired"] == [] and ch["backup"] is None


def test_init_is_idempotent(monkeypatch, tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        "name: My Config\nversion: 1.0.0\nschema: v1\n"
        "models:\n  - name: Claude\n    provider: anthropic\n    model: claude-sonnet-5\n"
    )
    monkeypatch.setattr(continue_dev, "config_file", lambda: p)

    continue_dev.init(port=7799)
    ch2 = continue_dev.init(port=7799)

    assert ch2["models_wired"] == []


def test_uninstall_reverts_only_what_was_added(monkeypatch, tmp_path):
    p = tmp_path / "config.yaml"
    p.write_text(
        "name: My Config\nversion: 1.0.0\nschema: v1\n"
        "models:\n"
        "  - name: Claude\n    provider: anthropic\n    model: claude-sonnet-5\n"
        "  - name: Claude via corp gateway\n    provider: anthropic\n    model: claude-sonnet-5\n    apiBase: https://corp-gateway.example.com\n"
    )
    monkeypatch.setattr(continue_dev, "config_file", lambda: p)
    continue_dev.init(port=7799)

    ch = continue_dev.uninstall()

    assert ch["models_unwired"] == ["Claude"]
    text = p.read_text()
    assert "apiBase" not in text.split("name: Claude\n")[1].split("- name:")[0]
    assert "corp-gateway.example.com" in text  # the deliberately-set one survives
    assert not p.with_name("config.yaml.omna-backup").exists()


def test_uninstall_on_missing_file_does_not_raise(monkeypatch, tmp_path):
    monkeypatch.setattr(continue_dev, "config_file", lambda: tmp_path / "nope" / "config.yaml")
    ch = continue_dev.uninstall()
    assert ch["models_unwired"] == [] and not ch["backup"]


def test_malformed_yaml_is_skipped_not_corrupted(monkeypatch, tmp_path):
    p = tmp_path / "config.yaml"
    bad = "models: [this is not: valid: yaml: at: all\n"
    p.write_text(bad)
    monkeypatch.setattr(continue_dev, "config_file", lambda: p)

    ch = continue_dev.init(port=7799)

    assert ch["models_wired"] == []
    assert ch.get("skipped")
    assert p.read_text() == bad
