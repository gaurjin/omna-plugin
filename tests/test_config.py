from pathlib import Path

from omna_plugin import config


def test_home_defaults_when_omna_home_is_unset(monkeypatch):
    monkeypatch.delenv("OMNA_HOME", raising=False)
    assert config.home() == Path.home() / ".omna"


def test_home_defaults_when_omna_home_is_set_but_empty(monkeypatch):
    # `export OMNA_HOME=` in a shell profile leaves the var set to "". `omna
    # uninstall` recursively deletes this directory, and Path("") resolves to
    # the current directory — this must fall back to the default, not become ".".
    monkeypatch.setenv("OMNA_HOME", "")
    assert config.home() == Path.home() / ".omna"


def test_home_honours_a_real_omna_home_override(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    assert config.home() == tmp_path
