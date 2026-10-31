"""How the curl command re-launches itself (background start, Claude Code's
session hook). The Homebrew build is one packaged program (PyInstaller): it
has no `-m`, so `omna -m omna_plugin.cli ensure` failed there — every
Homebrew version until 0.6.10 could not start in the background."""

import sys

from omna_plugin import claude_code, cli, config


def test_python_install_uses_dash_m(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    assert config.self_command() == [sys.executable, "-m", "omna_plugin.cli"]


def test_packaged_build_calls_itself_directly(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    assert config.self_command() == [sys.executable]


def test_background_start_and_session_hook_use_it(monkeypatch, tmp_path):
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    seen = {}

    class P:
        pid = 4242

    def fake_popen(cmd, **kw):
        seen["cmd"] = cmd
        return P()

    monkeypatch.setattr(cli.subprocess, "Popen", fake_popen)
    cli._spawn(7788, smart=True)
    assert seen["cmd"][:2] == [sys.executable, "start"], seen["cmd"]
    assert "-m" not in seen["cmd"]
    monkeypatch.setattr(claude_code.shutil, "which", lambda name: None)  # omna not on PATH
    hook = claude_code._omna_command()
    assert "-m omna_plugin.cli" not in hook and hook.endswith(" ensure")
