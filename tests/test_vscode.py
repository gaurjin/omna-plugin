import json
from pathlib import Path

from omna_plugin.mac import vscode


def test_init_proxy_setting_writes_clean_json_and_reverts(monkeypatch, tmp_path):
    p = tmp_path / "settings.json"
    monkeypatch.setattr(vscode, "settings_file", lambda: p)

    ch = vscode.init_proxy_setting(system_port=7799)

    assert ch["proxy"] and ch["backup"] is None and ch["skipped"] is None
    data = json.loads(p.read_text())
    assert data["http.proxy"] == "http://127.0.0.1:7799"
    assert data[vscode.MARK_KEY] is True
    # idempotent
    ch2 = vscode.init_proxy_setting(system_port=7799)
    assert not ch2["proxy"]

    ch3 = vscode.revert_proxy_setting()
    assert ch3["proxy"]
    assert not p.exists()  # no backup existed (we created it from nothing) — delete outright


def test_init_preserves_other_settings_and_backs_up(monkeypatch, tmp_path):
    p = tmp_path / "settings.json"
    before = {"editor.fontSize": 14, "workbench.colorTheme": "Default Dark"}
    p.write_text(json.dumps(before))
    monkeypatch.setattr(vscode, "settings_file", lambda: p)

    ch = vscode.init_proxy_setting(system_port=7799)

    assert ch["backup"] == str(p.with_name("settings.json.omna-backup"))
    assert json.loads(p.with_name("settings.json.omna-backup").read_text()) == before
    data = json.loads(p.read_text())
    assert data["editor.fontSize"] == 14 and data["workbench.colorTheme"] == "Default Dark"
    assert data["http.proxy"] == "http://127.0.0.1:7799"

    vscode.revert_proxy_setting()
    after = json.loads(p.read_text())
    assert after == before
    assert not p.with_name("settings.json.omna-backup").exists()


def test_revert_restores_original_bytes_exactly_not_a_reformatted_reconstruction(monkeypatch, tmp_path):
    # json.dumps(..., indent=4) on every key (not just the two Omna added)
    # would permanently reformat a person's file even after uninstall.
    # Revert must hand back the exact original bytes, comments-would-survive
    # included (this file happens to have none, but the two-space indent and
    # trailing-newline-less ending below only survive a byte-for-byte restore).
    p = tmp_path / "settings.json"
    original = '{\n  "editor.fontSize": 14,\n  "files.autoSave": "onFocusChange"\n}'
    p.write_text(original)
    monkeypatch.setattr(vscode, "settings_file", lambda: p)

    vscode.init_proxy_setting(system_port=7799)
    assert p.read_text() != original  # confirms init really did reformat it

    vscode.revert_proxy_setting()

    assert p.read_text() == original


def test_init_skips_a_file_with_comments_rather_than_risk_corrupting_it(monkeypatch, tmp_path):
    p = tmp_path / "settings.json"
    p.write_text('{\n  // my own comment\n  "editor.fontSize": 14,\n}\n')
    monkeypatch.setattr(vscode, "settings_file", lambda: p)

    ch = vscode.init_proxy_setting(system_port=7799)

    assert not ch["proxy"]
    assert ch["skipped"] is not None
    assert "// my own comment" in p.read_text()  # untouched


def test_init_never_overwrites_a_proxy_it_did_not_set(monkeypatch, tmp_path):
    p = tmp_path / "settings.json"
    p.write_text(json.dumps({"http.proxy": "http://someones-own-proxy.example.com:3128"}))
    monkeypatch.setattr(vscode, "settings_file", lambda: p)

    ch = vscode.init_proxy_setting(system_port=7799)

    assert not ch["proxy"] and ch["backup"] is None
    assert ch["skipped"] is not None
    data = json.loads(p.read_text())
    assert data["http.proxy"] == "http://someones-own-proxy.example.com:3128"


def test_revert_on_missing_file_does_not_raise(monkeypatch, tmp_path):
    monkeypatch.setattr(vscode, "settings_file", lambda: tmp_path / "nope" / "settings.json")
    ch = vscode.revert_proxy_setting()
    assert not ch["proxy"] and not ch["backup"]


class _GetenvResult:
    def __init__(self, value: str):
        self.stdout = value


def _fake_run(env_value: str, calls: list):
    def run(cmd, **k):
        calls.append(tuple(cmd))
        if list(cmd[:2]) == ["launchctl", "getenv"]:
            return _GetenvResult(env_value)
        return _GetenvResult("")
    return run


def test_enable_and_disable_node_ca_trust_drive_launchctl_and_a_launch_agent(monkeypatch, tmp_path):
    calls = []
    monkeypatch.setattr(vscode.subprocess, "run", _fake_run("", calls))  # nothing set yet
    installed = []
    monkeypatch.setattr(vscode.launchd, "install_oneshot", lambda label, args: installed.append((label, args)))
    removed = []
    monkeypatch.setattr(vscode.launchd, "remove", lambda label: removed.append(label))

    ch = vscode.enable_node_ca_trust(Path("/tmp/ca.pem"))
    assert ch == {"applied": True, "skipped": None}
    assert ("launchctl", "setenv", "NODE_EXTRA_CA_CERTS", "/tmp/ca.pem") in calls
    assert installed == [(vscode.CA_ENV_LABEL, ["/bin/launchctl", "setenv", "NODE_EXTRA_CA_CERTS", "/tmp/ca.pem"])]

    monkeypatch.setattr(vscode.subprocess, "run", _fake_run("/tmp/ca.pem", calls))  # now matches ours
    vscode.disable_node_ca_trust(Path("/tmp/ca.pem"))
    assert ("launchctl", "unsetenv", "NODE_EXTRA_CA_CERTS") in calls
    assert removed == [vscode.CA_ENV_LABEL]


def test_enable_node_ca_trust_never_overwrites_a_value_it_did_not_set(monkeypatch):
    calls = []
    monkeypatch.setattr(vscode.subprocess, "run", _fake_run("/etc/corp-ca-bundle.pem", calls))
    monkeypatch.setattr(vscode.launchd, "install_oneshot", lambda *a: (_ for _ in ()).throw(AssertionError("must not install")))

    ch = vscode.enable_node_ca_trust(Path("/tmp/ca.pem"))

    assert ch["applied"] is False
    assert "corp-ca-bundle" in ch["skipped"]
    assert not any(c[:2] == ("launchctl", "setenv") for c in calls)


def test_disable_node_ca_trust_never_unsets_a_value_it_did_not_set(monkeypatch):
    calls = []
    monkeypatch.setattr(vscode.subprocess, "run", _fake_run("/etc/corp-ca-bundle.pem", calls))
    removed = []
    monkeypatch.setattr(vscode.launchd, "remove", lambda label: removed.append(label))

    vscode.disable_node_ca_trust(Path("/tmp/ca.pem"))

    assert not any(c[:2] == ("launchctl", "unsetenv") for c in calls)
    assert removed == [vscode.CA_ENV_LABEL]  # our own LaunchAgent is always removed regardless
