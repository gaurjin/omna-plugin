import shlex
from pathlib import Path

import pytest

from omna_plugin.mac import certs, launchd, netproxy, setup

SERVICES = "An asterisk (*) denotes that a network service is disabled.\nThunderbolt Bridge\nWi-Fi\n*iPhone USB\n"


@pytest.fixture(autouse=True)
def _vscode_not_installed(monkeypatch):
    # Real regression class (2026-09-19, aider/codex): apply()/revert() must
    # never touch this machine's actual VS Code state just because pytest
    # happens to run on a Mac that has VS Code installed. revert()'s VS Code
    # cleanup is unconditional (installed() doesn't gate it, on purpose — see
    # test_revert_cleans_up_vscode_even_when_vscode_app_is_already_gone), so
    # every one of these three needs its own default mock, not just installed().
    # Tests that specifically exercise the VS Code path override these explicitly.
    monkeypatch.setattr(setup.vscode, "installed", lambda: False)
    monkeypatch.setattr(setup.vscode, "revert_proxy_setting", lambda: {"proxy": False, "backup": False})
    monkeypatch.setattr(setup.vscode, "disable_node_ca_trust", lambda cert: None)
    # Same rule for the Mac's real network settings and System keychain: the
    # read-backs revert() does are faked too (nothing of Omna's set) unless a
    # test says otherwise.
    monkeypatch.setattr(setup.netproxy, "current_pac", lambda s: ("", False))
    monkeypatch.setattr(setup.certs, "in_system_keychain", lambda: False)


def test_services_parsing_skips_header_and_disabled():
    assert netproxy.parse_services(SERVICES) == ["Thunderbolt Bridge", "Wi-Fi"]


def test_pac_on_off_commands():
    on = netproxy.pac_on_commands(["Wi-Fi"], "http://127.0.0.1:7788/omna/proxy.pac")
    assert on == ['networksetup -setautoproxyurl "Wi-Fi" "http://127.0.0.1:7788/omna/proxy.pac"',
                  'networksetup -setautoproxystate "Wi-Fi" on']
    assert netproxy.pac_off_commands(["Wi-Fi"]) == [
        'networksetup -setautoproxystate "Wi-Fi" off',
        'networksetup -setautoproxyurl "Wi-Fi" " "',
    ]


def test_trust_commands(tmp_path):
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    assert certs.trust_command(cert) == f'security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{cert}"'
    assert certs.untrust_command(cert) == f'security remove-trusted-cert -d "{cert}"'
    assert certs.delete_command() == f'security delete-certificate -c "{certs.CA_NAME}" /Library/Keychains/System.keychain'


def test_pac_commands_escape_a_hostile_service_name():
    # networksetup -listallnetworkservices returns whatever the user renamed a
    # service to; these commands later run as `sudo sh <script>`, so a name like
    # this must not break out of its double quotes and inject a new command.
    hostile = 'Wi-Fi" ; touch /tmp/pwned ; echo "'
    for cmd in netproxy.pac_on_commands([hostile], "http://x") + netproxy.pac_off_commands([hostile]):
        args = shlex.split(cmd)
        assert hostile in args         # the whole hostile string survives as ONE shell argument
        assert "touch" not in args     # never becomes its own token


def test_trust_commands_escape_a_hostile_cert_path(tmp_path):
    hostile = tmp_path / 'c.pem" ; touch /tmp/pwned ; echo "'
    cmd = certs.trust_command(hostile)
    args = shlex.split(cmd)
    assert str(hostile) in args
    assert "touch" not in args


def test_plist_text_escapes_xml_special_characters():
    text = launchd.plist_text(omna_bin=Path("/Users/Jane & Doe/omna"), log=Path("/tmp/a<b>.log"))
    assert "/Users/Jane & Doe/omna" not in text
    assert "Jane &amp; Doe" in text
    assert "<b>" not in text and "&lt;b&gt;" in text


def test_launchd_plist_contents():
    text = launchd.plist_text(omna_bin=Path("/Users/x/.local/bin/omna"), log=Path("/Users/x/.omna/proxy.log"))
    assert "<string>dev.omna.plugin</string>" in text
    assert "<string>/Users/x/.local/bin/omna</string>" in text and "<string>start</string>" in text
    assert "<key>KeepAlive</key>" in text and "<key>RunAtLoad</key>" in text


def test_setup_plan_is_one_batch_with_both_privileged_actions(tmp_path):
    lines = setup.plan(services=["Wi-Fi"], cert=tmp_path / "c.pem", pac_url="http://127.0.0.1:7788/omna/proxy.pac")
    assert lines[0].startswith("security add-trusted-cert")
    assert any(l.startswith("networksetup -setautoproxyurl") for l in lines)
    assert all("sudo" not in l for l in lines)          # sudo wraps the batch, never the lines


def test_plist_text_defaults_to_the_daemon_label_and_args():
    text = launchd.plist_text(omna_bin=Path("/x/omna"), log=Path("/x/proxy.log"))
    assert f"<string>{launchd.LABEL}</string>" in text
    assert "<string>start</string>" in text


def test_plist_text_supports_a_second_label_and_args():
    text = launchd.plist_text(omna_bin=Path("/x/omna"), log=Path("/x/menubar.log"), label=launchd.MENUBAR_LABEL, args=["menubar"])
    assert f"<string>{launchd.MENUBAR_LABEL}</string>" in text
    assert "<string>menubar</string>" in text
    assert launchd.LABEL not in text.split(f"<string>{launchd.MENUBAR_LABEL}</string>")[0].replace(launchd.MENUBAR_LABEL, "")


def test_apply_never_installs_a_raw_launchd_agent_and_uses_the_branded_login_item(monkeypatch, tmp_path):
    # A bare-binary LaunchAgent always shows up in Login Items & Extensions as an
    # unbranded "exec" entry ("Item from unidentified developer"), no matter what —
    # `omna init` must never install one for the menu-bar. Only the branded `.app`
    # login item (System Events, same mechanism as the native Mac app) may start it.
    monkeypatch.setattr(setup, "ensure_ca", lambda d: tmp_path / "ca.pem")
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why: 0)
    monkeypatch.setattr(setup.shutil, "which", lambda name: "/usr/local/bin/omna")
    app_path = tmp_path / "Omna Plugin.app"
    monkeypatch.setattr(setup.app_bundle, "install", lambda omna_bin, **kw: app_path)
    install_calls = []
    remove_calls = []
    login_item_calls = []
    subprocess_calls = []
    monkeypatch.setattr(setup.launchd, "install", lambda omna_bin, **kw: install_calls.append((omna_bin, kw)) or tmp_path / "p.plist")
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: remove_calls.append(label))
    monkeypatch.setattr(setup.app_bundle, "enable_login_item", lambda **kw: login_item_calls.append(kw))
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: subprocess_calls.append(tuple(cmd)))

    out = setup.apply()

    assert install_calls == []  # never a raw launchd job for the menu-bar
    assert remove_calls == [launchd.LABEL, launchd.MENUBAR_LABEL]  # cleanup of any pre-existing agents
    assert login_item_calls == [{"app_path": app_path}]
    assert ("open", str(app_path)) in subprocess_calls
    assert "launchd" not in out
    assert "menubar_launchd" not in out
    assert out["app_bundle"] == str(app_path)


def test_wait_for_daemon_exit_returns_as_soon_as_the_pid_is_gone(monkeypatch):
    calls = []

    def fake_kill(pid, sig):
        calls.append(pid)
        if len(calls) >= 3:
            raise ProcessLookupError()

    monkeypatch.setattr(setup.os, "kill", fake_kill)
    monkeypatch.setattr(setup.time, "sleep", lambda s: None)

    setup._wait_for_daemon_exit(1234, timeout=5.0)

    assert calls == [1234, 1234, 1234]


def test_wait_for_daemon_exit_gives_up_after_the_timeout(monkeypatch):
    # A daemon that ignores SIGTERM must never hang `omna uninstall` forever.
    t = [0.0]
    monkeypatch.setattr(setup.time, "monotonic", lambda: t[0])

    def fake_sleep(s):
        t[0] += s

    monkeypatch.setattr(setup.time, "sleep", fake_sleep)
    monkeypatch.setattr(setup.os, "kill", lambda pid, sig: None)  # always "still alive"

    setup._wait_for_daemon_exit(1234, timeout=2.0)  # must return, not hang

    assert t[0] >= 2.0


def test_revert_stops_the_daemon_subprocess_and_removes_both_launchd_agents(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path)  # no cert on disk -> no sudo batch needed
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi"])
    calls = []
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: calls.append(tuple(cmd)))
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: calls.append(label))
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: calls.append("disable_login_item"))
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: calls.append("remove_app_bundle"))
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: calls.append("remove_deep_redirector_app"))

    setup.revert()

    # (The look at the network settings is a read: is Omna's routing file still set?)
    assert [c for c in calls if c[:2] != ("networksetup", "-getautoproxyurl")] == [
        tuple(setup.config.self_command() + ["stop"]), launchd.LABEL, launchd.MENUBAR_LABEL,   # #34a: by full path
        "disable_login_item", "remove_app_bundle", "remove_deep_redirector_app",
    ]


def test_revert_still_turns_the_system_proxy_off_when_the_certificate_file_is_gone(monkeypatch, tmp_path):
    # Security review 2026-11-11 ("not checked: omna uninstall reverses
    # everything"): with ~/.omna deleted by hand, uninstall skipped the whole
    # administrator step — the Mac kept sending browsers to a routing file
    # that no longer exists, and kept trusting Omna's certificate.
    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path / "gone")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi", "Ethernet"])
    monkeypatch.setattr(setup.netproxy, "current_pac",
                        lambda s: ("http://127.0.0.1:7788/omna/proxy.pac", True) if s == "Wi-Fi" else ("", False))
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: None)
    monkeypatch.setattr(setup.certs, "in_system_keychain", lambda: True)
    batches = []
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why, stop_on_error=True: batches.append(lines) or 0)

    setup.revert()

    assert len(batches) == 1
    assert batches[0] == [
        'networksetup -setautoproxystate "Wi-Fi" off',
        'networksetup -setautoproxyurl "Wi-Fi" " "',
        f'security delete-certificate -c "{setup.certs.CA_NAME}" {setup.certs.SYSTEM_KEYCHAIN}',
    ]


def test_revert_asks_for_no_password_when_nothing_of_omnas_is_set(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path / "gone")
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(setup.netproxy, "current_pac", lambda s: ("http://corp.example/proxy.pac", True))
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: None)
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why, **k: (_ for _ in ()).throw(AssertionError("no admin step needed")))
    setup.revert()          # a company's own proxy file is never touched


def test_revert_deletes_all_local_state_so_nothing_is_left_behind(monkeypatch, tmp_path):
    # registry.json, receipts.jsonl, policy.json, ruleset.json, the CA files on
    # disk, logs and the pidfile must all be gone after uninstall — untrusting
    # the cert from the keychain alone is not "no trace". ca_dir points AT the
    # real cert location under home (not some unrelated tmp_path) so the cert
    # actually exists and the untrust batch runs alongside the full wipe.
    home = tmp_path / "home"
    home.mkdir()
    (home / "registry.json").write_text("{}")
    (home / "receipts.jsonl").write_text("")
    (home / "ca").mkdir()
    (home / "ca" / "mitmproxy-ca-cert.pem").write_text("cert")
    monkeypatch.setattr(setup.config, "ca_dir", lambda: home / "ca")
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: [])

    class R:
        returncode = 0

    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: R())
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: None)

    out = setup.revert()

    assert out["sudo_rc"] == 0
    assert out["home_removed"] is True

    assert not home.exists()


def test_revert_removes_the_deep_door_redirector_app(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: [])
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    calls = []
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: calls.append("called"))

    setup.revert()

    assert calls == ["called"]


def test_revert_reports_a_failed_home_delete_instead_of_swallowing_it(monkeypatch, tmp_path):
    # A permission error, or ~/.omna relocated to a symlink, must be reported —
    # never presented to the person as a clean "no trace" uninstall while
    # registry.json (real secret/PII values) is still sitting on disk.
    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: [])
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: None)

    def _boom(path):
        raise PermissionError("no")

    monkeypatch.setattr(setup.shutil, "rmtree", _boom)

    out = setup.revert()

    assert out["home_removed"] is False
    assert "no" in out["home_error"]


def test_oneshot_plist_contents():
    text = launchd.oneshot_plist_text("dev.omna.plugin.node-ca-trust", ["/bin/launchctl", "setenv", "FOO", "/x/ca.pem"])
    assert "<string>dev.omna.plugin.node-ca-trust</string>" in text
    assert "<string>/bin/launchctl</string>" in text
    assert "<string>setenv</string>" in text
    assert "<string>FOO</string>" in text
    assert "<key>RunAtLoad</key><true/>" in text
    assert "KeepAlive" not in text  # one-shot: no supervision, just run and exit


def test_apply_wires_vscode_when_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(setup, "ensure_ca", lambda d: tmp_path / "ca.pem")
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why: 0)
    monkeypatch.setattr(setup.shutil, "which", lambda name: "/usr/local/bin/omna")
    app_path = tmp_path / "Omna Plugin.app"
    monkeypatch.setattr(setup.app_bundle, "install", lambda omna_bin, **kw: app_path)
    monkeypatch.setattr(setup.app_bundle, "enable_login_item", lambda **kw: None)
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.vscode, "installed", lambda: True)
    calls = []
    monkeypatch.setattr(setup.vscode, "init_proxy_setting", lambda: calls.append("init_proxy") or {"proxy": True, "skipped": None})
    monkeypatch.setattr(setup.vscode, "enable_node_ca_trust", lambda cert: calls.append(("ca_trust", cert)) or {"applied": True, "skipped": None})

    out = setup.apply()

    assert calls == ["init_proxy", ("ca_trust", tmp_path / "ca.pem")]
    assert out["vscode"] == {"proxy": True, "skipped": None}


def test_apply_reports_vscode_ca_trust_skip_alongside_a_successful_proxy_write(monkeypatch, tmp_path):
    # Regression: apply() must surface a skipped cert-trust step even when
    # the proxy setting itself succeeded — cmd_init only prints "wired" when
    # BOTH parts of vscode's result are clean, so this combined dict is what
    # keeps that message honest.
    monkeypatch.setattr(setup, "ensure_ca", lambda d: tmp_path / "ca.pem")
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why: 0)
    monkeypatch.setattr(setup.shutil, "which", lambda name: "/usr/local/bin/omna")
    monkeypatch.setattr(setup.app_bundle, "install", lambda omna_bin, **kw: tmp_path / "Omna Plugin.app")
    monkeypatch.setattr(setup.app_bundle, "enable_login_item", lambda **kw: None)
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.vscode, "installed", lambda: True)
    monkeypatch.setattr(setup.vscode, "init_proxy_setting", lambda: {"proxy": True, "backup": None, "skipped": None})
    monkeypatch.setattr(setup.vscode, "enable_node_ca_trust", lambda cert: {"applied": False, "skipped": "already set to something else"})

    out = setup.apply()

    assert out["vscode"]["proxy"] is True
    assert "already set to something else" in out["vscode"]["skipped"]


def test_apply_skips_vscode_entirely_when_not_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(setup, "ensure_ca", lambda d: tmp_path / "ca.pem")
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why: 0)
    monkeypatch.setattr(setup.shutil, "which", lambda name: "/usr/local/bin/omna")
    monkeypatch.setattr(setup.app_bundle, "install", lambda omna_bin, **kw: tmp_path / "Omna Plugin.app")
    monkeypatch.setattr(setup.app_bundle, "enable_login_item", lambda **kw: None)
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.vscode, "init_proxy_setting", lambda: (_ for _ in ()).throw(AssertionError("must not touch VS Code")))
    monkeypatch.setattr(setup.vscode, "enable_node_ca_trust", lambda cert: (_ for _ in ()).throw(AssertionError("must not touch VS Code")))

    out = setup.apply()

    assert out["vscode"] is None


def test_revert_reverts_vscode_when_installed(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: [])
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: None)
    monkeypatch.setattr(setup.vscode, "installed", lambda: True)
    calls = []
    monkeypatch.setattr(setup.vscode, "revert_proxy_setting", lambda: calls.append("revert_proxy"))
    monkeypatch.setattr(setup.vscode, "disable_node_ca_trust", lambda cert: calls.append(("disable_ca_trust", cert)))

    setup.revert()

    assert calls == ["revert_proxy", ("disable_ca_trust", tmp_path / "mitmproxy-ca-cert.pem")]


def test_revert_cleans_up_vscode_even_when_vscode_app_is_already_gone(monkeypatch, tmp_path):
    # Regression: if the person deleted VS Code.app before running `omna
    # uninstall`, vscode.installed() now returns False — but the settings.json
    # edit, NODE_EXTRA_CA_CERTS and its LaunchAgent must still be cleaned up,
    # not orphaned forever. revert()'s VS Code cleanup is unconditional.
    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: [])
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: None)
    monkeypatch.setattr(setup.vscode, "installed", lambda: False)  # VS Code.app is gone
    calls = []
    monkeypatch.setattr(setup.vscode, "revert_proxy_setting", lambda: calls.append("revert_proxy"))
    monkeypatch.setattr(setup.vscode, "disable_node_ca_trust", lambda cert: calls.append("disable_ca_trust"))

    setup.revert()

    assert calls == ["revert_proxy", "disable_ca_trust"]


def test_revert_removes_the_registry_key_from_the_keychain(monkeypatch, tmp_path):
    # rmtree(~/.omna) cannot reach the Keychain, so the key that opened
    # registry.json would otherwise outlive the file forever (#131).
    from omna_plugin import vault

    store = {vault.ACCOUNT: "whatever"}
    monkeypatch.delenv("OMNA_REGISTRY_ENCRYPTION", raising=False)
    monkeypatch.setattr(vault, "_kc_supported", lambda: True)
    monkeypatch.setattr(vault, "_kc_delete", lambda a: store.pop(a, None) is not None)

    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: [])
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: None)

    res = setup.revert()

    assert res["key_removed"] is True
    assert store == {}


def test_the_admin_batch_leaves_no_script_behind(tmp_path, monkeypatch, capsys):
    # Security review 2026-11-11, delete list: setup.sh stayed in ~/.omna
    # after setup — a script that had run as administrator.
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    (tmp_path / "setup.sh").write_text("left by an older version\n")
    ran = []

    def fake_run(cmd, **kw):
        ran.append((cmd, kw.get("input")))
        return type("R", (), {"returncode": 0})()

    monkeypatch.setattr(setup.subprocess, "run", fake_run)
    assert setup._run_batch(["echo one", "echo two"], "test") == 0
    assert ran == [(["sudo", "sh", "-s"], "set -e\necho one\necho two\n")]
    assert not (tmp_path / "setup.sh").exists()
    assert "echo one" in capsys.readouterr()[0]          # still printed before it runs


def test_init_closes_an_old_menu_bar_before_opening_the_app(monkeypatch, tmp_path):
    # #35: an old menu bar still running from a deleted tool folder made
    # `open Omna Plugin.app` a no-op (macOS only "activated" the old one).
    monkeypatch.setattr(setup, "ensure_ca", lambda d: tmp_path / "ca.pem")
    monkeypatch.setattr(setup.netproxy, "list_services", lambda: ["Wi-Fi"])
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why: 0)
    monkeypatch.setattr(setup.shutil, "which", lambda name: "/usr/local/bin/omna")
    app_path = tmp_path / "Omna Plugin.app"
    monkeypatch.setattr(setup.app_bundle, "install", lambda omna_bin, **kw: app_path)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "enable_login_item", lambda **kw: None)
    order = []
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: order.append(tuple(cmd)))
    from omna_plugin import menubar
    monkeypatch.setattr(menubar, "stop_other_menu_bars", lambda: order.append("stop-old-menu-bars"))
    setup.apply()
    assert "stop-old-menu-bars" in order, "the old menu bar was not closed"
    assert order.index("stop-old-menu-bars") < order.index(("open", str(app_path)))


# ---------------------------------------------------------------- #49: uninstall fails partway, claims success

def _quiet_revert(monkeypatch, tmp_path, *, cert_file: bool):
    """revert() with every side effect faked; only the admin batch + the read-back are left to the test."""
    ca = tmp_path / "ca"
    ca.mkdir()
    if cert_file:
        (ca / "mitmproxy-ca-cert.pem").write_text("cert")
    monkeypatch.setattr(setup.config, "ca_dir", lambda: ca)
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(setup.config, "home", lambda: home)
    monkeypatch.setattr(setup.subprocess, "run", lambda cmd, **k: None)
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: None)
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: None)
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: None)
    monkeypatch.setattr(setup, "remove_deep_redirector_app", lambda: None)


def test_pac_off_never_passes_an_empty_url():
    # Owner, 2026-11-22: `networksetup -setautoproxyurl "Wi-Fi" ""` answers
    # "** Error: The parameters were not valid." (checked on a real Mac inside a
    # write-blocked sandbox). Under `set -e` that one line stopped uninstall
    # after the first service — every later service and the certificate stayed.
    for cmd in netproxy.pac_off_commands(["Wi-Fi", "Ethernet"]):
        assert "" not in shlex.split(cmd)


def test_uninstall_batch_keeps_going_after_one_failed_line(tmp_path, monkeypatch):
    # The batch runs for real here (plain `sh`, never sudo): a failed first
    # line must not stop the lines after it.
    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    real_run = setup.subprocess.run
    monkeypatch.setattr(setup.subprocess, "run",
                        lambda cmd, **kw: real_run(["sh", "-s"], **kw) if cmd[:1] == ["sudo"] else real_run(cmd, **kw))
    marker = tmp_path / "second-line-ran"
    setup._run_batch(["false", f'touch "{marker}"'], "test", stop_on_error=False)
    assert marker.exists()


def test_uninstall_lists_disabled_services_too():
    assert netproxy.parse_services(SERVICES, include_disabled=True) == ["Thunderbolt Bridge", "Wi-Fi", "iPhone USB"]


def test_revert_reports_exactly_what_is_still_set_after_the_batch(monkeypatch, tmp_path):
    _quiet_revert(monkeypatch, tmp_path, cert_file=True)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi", "Ethernet"])
    # The admin step "ran" but changed nothing on Wi-Fi; Ethernet was never Omna's.
    monkeypatch.setattr(setup.netproxy, "current_pac",
                        lambda s: ("http://127.0.0.1:7788/omna/proxy.pac", True) if s == "Wi-Fi" else ("", False))
    monkeypatch.setattr(setup.certs, "in_system_keychain", lambda: True)
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why, stop_on_error=True: 1)

    res = setup.revert()

    assert res["proxy_left"] == ["Wi-Fi"]
    assert res["cert_left"] is True


def test_revert_removes_a_trusted_certificate_even_when_no_service_points_at_omna(monkeypatch, tmp_path):
    # Before: with the certificate FILE gone and no network service left on
    # Omna's routing file, the certificate in the System keychain was skipped.
    _quiet_revert(monkeypatch, tmp_path, cert_file=False)
    monkeypatch.setattr(setup.netproxy, "list_services", lambda **k: ["Wi-Fi"])
    monkeypatch.setattr(setup.netproxy, "current_pac", lambda s: ("", False))
    state = {"cert": True}
    monkeypatch.setattr(setup.certs, "in_system_keychain", lambda: state["cert"])
    batches = []

    def fake_batch(lines, why, stop_on_error=True):
        batches.append((lines, stop_on_error))
        state["cert"] = False
        return 0

    monkeypatch.setattr(setup, "_run_batch", fake_batch)

    res = setup.revert()

    assert batches == [([f'security delete-certificate -c "{certs.CA_NAME}" {certs.SYSTEM_KEYCHAIN}'], False)]
    assert res["proxy_left"] == [] and res["cert_left"] is False
