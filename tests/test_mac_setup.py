import shlex
from pathlib import Path

from omna_plugin.mac import certs, launchd, netproxy, setup

SERVICES = "An asterisk (*) denotes that a network service is disabled.\nThunderbolt Bridge\nWi-Fi\n*iPhone USB\n"


def test_services_parsing_skips_header_and_disabled():
    assert netproxy.parse_services(SERVICES) == ["Thunderbolt Bridge", "Wi-Fi"]


def test_pac_on_off_commands():
    on = netproxy.pac_on_commands(["Wi-Fi"], "http://127.0.0.1:7788/omna/proxy.pac")
    assert on == ['networksetup -setautoproxyurl "Wi-Fi" "http://127.0.0.1:7788/omna/proxy.pac"',
                  'networksetup -setautoproxystate "Wi-Fi" on']
    assert netproxy.pac_off_commands(["Wi-Fi"]) == ['networksetup -setautoproxystate "Wi-Fi" off']


def test_trust_commands(tmp_path):
    cert = tmp_path / "mitmproxy-ca-cert.pem"
    assert certs.trust_command(cert) == f'security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "{cert}"'
    assert certs.untrust_commands(cert)[0] == f'security remove-trusted-cert -d "{cert}"'


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


def test_apply_installs_the_daemon_and_the_menubar_launchd_agents(monkeypatch, tmp_path):
    monkeypatch.setattr(setup, "ensure_ca", lambda d: tmp_path / "ca.pem")
    monkeypatch.setattr(setup.netproxy, "list_services", lambda: ["Wi-Fi"])
    monkeypatch.setattr(setup, "_run_batch", lambda lines, why: 0)
    monkeypatch.setattr(setup.shutil, "which", lambda name: "/usr/local/bin/omna")
    monkeypatch.setattr(setup.app_bundle, "install", lambda omna_bin: tmp_path / "Omna Plugin.app")
    calls = []
    monkeypatch.setattr(setup.launchd, "install", lambda omna_bin, **kw: calls.append((omna_bin, kw)) or tmp_path / "p.plist")

    out = setup.apply()

    assert len(calls) == 2
    assert calls[0][1] == {}  # the daemon: default label ("start")
    assert calls[1][1]["label"] == launchd.MENUBAR_LABEL
    assert calls[1][1]["args"] == ["menubar"]
    assert "menubar_launchd" in out
    assert "app_bundle" in out


def test_revert_removes_the_daemon_and_the_menubar_launchd_agents(monkeypatch, tmp_path):
    monkeypatch.setattr(setup.config, "ca_dir", lambda: tmp_path)  # no cert on disk -> no sudo batch needed
    monkeypatch.setattr(setup.netproxy, "list_services", lambda: ["Wi-Fi"])
    calls = []
    monkeypatch.setattr(setup.launchd, "remove", lambda label=launchd.LABEL: calls.append(label))
    monkeypatch.setattr(setup.app_bundle, "disable_login_item", lambda: calls.append("disable_login_item"))
    monkeypatch.setattr(setup.app_bundle, "remove", lambda: calls.append("remove_app_bundle"))

    setup.revert()

    assert calls == [launchd.LABEL, launchd.MENUBAR_LABEL, "disable_login_item", "remove_app_bundle"]
