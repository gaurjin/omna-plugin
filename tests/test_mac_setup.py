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
