import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def _never_touch_the_real_keychain(monkeypatch):
    """Registry encryption is OFF for the whole suite unless a test opts in.

    `OMNA_HOME` isolates every test's files into a tmp directory, but the macOS
    Keychain is machine-wide: without this, running the tests would mint (and
    leave behind) a real key in the developer's own login keychain. Tests that
    need a working key install the in-memory fake from `test_vault.py`.
    """
    monkeypatch.setenv("OMNA_REGISTRY_ENCRYPTION", "off")


@pytest.fixture(autouse=True)
def _never_touch_the_real_browsers(monkeypatch, tmp_path_factory):
    """Native-messaging registration (finding 6) writes into the browsers'
    own settings folders. No test may touch the developer's real Chrome, or
    read the Mac app's real dev-ID list: by default there are no browsers on
    the machine; a test that needs one points this at its own tmp folder."""
    from omna_plugin import extension_auth

    monkeypatch.setattr(extension_auth, "_browser_roots", lambda: [])
    nowhere = tmp_path_factory.mktemp("no-mac-app") / "dev_extension_ids"
    monkeypatch.setattr(extension_auth, "_mac_app_dev_ids", lambda: nowhere)


@pytest.fixture(autouse=True)
def _never_touch_the_real_home_folder(monkeypatch, tmp_path_factory):
    """Every tool Omna wires keeps its settings under the person's home folder
    (~/.claude, ~/.codex, ~/.aider.conf.yml, ~/.continue). A test that runs
    `omna uninstall` or `omna init` without replacing each of those by hand
    would edit the developer's REAL files — one such test existed
    (found 2026-11-14 while checking that uninstall reverses everything).
    The whole suite now has a throwaway home folder."""
    monkeypatch.setenv("HOME", str(tmp_path_factory.mktemp("home")))


@pytest.fixture(autouse=True)
def _never_send_install_counts(monkeypatch):
    """`omna init` / `omna uninstall` send one install/uninstall count to
    omna.dev. No test may reach the network or inflate the real count; the
    tests for that ping (test_installping.py) turn this back on with a fake."""
    monkeypatch.setenv("OMNA_NO_TELEMETRY", "1")


@pytest.fixture(autouse=True)
def _never_close_real_menu_bars(monkeypatch):
    """#35: stop_other_menu_bars() closes Omna menu-bar processes on this Mac.
    No test may close the developer's real one: it is a no-op unless a test
    calls the real function with its own fake process list."""
    from omna_plugin import menubar

    monkeypatch.setattr(menubar, "stop_other_menu_bars", lambda: None)


@pytest.fixture(autouse=True)
def _never_touch_the_real_menu_bar_app(monkeypatch, tmp_path_factory):
    """2026-11-22: `omna ensure` repairs /Applications/Omna Plugin.app, and a
    test that ran `ensure` rebuilt the developer's REAL app to point at the
    test copy. Every test gets a throwaway app path."""
    from omna_plugin.mac import app_bundle

    monkeypatch.setattr(app_bundle, "APP_PATH", tmp_path_factory.mktemp("apps") / "Omna Plugin.app")
