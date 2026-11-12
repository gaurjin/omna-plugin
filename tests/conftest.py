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
