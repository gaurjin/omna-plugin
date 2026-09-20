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
