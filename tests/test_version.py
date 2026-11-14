import tomllib
from pathlib import Path

from omna_plugin.proxy import __version__


def test_version_matches_pyproject_so_it_cannot_silently_drift():
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert __version__ == pyproject["project"]["version"]


def test_the_engine_named_in_receipts_is_the_installed_engine(tmp_path, monkeypatch):
    # Security review 2026-11-11, finding 18: receipts said "0.2.2+…" while
    # the installed masking engine (omna-pii-mask) was 0.2.21 — the kernel
    # kept its own stale number. A record must name the engine that made it.
    from importlib.metadata import version

    from omna_plugin import receipts, smart
    from omna_plugin.engine import MaskingSession, engine_version
    from omna_plugin.pipeline import MaskStats, Pipeline

    monkeypatch.setenv("OMNA_HOME", str(tmp_path))
    installed = version("omna-pii-mask")
    assert engine_version().split("+")[0] == installed
    assert smart.engine_fingerprint().split("+")[0] == installed
    Pipeline(MaskingSession()).receipt(door="api", route="/v1/messages", host="x", status=200, stats=MaskStats(),
                                       nbytes=1, ms=1, stream=False, app=None, note=None, session_id=None)
    assert receipts.tail(1)[0]["engine"].split("+")[0] == installed
