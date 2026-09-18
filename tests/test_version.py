import tomllib
from pathlib import Path

from omna_plugin.proxy import __version__


def test_version_matches_pyproject_so_it_cannot_silently_drift():
    pyproject = tomllib.loads((Path(__file__).parent.parent / "pyproject.toml").read_text())
    assert __version__ == pyproject["project"]["version"]
