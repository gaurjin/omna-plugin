"""install.sh, the script `curl … | sh` runs (architecture review, MASTER #178)."""

import os
import re
import subprocess
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "install.sh"


def test_nothing_runs_until_the_whole_script_has_arrived():
    """A download cut off half-way must run nothing, not half an installer."""
    lines = [ln for ln in SCRIPT.read_text().splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    assert lines[-1] == 'main "$@"'
    # Before `main` is defined, only plain assignments and `set` are allowed.
    head = lines[: next(i for i, ln in enumerate(lines) if ln.startswith("main()"))]
    assert all(re.match(r"^(set -eu|[A-Z_]+=\"[^\"$`]*\")$", ln) for ln in head), head
    subprocess.run(["sh", "-n", str(SCRIPT)], check=True)


def test_the_installed_version_is_pinned_to_this_release():
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert f'OMNA_VERSION="{version}"' in SCRIPT.read_text()


def test_it_installs_the_pinned_version_and_passes_the_company_tags(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "calls.log"
    for name in ("uv", "omna", "curl"):
        p = bin_dir / name
        p.write_text(f'#!/bin/sh\necho "{name} $*" >> "{log}"\n')
        p.chmod(0o755)
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path), "OMNA_NO_INIT": "1"}
    subprocess.run(["sh", str(SCRIPT), "--org", "Acme Inc", "--dept", "eng"], env=env, check=True,
                   capture_output=True)
    calls = log.read_text()
    version = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]["version"]
    assert f"uv tool install --force --python 3.12 omna-plugin=={version}" in calls
    assert "omna enroll --org Acme Inc --dept eng" in calls
    assert "curl" not in calls            # uv already there: nothing fetched


def test_the_uv_installer_is_pinned_too(tmp_path):
    text = SCRIPT.read_text()
    assert re.search(r"https://astral\.sh/uv/\$\{?UV_VERSION\}?/install\.sh", text)
    assert "https://astral.sh/uv/install.sh" not in text
