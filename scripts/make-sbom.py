#!/usr/bin/env python3
"""Generate docs/sbom.cdx.json — a CycloneDX inventory of what the plugin ships.

Why bother: an enterprise security review increasingly opens with "send us your
SBOM". Having one is the difference between a two-day answer and a two-week one.

Source of truth is `uv.lock`, not the current virtualenv, because the lockfile
is what a user's `uv tool install` actually resolves. Run it after any
dependency change:

    .venv/bin/python scripts/make-sbom.py
"""
from __future__ import annotations

import datetime
import json
import pathlib
import re
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent


def packages() -> list[tuple[str, str]]:
    lock = (ROOT / "uv.lock").read_text()
    out = []
    for block in lock.split("[[package]]")[1:]:
        name = re.search(r'^name = "(.+?)"', block, re.M)
        ver = re.search(r'^version = "(.+?)"', block, re.M)
        if name and ver:
            out.append((name.group(1), ver.group(1)))
    return sorted(set(out))


def main() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    version = project["version"]
    now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

    components = []
    for name, ver in packages():
        if name == "omna-plugin":
            continue
        comp = {
            "type": "library",
            "name": name,
            "version": ver,
            "purl": f"pkg:pypi/{name}@{ver}",
            "scope": "required",
        }
        if name == "omna-pii-mask":
            comp["description"] = (
                "The Omna masking engine. Closed-source kernel, distributed as a "
                "compiled binary wheel; built in CI from a private repository."
            )
        components.append(comp)

    bom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "component": {
                "type": "application",
                "name": "omna-plugin",
                "version": version,
                "purl": f"pkg:pypi/omna-plugin@{version}",
                "description": project["description"],
                "licenses": [{"license": {"id": "MIT"}}],
            },
            "tools": [{"name": "omna scripts/make-sbom.py"}],
        },
        "components": components,
    }

    out = ROOT / "docs" / "sbom.cdx.json"
    out.write_text(json.dumps(bom, indent=2) + "\n")
    print(f"wrote {out.relative_to(ROOT)} — {len(components)} components, "
          f"omna-plugin {version}")


if __name__ == "__main__":
    main()
