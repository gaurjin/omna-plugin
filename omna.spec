# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller recipe for a self-contained `omna` (#133).

Why this exists: Homebrew's Python formula model builds from source
distributions, and our masking engine ships as an architecture-specific binary
wheel with no sdist. That is deliberate — the kernel is closed — so the formula
route fights the product's own architecture.

Kiji solves the same problem by shipping a prebuilt notarized binary that
Homebrew merely downloads and hash-checks (`brew install --cask`). This is our
version of that: one directory containing Python, every dependency, and the
compiled engine, signed with our Developer ID and notarized by Apple.

Built with: .venv/bin/pyinstaller omna.spec --noconfirm
"""

import importlib.util
from pathlib import Path

# The compiled engine is a binary wheel; PyInstaller cannot infer its data
# files, so point at the installed package directly.
_spec = importlib.util.find_spec("omna_pii_mask")
engine_dir = Path(_spec.origin).parent

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

datas = [
    # mitmproxy ships templates/certs/statics it loads at runtime by path.
    *collect_data_files("mitmproxy"),
    *collect_data_files("certifi"),
    # proxy.py reads its own version from installed package metadata so it can
    # never drift from pyproject. Without the dist-info in the bundle that
    # lookup fails and every build reports 0.0.0+unknown.
    *copy_metadata("omna-plugin"),
    *copy_metadata("omna-pii-mask"),
]

hiddenimports = [
    # mitmproxy resolves addons and its command set dynamically.
    *collect_submodules("mitmproxy"),
    # uvicorn picks its loop/protocol implementations by string name.
    "uvicorn.logging", "uvicorn.loops", "uvicorn.loops.auto", "uvicorn.loops.asyncio",
    "uvicorn.protocols", "uvicorn.protocols.http", "uvicorn.protocols.http.auto",
    "uvicorn.protocols.http.h11_impl",
    "uvicorn.protocols.websockets", "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan", "uvicorn.lifespan.on",
    # the menu bar
    "pystray._darwin", "PIL._tkinter_finder",
    "omna_pii_mask",
]

a = Analysis(
    ["src/omna_plugin/__main__.py"],
    pathex=["src"],
    binaries=[(str(p), "omna_pii_mask") for p in engine_dir.glob("*.so")],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    excludes=["tkinter", "matplotlib", "numpy.testing", "pytest"],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz, a.scripts, [],
    exclude_binaries=True,
    name="omna",
    debug=False,
    strip=False,
    upx=False,               # UPX breaks codesigning
    console=True,
    target_arch=None,        # native (arm64); universal2 would need fat deps
    codesign_identity=None,  # signed as one bundle afterwards, see scripts/build-cask.sh
    entitlements_file=None,
)
coll = COLLECT(
    exe, a.binaries, a.datas,
    strip=False, upx=False, name="omna",
)
