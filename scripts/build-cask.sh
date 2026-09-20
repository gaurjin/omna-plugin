#!/bin/bash
# Build, sign, notarize and staple a self-contained `omna` for Homebrew (#133).
#
# Why a prebuilt binary rather than a Homebrew formula: our masking engine is an
# architecture-specific binary wheel with no source distribution (the kernel is
# closed, deliberately), and Homebrew's Python formula model builds from source.
# Kiji ships a notarized binary and lets Homebrew just download it; this is ours.
#
# Requires: the `omna-notarize` keychain profile (already set up on this Mac —
# see native/install/build-pkg.sh in omna-workspace for how it was created).
set -euo pipefail

cd "$(dirname "$0")/.."
VERSION=$(.venv/bin/python -c "import tomllib,pathlib;print(tomllib.loads(pathlib.Path('pyproject.toml').read_text())['project']['version'])")
IDENTITY="Developer ID Application: Gaurav Jindal (HGVZ7MLM7N)"
ARCH=$(uname -m)
OUT="dist/omna-${VERSION}-macos-${ARCH}.zip"

echo "==> PyInstaller (self-contained: Python + deps + the compiled engine)"
.venv/bin/pyinstaller omna.spec --noconfirm --log-level ERROR

echo "==> smoke test the bundle BEFORE signing it"
./dist/omna/omna version
./dist/omna/omna mask "x jane.doe@example.com" | grep -q "EMAIL_" \
  || { echo "FAILED: the bundled engine did not mask"; exit 1; }

echo "==> codesign --options runtime (hardened runtime, required for notarization)"
# Sign every nested binary first, then the launcher. --deep is deprecated and
# unreliable for this layout, so the inner Mach-O files are done explicitly.
find dist/omna/_internal -type f \( -name "*.so" -o -name "*.dylib" \) -print0 \
  | xargs -0 -I{} codesign --force --timestamp --options runtime --sign "$IDENTITY" {}
codesign --force --timestamp --options runtime --sign "$IDENTITY" dist/omna/omna

echo "==> verify the signature"
codesign --verify --strict --verbose=2 dist/omna/omna

echo "==> zip for notarization"
rm -f "$OUT"
ditto -c -k --keepParent dist/omna "$OUT"

echo "==> notarytool submit --wait (typically 5-30 min)"
xcrun notarytool submit "$OUT" --keychain-profile "omna-notarize" --wait

echo "==> staple the ticket into the bundle, then re-zip so the zip carries it"
xcrun stapler staple dist/omna/omna || xcrun stapler staple dist/omna
rm -f "$OUT"
ditto -c -k --keepParent dist/omna "$OUT"

echo "==> Gatekeeper check (what a user's Mac will do)"
spctl --assess --type execute --verbose dist/omna/omna || true

SHA=$(shasum -a 256 "$OUT" | cut -d' ' -f1)
echo
echo "built:  $OUT"
echo "sha256: $SHA"
echo
echo "Next: attach it to the GitHub release, then update Casks/omna.rb with"
echo "that version and sha256."
