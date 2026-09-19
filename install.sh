#!/bin/sh
# Omna plugin installer — macOS (Apple Silicon) and Linux (x86_64 / aarch64).
#   curl -fsSL https://raw.githubusercontent.com/gaurjin/omna-plugin/main/install.sh | sh
# What it does: installs uv if missing, installs the `omna` command with uv,
# wires Claude Code (ANTHROPIC_BASE_URL + a SessionStart hook), starts the proxy.
# Nothing is sent to Omna. Set OMNA_SOURCE to install from a git URL or a local path.
set -eu

# Until the PyPI release, install straight from GitHub (a tagged release, not a moving branch).
SOURCE="${OMNA_SOURCE:-git+https://github.com/gaurjin/omna-plugin@v0.4.0}"

if ! command -v uv >/dev/null 2>&1; then
  echo "omna: installing uv (Python tool manager)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

echo "omna: installing the omna command from $SOURCE ..."
uv tool install --force --python 3.12 "$SOURCE"
export PATH="$HOME/.local/bin:$PATH"

if [ "${OMNA_NO_INIT:-}" = "" ]; then
  omna init
  omna ensure || true
fi
omna status
echo
echo "omna: done. Open a new terminal (so PATH includes ~/.local/bin) and run Claude Code as usual."
