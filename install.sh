#!/bin/sh
# Omna plugin installer — macOS (Apple Silicon) and Linux (x86_64 / aarch64).
#   curl -fsSL https://raw.githubusercontent.com/gaurjin/omna-plugin/main/install.sh | sh
# What it does: installs uv if missing, installs the `omna` command with uv,
# wires Claude Code (ANTHROPIC_BASE_URL + a SessionStart hook), starts the proxy.
# Nothing is sent to Omna. Set OMNA_SOURCE to install from a git URL or a local path.
#
# Company rollout: an IT admin can tag every machine at install time, so the
# per-machine reports can later be grouped by department. This only writes the
# two names into the local policy file — it does not send anything anywhere.
#   curl -fsSL https://omna.dev/cli/install.sh | sh -s -- --org "Acme Inc" --dept engineering
set -eu

ORG=""
DEPT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --org)  ORG="${2:-}";  shift 2 ;;
    --dept) DEPT="${2:-}"; shift 2 ;;
    --org=*)  ORG="${1#*=}";  shift ;;
    --dept=*) DEPT="${1#*=}"; shift ;;
    *) echo "omna: unknown option: $1" >&2; exit 2 ;;
  esac
done

# Until the PyPI release, install straight from GitHub (a tagged release, not a moving branch).
SOURCE="${OMNA_SOURCE:-git+https://github.com/gaurjin/omna-plugin@v0.4.3}"

if ! command -v uv >/dev/null 2>&1; then
  echo "omna: installing uv (Python tool manager)..."
  curl -LsSf https://astral.sh/uv/install.sh | sh
  export PATH="$HOME/.local/bin:$PATH"
fi

echo "omna: installing the omna command from $SOURCE ..."
uv tool install --force --python 3.12 "$SOURCE"
export PATH="$HOME/.local/bin:$PATH"

if [ -n "$ORG" ] || [ -n "$DEPT" ]; then
  omna enroll ${ORG:+--org "$ORG"} ${DEPT:+--dept "$DEPT"}
fi

if [ "${OMNA_NO_INIT:-}" = "" ]; then
  omna init
  omna ensure || true
fi
omna status
echo
echo "omna: done. Open a new terminal (so PATH includes ~/.local/bin) and run Claude Code as usual."
