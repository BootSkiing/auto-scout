#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"
export PYTHONPATH="$SCRIPT_DIR:${PYTHONPATH:-}"

# Ensure pipx's bin dir is on PATH so CLI tools installed via pipx (e.g. bbot,
# used by stage 6) resolve even when the user hasn't restarted their shell
# since running setup.sh. pipx ensurepath only edits the shell rc; a fresh
# login shell or this guard is what actually makes `bbot` reachable.
PIPX_BIN_DIR="$(pipx environment --value PIPX_BIN_DIR 2>/dev/null || true)"
[ -z "$PIPX_BIN_DIR" ] && PIPX_BIN_DIR="${HOME}/.local/bin"
case ":${PATH}:" in
    *":${PIPX_BIN_DIR}:"*) ;;
    *) export PATH="${PIPX_BIN_DIR}:${PATH}" ;;
esac

VENV_PYTHON="$SCRIPT_DIR/auto-scout-venv/bin/python"
if [ -x "$VENV_PYTHON" ]; then
    exec "$VENV_PYTHON" orchestrator.py "$@"
else
    exec python3 orchestrator.py "$@"
fi
