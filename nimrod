#!/usr/bin/env bash
# NIMROD launcher - boots the agent from anywhere on your PATH.
# Target can be overridden with the NIMROD_HOME env var.
NIMROD_DIR="${NIMROD_HOME:-$HOME/Documents/nimrod}"
SCRIPT="$NIMROD_DIR/nimrod.py"

if [[ ! -f "$SCRIPT" ]]; then
    echo "[!] nimrod not found at $SCRIPT" >&2
    echo "    (set NIMROD_HOME to the folder containing nimrod.py)" >&2
    exit 1
fi

exec python3 "$SCRIPT" "$@"
