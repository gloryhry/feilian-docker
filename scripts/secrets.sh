#!/usr/bin/env bash
# Trusted wrapper; config and secret contents are never sourced or echoed.
set -Eeuo pipefail
SCRIPT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
exec python3 "$SCRIPT_ROOT/scripts/secrets-cli.py" "$@"
