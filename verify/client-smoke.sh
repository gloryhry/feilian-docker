#!/usr/bin/env bash
# Existing-container official-only smoke; use all.sh --suite client to provision.
set -Eeuo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 -B "$root/verify/driver.py" client --container "${NAME:-feilian}" "$@"
