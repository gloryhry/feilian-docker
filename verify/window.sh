#!/usr/bin/env bash
# Uses configured actual DISPLAY; optional --capture .state/... only.
set -Eeuo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 -B "$root/verify/driver.py" window --container "${NAME:-feilian}" "$@"
