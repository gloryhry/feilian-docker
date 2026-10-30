#!/usr/bin/env bash
# Default is strict enterprise readiness. --doctor is diagnostics, not PASS.
set -Eeuo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 -B "$root/verify/driver.py" network --container "${NAME:-feilian}" "$@"
