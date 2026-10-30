#!/usr/bin/env bash
# Metadata assertions only; never read host credential files or print hashes.
set -Eeuo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 -B "$root/verify/driver.py" isolation --container "${NAME:-feilian}" "$@"
