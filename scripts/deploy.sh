#!/usr/bin/env bash
# Digest-pinned deploy/rollback wrapper; secrets and config are never parsed here.
set -Eeuo pipefail
root=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec python3 "$root/scripts/deploy.py" "$@"
