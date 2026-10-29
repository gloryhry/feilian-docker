#!/usr/bin/env bash
# Validated Buildx only; no automatic push, host networking or builder setup.
set -Eeuo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/scripts/build-image.py" "$@"
