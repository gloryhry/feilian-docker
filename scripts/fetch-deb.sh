#!/usr/bin/env bash
# Download only the reviewed lock; discovery is a separate, candidate-only CLI.
set -Eeuo pipefail
script_dir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
exec python3 "$script_dir/client-artifacts.py" fetch "$@"
