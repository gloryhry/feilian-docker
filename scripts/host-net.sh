#!/usr/bin/env bash
# Read-only doctor by default; explicit apply is limited to the owned project bridge.
set -Eeuo pipefail
SCRIPT_ROOT="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
source "$SCRIPT_ROOT/lib/config.sh"
action=doctor
if (( $# )) && [[ "$1" != --* ]]; then action="$1"; shift; fi
case "$action" in doctor|plan|apply|cleanup|ensure-bridge) ;; *) printf 'Use doctor|plan|apply|cleanup|ensure-bridge\n' >&2; exit 2 ;; esac
config_args=()
extra=()
while (( $# )); do
  case "$1" in
    --config|--set)
      [[ $# -ge 2 ]] || { printf 'Missing configuration value\n' >&2; exit 2; }
      config_args+=("$1" "$2"); shift 2 ;;
    --dry-run) extra+=(--dry-run); shift ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
feilian_load_config "${config_args[@]}"
if [[ "$NET_MODE" == host && "$action" != doctor && "$action" != plan ]]; then
  printf 'Project host-network mutations are forbidden in host compatibility mode.\n' >&2
  exit 2
fi
args=(--project "$PROJECT_NAME")
[[ -z "$UP_IF" ]] || args+=(--up-if "$UP_IF")
exec python3 "$FEILIAN_ROOT/scripts/network-resources.py" "$action" "${args[@]}" "${extra[@]}"
