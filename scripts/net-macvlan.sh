#!/usr/bin/env bash
# Explicit, owner-checked macvlan preparation. No guessing, replacement or shim by default.
set -Eeuo pipefail
SCRIPT_ROOT="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
source "$SCRIPT_ROOT/lib/config.sh"
action="${1:-help}"
(( $# == 0 )) || shift
case "$action" in
  create) operation=macvlan-create ;;
  plan) operation=macvlan-create ;;
  destroy) operation=macvlan-destroy ;;
  help|--help|-h)
    printf '%s\n' 'Usage: scripts/net-macvlan.sh create|plan|destroy [--config FILE] [--set KEY=VALUE] [--dry-run]' \
      'Set MACVLAN_PARENT, MACVLAN_SUBNET, MACVLAN_GATEWAY, MACVLAN_IP explicitly.' \
      'plan is read-only; destroy removes only the recorded, unused owned macvlan.'
    exit 0 ;;
  *) printf 'Unknown macvlan action: %s\n' "$action" >&2; exit 2 ;;
esac
config_args=()
extra=()
[[ "$action" != plan ]] || extra+=(--dry-run)
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
args=(--project "$PROJECT_NAME")
if [[ "$operation" == macvlan-create ]]; then
  args+=(--parent "$MACVLAN_PARENT" --subnet "$MACVLAN_SUBNET" --gateway "$MACVLAN_GATEWAY" --ip "$MACVLAN_IP")
fi
exec python3 "$FEILIAN_ROOT/scripts/network-resources.py" "$operation" "${args[@]}" "${extra[@]}"
