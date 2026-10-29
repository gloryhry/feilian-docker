#!/usr/bin/env bash
# Graceful, project-scoped stop. Never remove volumes or unrelated tun devices.
set -Eeuo pipefail
SCRIPT_ROOT="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
source "$SCRIPT_ROOT/scripts/lib/config.sh"
source "$SCRIPT_ROOT/scripts/lib/compose.sh"
config_args=()
dry_run=0
cleanup_network=0
include_macvlan=0
while (( $# )); do
  case "$1" in
    --config|--set)
      [[ $# -ge 2 ]] || { printf 'Missing value for %s\n' "$1" >&2; exit 2; }
      config_args+=("$1" "$2"); shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --cleanup-network) cleanup_network=1; shift ;;
    --include-macvlan) include_macvlan=1; shift ;;
    --help|-h)
      printf '%s\n' 'Usage: ./stop.sh [--config FILE] [--set KEY=VALUE] [--dry-run] [--cleanup-network [--include-macvlan]]' \
        'Default preserves containers, named volumes and external networks.'
      exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; exit 2 ;;
  esac
done
if (( include_macvlan && !cleanup_network )); then
  printf '%s\n' '--include-macvlan requires --cleanup-network' >&2; exit 2
fi
feilian_load_config "${config_args[@]}"
cd -- "$FEILIAN_ROOT"
compose_file="$(feilian_compose_file)"
command=(docker compose --project-name "$PROJECT_NAME" --env-file /dev/null -f "$compose_file")
if (( cleanup_network )); then
  command+=(down --timeout "$STOP_TIMEOUT")
else
  command+=(stop --timeout "$STOP_TIMEOUT")
fi
cleanup=(python3 "$FEILIAN_ROOT/scripts/network-resources.py" cleanup --project "$PROJECT_NAME")
(( include_macvlan == 0 )) || cleanup+=(--include-macvlan)
if (( dry_run )); then
  feilian_print_command "${command[@]}"
  (( cleanup_network == 0 )) || feilian_print_command "${cleanup[@]}"
  exit 0
fi
"${command[@]}"
if (( cleanup_network )); then
  "${cleanup[@]}"
fi
printf '[feilian] Project %s stopped; named volumes retained.\n' "$PROJECT_NAME"
if [[ "$NET_MODE" == host ]]; then
  printf '[feilian] Host mode: no generic tun/route deletion performed; inspect official-client host changes manually.\n'
fi
