#!/usr/bin/env bash
# Trusted project code; user configuration is parsed by config.py, never sourced.

feilian_compose_file() {
  case "${NET_MODE:?configuration not loaded}" in
    bridge|auto) printf '%s/compose.yaml\n' "$FEILIAN_ROOT" ;;
    host) printf '%s/compose.host.yaml\n' "$FEILIAN_ROOT" ;;
    macvlan) printf '%s/compose.macvlan.yaml\n' "$FEILIAN_ROOT" ;;
    *) printf 'invalid network mode\n' >&2; return 2 ;;
  esac
}

feilian_compose() {
  local compose_file
  compose_file="$(feilian_compose_file)" || return
  docker compose --project-name "$PROJECT_NAME" --env-file /dev/null -f "$compose_file" "$@"
}

feilian_print_command() {
  printf '  '
  printf '%q ' "$@"
  printf '\n'
}
