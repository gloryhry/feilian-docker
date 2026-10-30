#!/usr/bin/env bash
# Trusted project code; user configuration is parsed by config.py, never sourced.

feilian_compose_files() {
  local base
  case "${NET_MODE:?configuration not loaded}" in
    bridge|auto) base="$FEILIAN_ROOT/compose.yaml" ;;
    host) base="$FEILIAN_ROOT/compose.host.yaml" ;;
    macvlan) base="$FEILIAN_ROOT/compose.macvlan.yaml" ;;
    *) printf 'invalid network mode\n' >&2; return 2 ;;
  esac
  printf '%s\n' "$base"
  # The SNAT gateway needs a second, dedicated access network; the overlay only
  # attaches it, the network itself is created by network-resources.py.
  if [ "${GATEWAY_ENABLED:-0}" = "1" ] && [ -f "$FEILIAN_ROOT/compose.gateway.yaml" ]; then
    printf '%s\n' "$FEILIAN_ROOT/compose.gateway.yaml"
  fi
}

feilian_compose_file() {
  feilian_compose_files | head -n1
}

feilian_compose() {
  local files=() file
  while IFS= read -r file; do files+=(-f "$file"); done < <(feilian_compose_files) || return
  docker compose --project-name "$PROJECT_NAME" --env-file /dev/null "${files[@]}" "$@"
}

feilian_print_command() {
  printf '  '
  printf '%q ' "$@"
  printf '\n'
}
