#!/usr/bin/env bash
# Validated, isolated startup. A failed bridge probe never upgrades to host.
set -Eeuo pipefail
SCRIPT_ROOT="$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")"
# shellcheck source=scripts/lib/config.sh
source "$SCRIPT_ROOT/scripts/lib/config.sh"
# shellcheck source=scripts/lib/compose.sh
source "$SCRIPT_ROOT/scripts/lib/compose.sh"

config_args=()
dry_run=0
prepare_network=0
usage() {
  printf '%s\n' 'Usage: ./run.sh [--config FILE] [--set KEY=VALUE] [--dry-run] [--prepare-network]' \
    'Default: verified project bridge; never automatically selects host.' \
    '--prepare-network: apply only the explicitly scoped, owned project UFW rule.'
}
while (( $# )); do
  case "$1" in
    --config|--set)
      [[ $# -ge 2 ]] || { usage >&2; exit 2; }
      config_args+=("$1" "$2"); shift 2 ;;
    --dry-run) dry_run=1; shift ;;
    --prepare-network) prepare_network=1; shift ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'Unknown option: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done
feilian_load_config "${config_args[@]}"
cd -- "$FEILIAN_ROOT"
[[ "$HOST_NET_APPLY" == 1 ]] && prepare_network=1
if [[ "$NET_MODE" == host && "$prepare_network" == 1 ]]; then
  printf 'Host compatibility mode may not install project network rules.\n' >&2
  exit 2
fi

log() { printf '[feilian] %s\n' "$*"; }
network_tool=(python3 "$FEILIAN_ROOT/scripts/network-resources.py")
network_args=(--project "$PROJECT_NAME")
[[ -z "$UP_IF" ]] || network_args+=(--up-if "$UP_IF")

if (( dry_run )); then
  log "DRY RUN: project=$PROJECT_NAME mode=$NET_MODE image=$IMAGE_REF"
  log 'Validate Compose and image feature labels before mutating resources.'
  feilian_print_command docker compose --project-name "$PROJECT_NAME" --env-file /dev/null -f "$(feilian_compose_file)" config --quiet
  case "$NET_MODE" in
    bridge|auto)
      feilian_print_command "${network_tool[@]}" ensure-bridge "${network_args[@]}"
      if (( prepare_network )); then
        feilian_print_command "${network_tool[@]}" apply "${network_args[@]}"
      fi
      log "Probe only $PROJECT_NAME-net, then start; failure stops without host fallback." ;;
    macvlan)
      feilian_print_command "${network_tool[@]}" macvlan-create --project "$PROJECT_NAME" \
        --parent "$MACVLAN_PARENT" --subnet "$MACVLAN_SUBNET" --gateway "$MACVLAN_GATEWAY" --ip "$MACVLAN_IP" ;;
    host) log 'Explicit host GUI compatibility mode, no managed egress rules.' ;;
  esac
  feilian_print_command docker compose --project-name "$PROJECT_NAME" --env-file /dev/null -f "$(feilian_compose_file)" up --detach --wait --wait-timeout 90
  exit 0
fi

command -v docker >/dev/null 2>&1 || { log 'Docker is required.' >&2; exit 1; }
# Compose/config checks happen before building, preparing networks or recreating anything.
feilian_compose config --quiet
if ! docker image inspect "$IMAGE_REF" >/dev/null 2>&1; then
  log 'Image missing; build the explicitly selected wrapper image.'
  "$FEILIAN_ROOT/build.sh" "${config_args[@]}"
fi
schema="$(docker image inspect --format '{{index .Config.Labels "io.feilian.runtime.schema"}}' "$IMAGE_REF")"
features="$(docker image inspect --format '{{index .Config.Labels "io.feilian.features"}}' "$IMAGE_REF")"
[[ "$schema" == 1 ]] || { log 'Image does not implement runtime schema 1; rebuild the wrapper, not the baseline image.' >&2; exit 2; }
if [[ "$WEB_AUTH" == 1 && ",$features," != *,web-auth,* ]]; then
  log 'Selected image lacks the required web-auth feature; refusing unsafe startup.' >&2
  exit 2
fi
if [[ "$WEB_TLS" != off && ",$features," != *,web-tls,* ]]; then
  log 'Selected image lacks the required web-tls feature.' >&2
  exit 2
fi

probe_bridge() {
  local endpoint
  for endpoint in https://www.volcengine.com https://deb.debian.org; do
    if docker run --rm --label "io.feilian.project=$PROJECT_NAME" \
      --label io.feilian.role=bootstrap-probe --network "$PROJECT_NAME-net" \
      --cap-drop ALL --security-opt no-new-privileges:true --entrypoint /usr/bin/curl \
      "$IMAGE_REF" --fail --silent --show-error --location --connect-timeout "$PROBE_TIMEOUT" \
      --max-time "$PROBE_TIMEOUT" --output /dev/null "$endpoint"; then
      return 0
    fi
  done
  return 1
}

case "$NET_MODE" in
  bridge|auto)
    "${network_tool[@]}" ensure-bridge "${network_args[@]}"
    if (( prepare_network )); then
      "${network_tool[@]}" apply "${network_args[@]}"
    fi
    log "Checking bootstrap egress on the actual project bridge $PROJECT_NAME-net..."
    if ! probe_bridge; then
      log 'Project bridge bootstrap egress failed; existing application was not removed and host was NOT selected.' >&2
      "${network_tool[@]}" doctor "${network_args[@]}" || true
      log 'Review doctor/plan; --prepare-network is scoped UFW only, not a mihomo/global-route change.' >&2
      log 'Prepared owned resources remain recorded; use stop.sh --cleanup-network to explicitly reclaim unused resources.' >&2
      exit 1
    fi ;;
  macvlan)
    "${network_tool[@]}" macvlan-create --project "$PROJECT_NAME" --parent "$MACVLAN_PARENT" \
      --subnet "$MACVLAN_SUBNET" --gateway "$MACVLAN_GATEWAY" --ip "$MACVLAN_IP" ;;
  host)
    log 'WARNING: explicitly selected host mode shares host networking. The official client may alter host routes.' ;;
esac

feilian_compose up --detach --wait --wait-timeout 90
scheme=http
[[ "$WEB_TLS" == off ]] || scheme=https
if [[ "$NET_MODE" == macvlan ]]; then
  management_host="$MACVLAN_IP"; management_port="$NOVNC_INTERNAL_PORT"
else
  management_host="$WEB_BIND"; management_port="$NOVNC_HOST_PORT"
fi
[[ "$management_host" != *:* ]] || management_host="[$management_host]"
log "Management: $scheme://$management_host:$management_port/vnc.html?autoconnect=1&resize=scale"
log 'A rendered login page is not proof of VPN readiness; use scripts/status.sh when available.'
