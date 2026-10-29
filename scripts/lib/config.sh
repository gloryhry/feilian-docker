#!/usr/bin/env bash
# Trusted adapter only: never source/eval the user's .env or config output.
# Output is captured first so Python failures cannot be hidden by a pipeline or
# process substitution. Nothing is exported until all data has been validated.
_FEILIAN_CONFIG_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)"

feilian_load_config() {
  local _output _rc _key _value _index
  local -a _args=() _keys=() _values=()
  local -A _seen=()
  while (( $# )); do
    case "$1" in
      --config|--set)
        if (( $# < 2 )); then
          printf 'feilian config: option requires a value\n' >&2
          return 2
        fi
        _args+=("$1" "$2")
        shift 2
        ;;
      --config=*|--set=*) _args+=("$1"); shift ;;
      *) printf 'feilian config: unsupported adapter option\n' >&2; return 2 ;;
    esac
  done
  if _output="$(python3 "${_FEILIAN_CONFIG_ROOT}/scripts/config.py" render --format env "${_args[@]}")"; then
    :
  else
    _rc=$?
    return "$_rc"
  fi
  while IFS='=' read -r _key _value; do
    case "$_key" in
      PROJECT_NAME|CLIENT_MANIFEST|IMAGE_REF|TAG|NET_MODE|ALLOW_HOST_NETWORK|NOVNC_HOST_PORT|NOVNC_INTERNAL_PORT|NOVNC_PORT|WEB_BIND|WEB_AUTH|WEB_TLS|WEB_SOURCE_CIDRS|WEB_AUTH_FILE|WEB_TLS_CERT_FILE|WEB_TLS_KEY_FILE|GUI_MODE|VNC_GEOMETRY|X11_DISPLAY|VNC_PASSWORD_FILE|PROXY_ENABLED|PROXY_REQUIRE_VPN|PROXY_BIND|HTTP_PROXY_HOST_PORT|HTTP_PROXY_INTERNAL_PORT|SOCKS_PROXY_HOST_PORT|SOCKS_PROXY_INTERNAL_PORT|PROXY_SOURCE_CIDRS|PROXY_CONNECT_PORTS|CORP_DOMAINS|CORP_CIDRS|DNS_MODE|VPN_DNS_SOURCE|VPN_DNS|VPN_CONFIG_FILE|VPN_IFACE|VPN_PROBE_DNS_NAME|VPN_PROBE_URL|VPN_PROBE_EXPECT_STATUS|VPN_PROBE_CA_FILE|GATEWAY_ENABLED|GATEWAY_SOURCE_CIDRS|ACCESS_SUBNET|GATEWAY_IP|MSS_MODE|GUARD_ENABLED|START_NETWORKMANAGER|START_SERVICE|START_GUI|MACVLAN_PARENT|MACVLAN_SUBNET|MACVLAN_GATEWAY|MACVLAN_IP|MACVLAN_SHIM|MACVLAN_SHIM_IP|BUILD_PLATFORMS|BUILD_OUTPUT|BUILD_NETWORK|DEBIAN_MIRROR|NO_CACHE|REGISTRY_IMAGE|PROBE_TIMEOUT|HOST_NET_APPLY|STOP_TIMEOUT|UP_IF|FEILIAN_CONFIG_STATUS) ;;
      *) printf 'feilian config: invalid renderer output\n' >&2; return 2 ;;
    esac
    if [[ -n ${_seen[$_key]+present} ]]; then
      printf 'feilian config: duplicate renderer output\n' >&2
      return 2
    fi
    _seen[$_key]=1
    _keys+=("$_key")
    _values+=("$_value")
  done <<< "$_output"
  if [[ -z ${_seen[PROJECT_NAME]+present} || -z ${_seen[NET_MODE]+present} || -z ${_seen[FEILIAN_CONFIG_STATUS]+present} ]]; then
    printf 'feilian config: incomplete renderer output\n' >&2
    return 2
  fi
  for (( _index=0; _index<${#_keys[@]}; _index++ )); do
    export "${_keys[$_index]}=${_values[$_index]}" || return 2
  done
  export FEILIAN_ROOT="$_FEILIAN_CONFIG_ROOT"
}
