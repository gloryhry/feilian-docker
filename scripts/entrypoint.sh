#!/usr/bin/env bash
# PID 1 bootstrap: container runtime services, then hand over to the supervisor.
# This script never parses user configuration: the host passes a validated subset.
set -Eeuo pipefail

RUNTIME=/opt/feilian/runtime
STATE_DIR=/run/feilian
WEB_DIR=/run/feilian-web
PROXY_DIR=/run/feilian-proxy
SECRETS_DIR=/run/feilian-secrets
LOG_DIR=/var/log/feilian
GUI_UID=1000

log() { printf '[feilian-boot] %s\n' "$*"; }
die() { printf '[feilian-boot] FATAL: %s\n' "$*" >&2; exit 1; }

MODE=${FEILIAN_NETWORK_MODE:-bridge}
case "$MODE" in bridge|macvlan|host) ;; *) die "invalid FEILIAN_NETWORK_MODE" ;; esac

umask 027
mkdir -p "$STATE_DIR" "$LOG_DIR" /run/dbus /run/user/"$GUI_UID"
chmod 700 "$STATE_DIR"

# ---------------------------------------------------------------- dbus (system)
dbus-uuidgen --ensure >/dev/null 2>&1 || true
if [ ! -S /run/dbus/system_bus_socket ]; then
  rm -f /run/dbus/pid
  dbus-daemon --system --nofork --nopidfile >"$LOG_DIR/dbus-system.log" 2>&1 &
  for _ in $(seq 1 50); do [ -S /run/dbus/system_bus_socket ] && break; sleep 0.1; done
fi
[ -S /run/dbus/system_bus_socket ] || die "system dbus socket unavailable"
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=/run/dbus/system_bus_socket"
log "system dbus ready"

# ------------------------------------------------------- NetworkManager (opt-in)
# Only isolated modes may run NM, and never with managed DNS: dnsmasq is the
# single resolver owner, otherwise the client and the controller fight over it.
if [ "$MODE" != host ] && [ "${START_NETWORKMANAGER:-1}" = "1" ]; then
  mkdir -p /etc/NetworkManager/conf.d /var/lib/NetworkManager
  printf '%s\n' '[main]' 'dns=none' 'rc-manager=unmanaged' \
    > /etc/NetworkManager/conf.d/99-feilian-dns-owner.conf
  /usr/sbin/NetworkManager --no-daemon >"$LOG_DIR/networkmanager.log" 2>&1 &
  log "NetworkManager started (DNS owner disabled)"
fi

# ------------------------------------------------------------- runtime dirs
install -d -m 0700 -o root -g root "$STATE_DIR"
install -d -m 2750 -o root -g 1001 "$PROXY_DIR"
install -d -m 2770 -o root -g "$GUI_UID" /run/user/"$GUI_UID"
chown "$GUI_UID:$GUI_UID" /run/user/"$GUI_UID" 2>/dev/null || true

# The secrets volume is mounted read-only; verify shape instead of trusting it.
if [ -d "$SECRETS_DIR" ]; then
  if [ -f "$SECRETS_DIR/web.htpasswd" ] && [ -f "$SECRETS_DIR/tls.crt" ] && [ -f "$SECRETS_DIR/tls.key" ]; then
    install -d -m 2750 -o root -g 1001 "$WEB_DIR"
    if ! python3 "$RUNTIME/web_gateway.py" prepare --state-dir "$WEB_DIR" \
         --secrets-dir "$SECRETS_DIR" >"$LOG_DIR/web-gateway.log" 2>&1; then
      die "management gateway preparation rejected the provided secrets"
    fi
    log "management gateway prepared (auth+TLS enforced)"
  else
    log "WARNING: secrets volume incomplete; management gateway will not start"
  fi
else
  log "WARNING: no secrets volume mounted; management gateway will not start"
fi

# A session bus for Electron, owned by the unprivileged GUI user.
SESSION_BUS="$(runuser -u feilian -- dbus-daemon --session --fork --print-address=1 2>/dev/null | head -n1)"
[ -n "$SESSION_BUS" ] || log "WARNING: session dbus unavailable"
export DBUS_SESSION_BUS_ADDRESS="${SESSION_BUS:-}"

log "handing over to supervisor (mode=$MODE)"
exec python3 "$RUNTIME/supervisor.py" run --state-dir "$STATE_DIR"
