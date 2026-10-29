#!/usr/bin/env bash
# 容器 PID 1：拉起 dbus / NetworkManager / corplink-service / Xvfb / x11vnc / noVNC / GUI
# 所有进程都在容器内，宿主机只暴露一个 noVNC 端口（默认绑定 127.0.0.1）。
set -Eeuo pipefail

APP_DIR=/opt/apps/com.volcengine.feilian/files
FEILIAN_USER=feilian
FEILIAN_UID=1000
LOG_DIR=/var/log/feilian

GUI_MODE=${GUI_MODE:-vnc}             # vnc | x11
DISPLAY_NUM=${DISPLAY_NUM:-99}
VNC_GEOMETRY=${VNC_GEOMETRY:-1600x1000x24}
VNC_PORT=${VNC_PORT:-5900}
NOVNC_BIND=${NOVNC_BIND:-0.0.0.0}
NOVNC_PORT=${NOVNC_PORT:-6080}
VNC_PASSWORD=${VNC_PASSWORD:-}
START_NETWORKMANAGER=${START_NETWORKMANAGER:-1}
START_SERVICE=${START_SERVICE:-1}
START_GUI=${START_GUI:-1}
# 无 GPU 容器里 Electron 走软件渲染；/dev/shm 偏小时必须关掉共享内存
EXTRA_GUI_ARGS=${EXTRA_GUI_ARGS:---disable-gpu --disable-dev-shm-usage}

log() { printf '[feilian %s] %s\n' "$(date -u +%H:%M:%S)" "$*"; }
die() { log "FATAL: $*"; exit 1; }

CHILDREN=()
cleanup() {
  trap - TERM INT EXIT
  log "收到退出信号，收尾中…"
  for pid in "${CHILDREN[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  sleep 1
  for pid in "${CHILDREN[@]:-}"; do kill -9 "$pid" 2>/dev/null || true; done
}
trap cleanup TERM INT EXIT

wait_for_path() { # path timeout_s
  local p=$1 t=${2:-30} i=0
  while [ ! -e "$p" ]; do
    i=$((i+1)); [ "$i" -gt $((t*5)) ] && return 1
    sleep 0.2
  done
}

mkdir -p "$LOG_DIR" /run/dbus /run/NetworkManager /run/lock /run/user/"$FEILIAN_UID"

# ---------------------------------------------------------------- dbus (system)
dbus-uuidgen --ensure >/dev/null 2>&1 || true
if [ ! -S /run/dbus/system_bus_socket ]; then
  rm -f /run/dbus/pid
  dbus-daemon --system --fork --nopidfile || die "dbus system bus 启动失败"
fi
export DBUS_SYSTEM_BUS_ADDRESS="unix:path=/run/dbus/system_bus_socket"
log "system dbus 就绪"

# ---------------------------------------------------------------- NetworkManager
if [ "$START_NETWORKMANAGER" = "1" ]; then
  # NM 需要能写的运行时目录
  mkdir -p /var/lib/NetworkManager /var/run/NetworkManager
  /usr/sbin/NetworkManager --no-daemon >"$LOG_DIR/networkmanager.log" 2>&1 &
  CHILDREN+=($!)
  log "NetworkManager pid=$! (eth0 已配置为 unmanaged)"
fi

# ---------------------------------------------------------------- 显示链路
export DISPLAY=""
if [ "$GUI_MODE" = "x11" ]; then
  : "${X11_DISPLAY:?GUI_MODE=x11 时必须提供宿主机 DISPLAY，例如 :0}"
  [ -S "/tmp/.X11-unix/X${X11_DISPLAY#:}" ] || \
    die "找不到宿主机 X11 socket /tmp/.X11-unix/X${X11_DISPLAY#:}（需要在 compose 里只挂载这一个 socket）"
  export DISPLAY="$X11_DISPLAY"
  log "X11 直连模式：DISPLAY=$DISPLAY（只挂载了该 display 的 socket）"
else
  export DISPLAY=":$DISPLAY_NUM"
  Xvfb "$DISPLAY" -screen 0 "$VNC_GEOMETRY" -nolisten tcp -ac +extension RANDR \
      >"$LOG_DIR/xvfb.log" 2>&1 &
  CHILDREN+=($!)
  wait_for_path "/tmp/.X11-unix/X${DISPLAY_NUM}" 30 || die "Xvfb 未就绪"

  X11VNC_ARGS=(-display "$DISPLAY" -forever -shared -rfbport "$VNC_PORT" -localhost -quiet -noxdamage)
  if [ -n "$VNC_PASSWORD" ]; then
    x11vnc -storepasswd "$VNC_PASSWORD" /run/x11vnc.pass >/dev/null 2>&1
    X11VNC_ARGS+=(-rfbauth /run/x11vnc.pass)
  else
    X11VNC_ARGS+=(-nopw)
  fi
  x11vnc "${X11VNC_ARGS[@]}" >"$LOG_DIR/x11vnc.log" 2>&1 &
  CHILDREN+=($!)

  websockify --web=/usr/share/novnc "$NOVNC_BIND:$NOVNC_PORT" "127.0.0.1:$VNC_PORT" \
      >"$LOG_DIR/novnc.log" 2>&1 &
  CHILDREN+=($!)
  log "noVNC: http://${NOVNC_BIND}:${NOVNC_PORT}/vnc.html?autoconnect=1&resize=scale"
fi

# ---------------------------------------------------------------- GUI 用户环境
mkdir -p /run/user/"$FEILIAN_UID" /home/feilian/.config
chown "$FEILIAN_UID:$FEILIAN_UID" /run/user/"$FEILIAN_UID"
chmod 700 /run/user/"$FEILIAN_UID"
chown -R "$FEILIAN_UID:$FEILIAN_UID" /home/feilian/.config

# 一个独立 session bus，供 Electron 用；地址显式传给 GUI
SESSION_BUS_ADDRESS="$(runuser -u "$FEILIAN_USER" -- dbus-daemon --session --fork --print-address=1 --print-pid=2 2>/dev/null | head -n1)"
[ -n "$SESSION_BUS_ADDRESS" ] || log "警告：session dbus 未启动，GUI 仍会尝试运行"
log "session dbus: ${SESSION_BUS_ADDRESS:-none}"

# ---------------------------------------------------------------- 飞连服务（root）
if [ "$START_SERVICE" = "1" ]; then
  (
    set +e
    while :; do
      cd "$APP_DIR"
      "$APP_DIR/corplink-service" >>"$LOG_DIR/corplink-service.log" 2>&1
      rc=$?
      log "corplink-service 退出 rc=$rc，3s 后重启"
      sleep 3
    done
  ) &
  CHILDREN+=($!)
  log "corplink-service 守护已启动"
fi

# 服务要先监听本地 gRPC 端口，GUI 才连得上（否则界面会弹“未知错误 21110014”）
wait_for_service() {
  local i=0
  # GUI 首批请求打的是 31056（特权通道），31055 是主 gRPC；两个都等
  while [ "$i" -lt 120 ]; do
    if ss -ltn 2>/dev/null | grep -qE ':31056\b' \
       && ss -ltn 2>/dev/null | grep -qE ':31055\b'; then
      log "corplink-service 已监听本地端口 (31055/31056)"
      return 0
    fi
    i=$((i+1)); sleep 0.5
  done
  log "警告：corplink-service 60s 内没监听端口，GUI 仍会启动"
  return 1
}

# ---------------------------------------------------------------- 飞连 GUI（feilian 用户）
if [ "$START_GUI" = "1" ]; then
  [ "$START_SERVICE" = "1" ] && wait_for_service || true
  (
    set +e
    while :; do
      runuser -u "$FEILIAN_USER" -- env \
        HOME=/home/feilian \
        USER="$FEILIAN_USER" \
        LOGNAME="$FEILIAN_USER" \
        SHELL=/bin/bash \
        DISPLAY="$DISPLAY" \
        XDG_RUNTIME_DIR=/run/user/"$FEILIAN_UID" \
        XDG_SESSION_TYPE=x11 \
        DBUS_SESSION_BUS_ADDRESS="${SESSION_BUS_ADDRESS:-}" \
        LANG=zh_CN.UTF-8 \
        NODE_ENV=production \
        ELECTRON_DISABLE_SECURITY_WARNINGS=1 \
        "$APP_DIR/corplink" --no-sandbox $EXTRA_GUI_ARGS >>"$LOG_DIR/corplink-gui.log" 2>&1
      rc=$?
      log "corplink GUI 退出 rc=$rc，2s 后重启"
      sleep 2
    done
  ) &
  CHILDREN+=($!)
  log "corplink GUI 守护已启动（用户 $FEILIAN_USER）"
fi

# 日志转 stdout，便于 docker logs
tail -n +1 -F "$LOG_DIR"/*.log 2>/dev/null | sed -u 's/^/[log] /' &
CHILDREN+=($!)

log "启动完成。窗口请访问 noVNC（默认 http://127.0.0.1:${NOVNC_PORT}/）"
wait
