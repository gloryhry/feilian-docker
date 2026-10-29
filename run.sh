#!/usr/bin/env bash
# 启动容器（自动选择 bridge / host 网络），并把 noVNC 地址打出来。
set -Eeuo pipefail
cd "$(dirname "$0")"

TAG=${TAG:-feilian-gui:3.2.16}
NET_MODE=${NET_MODE:-auto}          # auto | bridge | host | macvlan
PROBE_TIMEOUT=${PROBE_TIMEOUT:-8}

log() { printf '\033[36m[feilian]\033[0m %s\n' "$*"; }

if ! docker image inspect "$TAG" >/dev/null 2>&1; then
  log "镜像不存在，先构建"
  ./build.sh
fi

probe_ok() {
  docker run --rm --network "$1" --entrypoint bash "$TAG" -lc \
    "curl -sS -m ${PROBE_TIMEOUT} -o /dev/null -w '%{http_code}' https://www.baidu.com" 2>/dev/null \
    | grep -qE '200|30[0-9]'
}

case "$NET_MODE" in
  auto)
    log "测试 bridge 网络出网能力…"
    if probe_ok bridge; then
      NET_MODE=bridge
    else
      NET_MODE=host
      log "bridge 出网失败（宿主机透明代理/防火墙拦截）→ 改用 host 网络模式"
    fi
    ;;
esac

log "网络模式: $NET_MODE"
docker rm -f feilian >/dev/null 2>&1 || true

case "$NET_MODE" in
  bridge)
    docker compose -f compose.yaml up -d --force-recreate
    # 网络起来了才有 br-xxx 接口，这时再补 ufw 转发规则
    ./scripts/host-net.sh || log "host-net.sh 有告警，继续"
    URL="http://127.0.0.1:${NOVNC_PORT:-6080}/vnc.html?autoconnect=1&resize=scale"
    ;;
  host)
    log "注意：host 模式下飞连的 tun/路由会作用在宿主机上；退出即消失"
    docker compose -f compose.host.yaml up -d --force-recreate
    URL="http://127.0.0.1:${NOVNC_PORT:-6080}/vnc.html?autoconnect=1&resize=scale"
    ;;
  macvlan)
    log "macvlan 模式：需要先 'bash scripts/net-macvlan.sh create'（参数见脚本）"
    docker compose -f compose.macvlan.yaml up -d --force-recreate
    URL="http://<容器IP>:${NOVNC_PORT:-6080}/vnc.html?autoconnect=1&resize=scale"
    ;;
  *)
    echo "未知 NET_MODE=$NET_MODE" >&2; exit 1;;
esac

sleep 3
docker ps --filter name=^feilian$ --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
log "等 20~40 秒让 Electron 起来，然后打开："
printf '   %s\n' "$URL"
log "抓窗口快照（确认 GUI 已起来）: bash verify/window.sh"
log "日志: docker logs -f feilian"
