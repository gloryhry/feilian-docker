#!/usr/bin/env bash
# 看容器内的网络：接口、路由、DNS、能否出网
set -uo pipefail
NAME=${NAME:-feilian}
echo "== 接口"; docker exec "$NAME" ip -br addr || true
echo "== 路由"; docker exec "$NAME" ip route || true
echo "== DNS"; docker exec "$NAME" cat /etc/resolv.conf | grep -v '^#' | grep . || true
echo "== 出网测试"
docker exec "$NAME" sh -c '
  ping -c1 -W2 223.5.5.5 >/dev/null 2>&1 && echo "ICMP 223.5.5.5 ok" || echo "ICMP 223.5.5.5 fail"
  curl -sS -m 10 -o /dev/null -w "HTTPS www.baidu.com => %{http_code}\n" https://www.baidu.com 2>&1 || true
  curl -sS -m 10 -o /dev/null -w "HTTPS www.volcengine.com => %{http_code}\n" https://www.volcengine.com 2>&1 || true
' || true
