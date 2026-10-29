#!/usr/bin/env bash
# 停掉容器；host 模式下顺带确认飞连的 tun/路由已消失。
set -uo pipefail
cd "$(dirname "$0")"
docker rm -f feilian >/dev/null 2>&1 || true
echo "容器已停止"
if ip link show 2>/dev/null | grep -qE '^[0-9]+: (tun|utun|feilian)' ; then
  echo "警告：仍有 tun 类接口残留，检查一下：ip -br link; ip route"
fi
