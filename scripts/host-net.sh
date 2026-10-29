#!/usr/bin/env bash
# 宿主机侧网络准备（只在 bridge 模式需要；幂等，可重复执行）
#   1) ufw 默认 deny(routed) 会掐掉 docker 转发 -> 只放开 docker 网桥 <-> 上行口
#   2) 检测无线网卡 / TUN 代理，给出明确提示（不做危险改动）
set -Eeuo pipefail

SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

UP_IF=${UP_IF:-$(ip route show default 2>/dev/null | awk '/default/{print $5; exit}')}
[ -n "$UP_IF" ] || { echo "找不到默认路由出口，跳过"; exit 0; }

echo "==> 上行接口: $UP_IF"

if command -v ufw >/dev/null 2>&1 && $SUDO ufw status 2>/dev/null | grep -q 'Status: active'; then
  bridges=$($SUDO ip -br link show 2>/dev/null | awk '$1=="docker0" || $1 ~ /^br-/{print $1}')
  [ -n "$bridges" ] || bridges="docker0"
  for b in $bridges; do
    $SUDO ufw route allow in on "$b" out on "$UP_IF" >/dev/null 2>&1 || true
    $SUDO ufw route allow in on "$UP_IF" out on "$b" >/dev/null 2>&1 || true
    echo "    ufw: $b <-> $UP_IF 转发已放行"
  done
fi

wifi_list=$(for i in /sys/class/net/*; do n=$(basename "$i"); [ -e "$i/phy80211" ] && echo "$n"; done || true)
if [ -n "$wifi_list" ]; then
  echo "==> 无线接口: $(echo $wifi_list | tr '\n' ' ')"
else
  echo "==> 没有无线接口：容器只能走宿主机现有出口（有线/代理），无法自己关联 802.11"
fi

if ip link show 2>/dev/null | grep -qE ': (Mihomo|mihomo|Meta|clash|tun[0-9]+)'; then
  echo "==> 警告：检测到 TUN 模式代理（mihomo/clash）。它常把容器 TCP/DNS 劫持到 redir 端口，"
  echo "    结果是容器 ping 得通但上不了网。此时用 NET_MODE=host（run.sh 会自动判断）。"
fi
