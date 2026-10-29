#!/usr/bin/env bash
# 把宿主机网卡（有线或无线）以 L2 方式映射进容器：macvlan。
# 注意：
#   - 无线 STA 网卡（wlan0）绝大多数驱动/AP 不支持 macvlan（4-address 模式被禁，AP 还会按 MAC 过滤）
#   - 云主机上常有 anti-spoofing，macvlan 的额外 MAC 会被上游丢弃
#   - 容器与宿主机互 ping 不通是 macvlan 的正常行为（要通需在宿主机加 shim 接口）
set -Eeuo pipefail

PARENT=${PARENT:-$(ip route show default | awk '/default/{print $5; exit}')}
SUBNET=${SUBNET:-}
GATEWAY=${GATEWAY:-}
IP=${IP:-}

usage() {
  cat <<EOF
用法:
  bash scripts/net-macvlan.sh create [parent=enp1s0] [subnet=192.168.0.0/20] [gateway=192.168.0.1]
  bash scripts/net-macvlan.sh destroy
参数可用环境变量 PARENT / SUBNET / GATEWAY / IP 覆盖
EOF
}

case "${1:-}" in
  create)
    [ -n "$PARENT" ] || { echo "无法确定物理网卡，请用 PARENT=wlan0 指定"; exit 1; }
    if [ -z "$SUBNET" ]; then
      SUBNET=$(ip -4 -o addr show dev "$PARENT" | awk '{print $4}' | head -n1)
      echo "==> 从 $PARENT 推断子网: $SUBNET"
    fi
    [ -n "$GATEWAY" ] || GATEWAY=$(ip route show default | awk '/default/{print $3; exit}')
    docker network rm feilian-macvlan >/dev/null 2>&1 || true
    docker network create -d macvlan \
      --subnet "$SUBNET" --gateway "$GATEWAY" \
      -o parent="$PARENT" \
      feilian-macvlan
    echo "==> 已创建 macvlan 网络 feilian-macvlan（parent=$PARENT）"
    echo "    compose.macvlan.yaml 里把 ipv4_address 设成同网段的空闲 IP"
    ;;
  destroy)
    docker network rm feilian-macvlan 2>/dev/null || true
    echo "==> 已删除"
    ;;
  *) usage; exit 1;;
esac
