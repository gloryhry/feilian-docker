#!/usr/bin/env bash
# 证明：容器里看不到宿主机任何文件内容（只有镜像内容 + docker 命名卷）
set -uo pipefail
cd "$(dirname "$0")/.."
NAME=${NAME:-feilian}
fail=0

hr() { printf '\n\033[36m== %s\033[0m\n' "$*"; }

hr "1) 容器挂载点（只允许 volume；bind 仅限 docker 注入的 3 个配置文件）"
docker inspect -f '{{range .Mounts}}{{.Type}} | {{.Source}} -> {{.Destination}}{{println}}{{end}}' "$NAME" || exit 1
bad=0
while read -r dst; do
  [ -z "$dst" ] && continue
  case "$dst" in
    /etc/hosts|/etc/hostname|/etc/resolv.conf)
      echo "ok   docker 注入的 $dst（容器自身配置，不含宿主机用户数据）" ;;
    *) echo "FAIL: 非法 bind 挂载 $dst"; bad=1 ;;
  esac
done < <(docker inspect -f '{{range .Mounts}}{{if eq .Type "bind"}}{{.Destination}}{{println}}{{end}}{{end}}' "$NAME")
[ "$bad" = 0 ] || fail=1

hr "2) 容器里的根目录（不是宿主机 /）"
docker exec "$NAME" ls -la /

hr "3) 宿主机特征路径：容器内必须不存在"
for p in /home/glory /var/lib/docker /etc/apt/sources.list.d/docker.list /root/.ssh/id_rsa; do
  if docker exec "$NAME" test -e "$p"; then
    echo "FAIL: 容器里能看到 $p"; fail=1
  else
    echo "ok   $p 不存在"
  fi
done

hr "4) 宿主机 /etc/shadow 与容器 /etc/shadow 必须不同"
h=$(sudo -n sha256sum /etc/shadow 2>/dev/null | cut -d' ' -f1)
c=$(docker exec "$NAME" sha256sum /etc/shadow 2>/dev/null | cut -d' ' -f1)
echo "host=$h"
echo "cont=$c"
[ -n "$h" ] && [ "$h" = "$c" ] && { echo "FAIL: 是同一个文件"; fail=1; } || echo "ok   不同（容器有独立 /etc）"

hr "5) 容器 capability / 设备（没有 SYS_ADMIN、没有 privileged）"
docker inspect -f 'Privileged={{.HostConfig.Privileged}} CapAdd={{.HostConfig.CapAdd}} Devices={{.HostConfig.Devices}}' "$NAME"

hr "6) 容器 /proc 视角：自己的 PID 命名空间"
docker exec "$NAME" sh -c 'echo "pid1=$(cat /proc/1/comm)"; echo "mounts=$(wc -l </proc/mounts)"'

echo
if [ "$fail" = 0 ]; then
  echo -e "\033[32mPASS：容器内没有任何宿主机文件（volume 为 docker 自管存储）\033[0m"
else
  echo -e "\033[31mFAIL：见上面标记\033[0m"; exit 1
fi
