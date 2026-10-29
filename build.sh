#!/usr/bin/env bash
# 构建飞连容器镜像。构建期使用 --network host：本机 apt/代理只在宿主网络下可用。
set -Eeuo pipefail
cd "$(dirname "$0")"

TAG=${TAG:-feilian-gui:3.2.16}
MIRROR=${DEBIAN_MIRROR:-}

shopt -s nullglob
debs=(dist/FeiLian_Linux_amd64_*.deb)
if [ ${#debs[@]} -eq 0 ]; then
  echo "dist/ 下没有 FeiLian_Linux_amd64_*.deb" >&2
  echo "下载：bash scripts/fetch-deb.sh" >&2
  exit 1
fi

echo "==> 使用安装包: ${debs[0]} ($(du -h "${debs[0]}" | cut -f1))"
echo "==> docker build -t $TAG"

build_args=(--network host -t "$TAG")
if [ -n "$MIRROR" ]; then build_args+=(--build-arg "DEBIAN_MIRROR=$MIRROR"); fi
if [ "${NO_CACHE:-0}" = "1" ]; then build_args+=(--no-cache); fi

docker build "${build_args[@]}" .
echo "==> 完成: $TAG"
