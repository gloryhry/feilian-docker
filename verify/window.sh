#!/usr/bin/env bash
# 抓一张容器内 X 显示的截图，证明窗口真的渲染出来了
set -Eeuo pipefail
cd "$(dirname "$0")/.."
NAME=${NAME:-feilian}
OUT=${OUT:-artifacts}
mkdir -p "$OUT"
ts=$(date +%Y%m%d-%H%M%S)
png="$OUT/window-$ts.png"

chrome=$(docker exec "$NAME" sh -c 'pgrep -af "files/corplink --no-sandbox" | head -3' 2>/dev/null || true)
echo "== GUI 进程"; echo "${chrome:-<无>}"

echo "== X 窗口树（前 40 行）"
docker exec "$NAME" sh -c 'DISPLAY=:99 xwininfo -root -tree 2>/dev/null | head -40' || true

echo "== 截图"
docker exec "$NAME" sh -c "DISPLAY=:99 scrot -o /tmp/fl-window.png" || { echo "scrot 失败"; exit 1; }
docker cp "$NAME:/tmp/fl-window.png" "$png" >/dev/null
echo "已保存: $png"
