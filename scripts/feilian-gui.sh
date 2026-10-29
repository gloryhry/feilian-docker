#!/usr/bin/env bash
# 手动在前台跑一次 GUI（调试用）：docker exec -it feilian feilian-gui.sh
set -Eeuo pipefail
APP_DIR=/opt/apps/com.volcengine.feilian/files
export DISPLAY="${DISPLAY:-:99}"
export NODE_ENV=production
mkdir -p /run/user/1000
chown 1000:1000 /run/user/1000
chmod 700 /run/user/1000
exec runuser -u feilian -- env \
  HOME=/home/feilian USER=feilian LOGNAME=feilian \
  DISPLAY="$DISPLAY" XDG_RUNTIME_DIR=/run/user/1000 XDG_SESSION_TYPE=x11 \
  LANG=zh_CN.UTF-8 NODE_ENV=production \
  "$APP_DIR/corplink" --no-sandbox "$@"
