#!/usr/bin/env bash
# 从火山引擎飞连官方下载页抓取 Linux 客户端直链并下载（amd64 + arm64 + rpm）。
set -Eeuo pipefail
cd "$(dirname "$0")/.."
mkdir -p dist

UA='Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36'
BUNDLE='https://lf6-cdn2-tos.bytegoofy.com/gftar/toutiao/fe_arch/fes2_app_17848070966032730/1.0.0.15/bundles/js/main.js'

echo "==> 拉取下载页数据（解析官方 CDN 直链，版本会随官网更新）"
tmp=$(mktemp)
curl -fsSL --max-time 120 -A "$UA" "$BUNDLE" -o "$tmp"

urls=$(grep -oE 'https://cdn\.isealsuite\.com/linux/FeiLian_Linux_[A-Za-z0-9_]+\.(deb|rpm)' "$tmp" | sort -u)
rm -f "$tmp"
if [ -z "$urls" ]; then
  echo "没解析到直链，改用页面内置的已知版本：" >&2
  urls=$(cat <<'EOF'
https://cdn.isealsuite.com/linux/FeiLian_Linux_amd64_v3.2.16_r8362_0d182a.deb
https://cdn.isealsuite.com/linux/FeiLian_Linux_arm64_v3.2.16_r8362_038591.deb
https://cdn.isealsuite.com/linux/FeiLian_Linux_amd64_v3.2.16_r8362_ea5f72.rpm
EOF
)
fi
printf '%s\n' "$urls"

for u in $urls; do
  f="dist/$(basename "$u")"
  [ -s "$f" ] && { echo "已存在 $f"; continue; }
  echo "==> 下载 $u"
  curl -fL --retry 3 --retry-delay 2 -o "$f.part" "$u"
  mv "$f.part" "$f"
done

echo "==> sha256"
sha256sum dist/*.deb dist/*.rpm 2>/dev/null || true
