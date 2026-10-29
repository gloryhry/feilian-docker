# syntax=docker/dockerfile:1.7
#
# 飞连 (FeiLian) Linux 客户端 · 容器化运行时
#   - 官方 deb 解包安装，不执行 maintainer scripts（避免安装期拉起 systemd）
#   - Electron GUI 以非 root 用户运行，渲染到容器内 Xvfb
#   - Xvfb -> x11vnc -> noVNC/websockify：宿主机用浏览器或 VNC 客户端看窗口
#   - 容器文件系统只有镜像内容 + docker 命名卷，不挂载任何宿主机目录
#
# 构建：build.sh（内部使用 --network host 以适配本机代理环境）
# 版本：飞连 3.2.16 / Electron 22.3.27

FROM debian:trixie-slim

ARG DEBIAN_MIRROR=""
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=zh_CN.UTF-8 \
    LANGUAGE=zh_CN:zh \
    LC_ALL=zh_CN.UTF-8 \
    TZ=Asia/Shanghai

# Debian 13 使用 deb822 源；可用 --build-arg DEBIAN_MIRROR= 指定镜像站
RUN if [ -n "$DEBIAN_MIRROR" ]; then \
        sed -i "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    fi

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
    # --- GUI 传输链路 ---
    xvfb xauth x11-utils x11-xserver-utils x11vnc novnc websockify scrot \
    # --- dbus / 网络 ---
    dbus dbus-x11 network-manager dnsmasq-base iw iproute2 iputils-ping \
    procps psmisc ca-certificates curl \
    # --- 飞连 deb 声明的依赖 ---
    libxtst6 libnss3 libnss3-tools auditd \
    # --- Electron 22 运行时依赖 ---
    libgtk-3-0 libgbm1 libasound2t64 libatspi2.0-0 libatk1.0-0 libatk-bridge2.0-0 \
    libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
    libxrandr2 libpango-1.0-0 libcairo2 libx11-6 libx11-xcb1 libxcb1 \
    libxcb-dri3-0 libxext6 libxss1 libsecret-1-0 libcanberra0 libcanberra-gtk3-0 \
    # --- 中文字体（登录界面必需） ---
    fonts-noto-cjk fonts-dejavu-core \
 && rm -rf /var/lib/apt/lists/*

# ---- 飞连客户端：解包安装，不跑 postinst（它依赖 systemd / 交互式会话） ----
# 用 bind mount 而不是 COPY，安装包不会留在镜像层里（省 250MB）
RUN --mount=type=bind,source=dist,target=/tmp/feilian-dist,ro \
    set -eux; \
    deb="$(ls /tmp/feilian-dist/FeiLian_Linux_amd64_*.deb | head -n1)"; \
    dpkg-deb -x "$deb" /; \
    mkdir -p \
      /opt/apps/com.volcengine.feilian/files/data/edlp/back_paks/ui \
      /opt/apps/com.volcengine.feilian/files/data/edlp/back_paks/cfg \
      /opt/apps/com.volcengine.feilian/files/logs; \
    chown -R root:root /opt/apps/com.volcengine.feilian/files; \
    chown root:root /etc/NetworkManager/dnsmasq.d/corplink.conf; \
    chmod 755 /opt/apps/com.volcengine.feilian/files/corplink \
              /opt/apps/com.volcengine.feilian/files/corplink-service

# ---- 运行期用户：GUI 不以 root 跑 ----
RUN groupadd -g 1000 feilian \
 && useradd -m -u 1000 -g 1000 -s /bin/bash feilian \
 && mkdir -p /home/feilian/.config/CorpLink/logs \
 && chown -R feilian:feilian /home/feilian

# ---- NetworkManager：只接管 VPN/无线相关设备，绝不碰 eth0（会打断容器网络） ----
RUN mkdir -p /etc/NetworkManager/conf.d \
 && printf '%s\n' \
    '[keyfile]' \
    'unmanaged-devices=interface-name:eth0;interface-name:docker0;interface-name:veth*;interface-name:br-*' \
    > /etc/NetworkManager/conf.d/99-feilian-unmanaged.conf \
 && mkdir -p /etc/NetworkManager/system-connections /var/lib/NetworkManager \
 && chmod 700 /etc/NetworkManager/system-connections

# ---- 运行期入口 ----
COPY scripts/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY scripts/feilian-gui.sh /usr/local/bin/feilian-gui.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh /usr/local/bin/feilian-gui.sh

ENV GUI_MODE=vnc \
    DISPLAY_NUM=99 \
    VNC_GEOMETRY=1600x1000x24 \
    NOVNC_BIND=0.0.0.0 \
    NOVNC_PORT=6080 \
    VNC_PORT=5900 \
    START_NETWORKMANAGER=1 \
    START_SERVICE=1 \
    START_GUI=1

EXPOSE 6080 5900
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD pgrep -f '/opt/apps/com.volcengine.feilian/files/corplink-service' >/dev/null || exit 1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
