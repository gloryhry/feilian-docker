# syntax=docker/dockerfile:1.7
# Public runtime context only. Official installers and mock fixtures enter through
# separate, explicitly selected BuildKit named contexts, never the root context.
ARG BASE_IMAGE=debian:trixie-slim@sha256:f6b08b09a05725f9431502d3b5714f5c4576e82c1a84fa1debe0c24a7e0c3ec4
FROM ${BASE_IMAGE} AS runtime-dependencies

ARG DEBIAN_MIRROR=""
ARG CLIENT_VERSION
ARG CLIENT_REVISION
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=zh_CN.UTF-8 \
    LANGUAGE=zh_CN:zh \
    LC_ALL=zh_CN.UTF-8 \
    TZ=Asia/Shanghai \
    FEILIAN_ROOT=/opt/feilian

# The mirror is an explicit build setting, not an automatic host-network fallback.
# Constrain sed replacement characters even if somebody bypasses build.sh.
RUN set -eu; \
    if [ -n "$DEBIAN_MIRROR" ]; then \
        case "$DEBIAN_MIRROR" in http://*|https://*) ;; *) exit 2 ;; esac; \
        case "$DEBIAN_MIRROR" in *[!a-zA-Z0-9:/._~-]*) exit 2 ;; esac; \
        sed -i "s|http://deb.debian.org/debian|${DEBIAN_MIRROR}|g" /etc/apt/sources.list.d/debian.sources; \
    fi; \
    printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d; \
    chmod 755 /usr/sbin/policy-rc.d; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        xvfb xauth x11-utils x11-xserver-utils x11vnc novnc websockify scrot \
        dbus dbus-x11 network-manager dnsmasq-base iw iproute2 iputils-ping \
        procps psmisc ca-certificates curl locales \
        libxtst6 libnss3 libnss3-tools auditd \
        libgtk-3-0 libgbm1 libasound2t64 libatspi2.0-0 libatk1.0-0 libatk-bridge2.0-0 \
        libcups2 libdrm2 libxkbcommon0 libxcomposite1 libxdamage1 libxfixes3 \
        libxrandr2 libpango-1.0-0 libcairo2 libx11-6 libx11-xcb1 libxcb1 \
        libxcb-dri3-0 libxext6 libxss1 libsecret-1-0 libcanberra0 libcanberra-gtk3-0 \
        fonts-noto-cjk fonts-dejavu-core \
        nginx-light openssl apache2-utils privoxy microsocks nftables python3; \
    LC_ALL=C.UTF-8 localedef -i zh_CN -f UTF-8 zh_CN.UTF-8; \
    rm -rf /var/lib/apt/lists/*

RUN groupadd -g 1000 feilian \
 && useradd -m -u 1000 -g 1000 -s /bin/bash feilian \
 && groupadd -g 1001 feilian-proxy \
 && useradd -M -u 1001 -g 1001 -d /nonexistent -s /usr/sbin/nologin feilian-socks \
 && useradd -M -u 1002 -g 1001 -d /nonexistent -s /usr/sbin/nologin feilian-http \
 && mkdir -p /home/feilian/.config/CorpLink/logs \
 && chown -R feilian:feilian /home/feilian \
 && mkdir -p /etc/NetworkManager/conf.d \
 && printf '%s\n' \
      '[keyfile]' \
      'unmanaged-devices=interface-name:eth0;interface-name:docker0;interface-name:veth*;interface-name:br-*' \
      > /etc/NetworkManager/conf.d/99-feilian-unmanaged.conf \
 && mkdir -p /etc/NetworkManager/system-connections /var/lib/NetworkManager \
 && chmod 700 /etc/NetworkManager/system-connections

FROM runtime-dependencies AS runtime-base
COPY scripts/ /opt/feilian/scripts/
COPY config/ /opt/feilian/config/
COPY runtime/ /opt/feilian/runtime/
RUN chmod 755 /opt/feilian/scripts/entrypoint.sh /opt/feilian/scripts/feilian-gui.sh \
 && ln -s /opt/feilian/scripts/entrypoint.sh /usr/local/bin/entrypoint.sh \
 && ln -s /opt/feilian/scripts/feilian-gui.sh /usr/local/bin/feilian-gui.sh

LABEL io.feilian.runtime.schema="1" \
      io.feilian.features="config,artifact-lock" \
      io.feilian.client.version="${CLIENT_VERSION}" \
      io.feilian.client.revision="${CLIENT_REVISION}" \
      org.opencontainers.image.title="FeiLian container runtime"

ENV GUI_MODE=vnc \
    DISPLAY_NUM=99 \
    VNC_GEOMETRY=1600x1000x24 \
    NOVNC_BIND=0.0.0.0 \
    NOVNC_PORT=6080 \
    VNC_PORT=5900 \
    START_NETWORKMANAGER=1 \
    START_SERVICE=1 \
    START_GUI=1
WORKDIR /opt/feilian
EXPOSE 6080
# Process liveness only, not a claim that the VPN has authenticated or is ready.
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
    CMD pgrep -f '/opt/apps/com.volcengine.feilian/files/corplink-service' >/dev/null || exit 1
ENTRYPOINT ["/opt/feilian/scripts/entrypoint.sh"]

# This target never inherits production and never references client_dist.
# Fixture contract: client/corplink and client/corplink-service (plus local helpers).
FROM runtime-base AS mock
COPY --from=test_fixtures /client/ /opt/apps/com.volcengine.feilian/files/
RUN test -f /opt/apps/com.volcengine.feilian/files/corplink \
 && test -f /opt/apps/com.volcengine.feilian/files/corplink-service \
 && chmod 755 /opt/apps/com.volcengine.feilian/files/corplink \
              /opt/apps/com.volcengine.feilian/files/corplink-service
ENV FEILIAN_CLIENT_KIND=mock
LABEL io.feilian.client.kind="mock"

# Deliberately last: a direct build cannot accidentally default to the mock target.
FROM runtime-base AS production
ARG TARGETARCH
ARG CLIENT_SHA256_AMD64
ARG CLIENT_SHA256_ARM64
ARG CLIENT_DEB_PACKAGE
ARG CLIENT_DEB_VERSION
# No glob, filename discovery, install script, or embedded installer image layer.
# The host fetcher checks this first; the image independently rechecks exact bytes
# and actual control headers before extraction for the requested TARGETARCH.
RUN --mount=type=bind,from=client_dist,source=/,target=/tmp/feilian-dist,ro \
    set -eu; \
    case "$TARGETARCH" in \
        amd64) expected_sha="$CLIENT_SHA256_AMD64" ;; \
        arm64) expected_sha="$CLIENT_SHA256_ARM64" ;; \
        *) printf 'Unsupported TARGETARCH\n' >&2; exit 2 ;; \
    esac; \
    test "${#expected_sha}" -eq 64; \
    case "$expected_sha" in *[!0-9a-f]*) exit 2 ;; esac; \
    deb="/tmp/feilian-dist/${TARGETARCH}/client.deb"; \
    test -f "$deb"; \
    printf '%s  %s\n' "$expected_sha" "$deb" | sha256sum --check --strict -; \
    test "$CLIENT_DEB_PACKAGE" = 'com.volcengine.feilian'; \
    test -n "$CLIENT_DEB_VERSION"; \
    test "$(dpkg-deb --field "$deb" Package)" = "$CLIENT_DEB_PACKAGE"; \
    test "$(dpkg-deb --field "$deb" Version)" = "$CLIENT_DEB_VERSION"; \
    test "$(dpkg-deb --field "$deb" Architecture)" = "$TARGETARCH"; \
    dpkg-deb --extract "$deb" /; \
    mkdir -p \
        /opt/apps/com.volcengine.feilian/files/data/edlp/back_paks/ui \
        /opt/apps/com.volcengine.feilian/files/data/edlp/back_paks/cfg \
        /opt/apps/com.volcengine.feilian/files/logs; \
    chown -R root:root /opt/apps/com.volcengine.feilian/files; \
    chown root:root /etc/NetworkManager/dnsmasq.d/corplink.conf; \
    chmod 755 /opt/apps/com.volcengine.feilian/files/corplink \
              /opt/apps/com.volcengine.feilian/files/corplink-service
ENV FEILIAN_CLIENT_KIND=official
LABEL io.feilian.client.kind="official"
