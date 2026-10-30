# 飞连 (FeiLian) 容器化运行环境 · 企业网络出口

把火山引擎 **飞连 Linux 客户端** 关进容器里跑，并且把它变成**宿主机上其它程序可以按需使用的企业网络出口**：
登录照常在浏览器里做，出口通过 HTTP / SOCKS5 代理（可选 SNAT 网关）提供，而不是把宿主机整机流量割给 VPN。

- 官方安装包：`com.volcengine.feilian` **3.2.16**（r8362），amd64 / arm64 双架构
- 基础镜像：`debian:trixie-slim`，按 **digest** 固定
- 管理入口：容器内 `Xvfb → x11vnc → websockify(Unix socket) → nginx`，nginx 负责 **Basic 认证 + TLS + 来源 ACL**
- 数据面：`Privoxy`（HTTP）→ `microsocks`（SOCKS5），两个进程都是固定 UID 的非 root 用户
- DNS：项目自带的 `runtime/dns_forward.py` 做分域解析（企业域走隧道，公共域走 bootstrap）
- 防泄漏：容器内专属 `nftables` 表 `feilian_guard`，只匹配代理 UID，不碰宿主规则
- 隔离：零宿主目录挂载；无 `privileged`、无 `SYS_ADMIN`、无 `docker.sock`、无 host PID

> ⚠️ **本仓库验证到的是「实现 + 隔离模拟验收」这一层**。真实企业账号登录、MFA、企业内网准入
> 与物理 WiFi/macvlan 环境**没有**在本仓库验证过，不能据此宣称企业网络已打通。

---

## 目录结构

```
.
├── Dockerfile                 多阶段：runtime-dependencies / runtime-base / mock / production
├── compose.yaml               主模式：项目专属 bridge + NAT
├── compose.host.yaml          host 兼容模式（显式 opt-in，无托管出口）
├── compose.macvlan.yaml       macvlan 高级模式（强制 TLS/认证/来源 ACL）
├── build.sh                  经校验配置的 Buildx 封装（默认不推送）
├── run.sh                    预检 → 项目网络 → 启动（失败不自动切 host）
├── stop.sh                   优雅停止；仅显式 --cleanup-network 才回收网络
├── config/client.lock.json   客户端版本/URL/完整 SHA256/DEB 头/基础镜像 digest
├── scripts/
│   ├── config.py             受限配置解析（无 eval/source，严格白名单）
│   ├── client-artifacts.py   锁定下载与校验（validate/fetch/export/discover）
│   ├── build-image.py        Buildx 计划与执行
│   ├── secrets-cli.py        秘密卷生成/导入/轮换（宿主侧）
│   ├── network-resources.py  项目网络与 UFW 规则的 doctor/plan/apply/cleanup
│   ├── deploy.py             digest 固定的 plan/apply/rollback
│   ├── entrypoint.sh         容器 PID1：dbus → 网关准备 → 交给 supervisor
│   ├── status.sh             运行存活与 VPN 就绪分离查询
│   └── fetch-deb.sh          client-artifacts 的薄包装
├── runtime/
│   ├── supervisor.py         进程组、有界重启、就绪联动数据面、安全排空
│   ├── vpn_state.py          状态机与真实就绪探测（含 readiness TTL）
│   ├── dns_manager.py        DNS 单属主：策略渲染、原子替换、所有权恢复
│   ├── dns_forward.py        分域 DNS 转发器（企业域不回落公网）
│   ├── proxy_config.py       Privoxy + microsocks 配置渲染
│   ├── egress_policy.py      nftables 守卫（专属表、只匹配代理 UID）
│   ├── web_gateway.py        管理网关 nginx 配置（认证/TLS/ACL）
│   └── secrets_volume.py     容器内秘密卷 helper
├── verify/                   验收驱动与套件
└── tests/                    离线单元 + 隔离集成套件
```

---

## 快速开始

```bash
# 1. 取官方安装包（只按 config/client.lock.json 锁定版本，不自动追新）
bash scripts/fetch-deb.sh --arch all

# 2. 生成管理入口凭据与证书（写入专用命名卷，不落宿主机目录）
python3 scripts/secrets-cli.py ensure          # 默认 WEB_TLS=off；需要 TLS 时加 --set WEB_TLS=selfsigned

# 3. 构建（单架构默认 --load；多架构必须显式 --output 或 --push）
./build.sh --platform native

# 4. 启动（预检失败会停止并打印原因，绝不自动切 host）
./run.sh

# 5. 查看状态：容器是否活着 ≠ 企业网是否可用
bash scripts/status.sh
```

管理入口默认只绑 `127.0.0.1`；需要远程访问时用 SSH 隧道，**不要**直接把端口暴露出去：

```bash
ssh -L 6080:127.0.0.1:6080 you@host    # 浏览器打开 https://127.0.0.1:6080/
```

---

## 三种运行模式

| 模式 | 用途 | 硬限制 |
|---|---|---|
| `bridge`（默认，主支持） | 管理入口 + HTTP/SOCKS5 代理 + 分域 DNS + 可选网关/MSS | 不自动改宿主默认路由/DNS；宿主侧只允许项目网桥的显式放行 |
| `host`（显式 opt-in） | 官方客户端/本机 GUI 兼容 | 必须 `NET_MODE=host` **且** `ALLOW_HOST_NETWORK=1`；禁止托管代理、DNS 53 监听、网关、MSS、guard；不承诺隔离 |
| `macvlan`（高级） | 容器以独立 IP 出现在二层网络 | 必须显式 parent/subnet/空闲 IP，且强制 `WEB_TLS` + 认证 + 来源 ACL；无管理路径时拒绝启动 |

`NET_MODE=auto` 只等价于 `bridge`（仅做诊断），**永远不会**回退到 host。

---

## 代理用法

代理只在 VPN 就绪（且数据面打开）后才会工作；未就绪时连接会被拒绝，而不是悄悄走公网。

```bash
# HTTP 代理（80 走普通转发；CONNECT 仅限 PROXY_CONNECT_PORTS，默认 443）
curl -x http://127.0.0.1:8888 http://intranet.example/
curl -x http://127.0.0.1:8888 https://intranet.example/

# SOCKS5（socks5h：域名在容器侧解析，才能命中分域规则）
curl --proxy socks5h://127.0.0.1:1088 https://intranet.example/
```

- 原始代理**始终只允许回环**；LAN 直连代理不是本项目的安全默认，请用 SSH 隧道。
- `scripts/status.sh` 输出 `proxy_usable`：只有 `vpn_ready` 且 `data_plane=ready` 时才为真。

---

## 配置

所有配置走同一套校验（`scripts/config.py`），优先级 **CLI `--set` > 进程环境 > `.env` > 安全默认**。
`.env` 只接受 `KEY=字面值`，**不支持** `export`、变量展开、命令替换或行尾注释，也绝不会被 `source`。

常用项（完整见 [.env.example](.env.example)）：

| 键 | 默认 | 说明 |
|---|---|---|
| `NET_MODE` | `bridge` | `bridge`/`host`/`macvlan`；`auto` 等同 bridge |
| `ALLOW_HOST_NETWORK` | `0` | host 模式必须同时置 1 |
| `WEB_BIND` / `NOVNC_HOST_PORT` | `127.0.0.1` / `6080` | 非回环必须同时满足认证 + TLS + 来源 CIDR |
| `PROXY_ENABLED` / `PROXY_REQUIRE_VPN` | `1` / `1` | 未就绪不提供企业出口 |
| `HTTP_PROXY_HOST_PORT` / `SOCKS_PROXY_HOST_PORT` | `8888` / `1088` | 宿主侧发布端口 |
| `CORP_DOMAINS` / `CORP_CIDRS` | 空 | 真实企业域/网段，**不预填、不伪造** |
| `DNS_MODE` | `auto` | `split`（有企业域）/ `full` / `off` |
| `VPN_PROBE_DNS_NAME` / `VPN_PROBE_URL` | 空 | 就绪探测目标；缺失时状态为 `UNCONFIGURED`，不影响 GUI 登录 |
| `GATEWAY_ENABLED` / `MSS_MODE` | `0` / `off` | 可选 SNAT 网关与 MSS clamp |
| `GUARD_ENABLED` | `1` | 隔离模式下启用容器内 nftables 守卫 |

---

## 虚拟机的真实状态：`status.sh` 与健康检查

```json
{"runtime_live": true, "vpn_ready": false, "data_plane": "closed", "proxy_usable": false}
```

- **容器健康**（Docker `HEALTHCHECK`）只表示 supervisor 与其关键进程活着；
- **VPN 就绪**要求：隧道接口与目标路由真实存在 + 企业 DNS 解析成功 + 内部 HTTPS 探针证书与状态符合预期，且连续两次成功；
- **代理可用**要求就绪 **且** 数据面已打开（代理端口真的在接受连接）。

三者分别成立，任何一环都不能替代另一环。

---

## 升级与回滚（按 digest）

```bash
./deploy.sh plan   --image ghcr.io/<owner>/<repo>:<tag>
./deploy.sh apply  --image ghcr.io/<owner>/<repo>@sha256:<index> --yes
./deploy.sh rollback --yes
```

- 部署记录写在 `.state/<project>/deploy.json`（0600），记录的是 **digest**，不是可变 tag；
- `apply` 会保留上一 digest 作为回滚点，**从不删除数据卷**；
- `rollback` 只接受已记录且格式可校验的旧 digest，无记录时拒绝猜测；
- 官方客户端的会话状态会随版本迁移，所以「换回旧镜像」不等于「回滚数据」——正式环境请同时准备数据快照。

---

## 验收分级

| 级别 | 内容 | 当前状态 |
|---|---|---|
| L0 单元 | 配置解析、锁定下载、资源所有权、编排、DNS/代理/守卫渲染、秘密、部署回滚 | ✅ 273 项全绿 |
| L1 契约 | 三种模式的 Compose 渲染（端口/挂载/权限/秘密） | ✅ |
| L2 隔离集成 | 真实内核 TUN + 假企业 DNS/HTTPS + 抓包断言 + 故障注入 | 🟡 18 项 PASS，4 项未实现 |
| L3 真实客户端无账号 | 官方镜像启动、服务端口、GUI 登录页（**不等于**隧道可用） | ✅ CI 双架构原生 runner 通过 |
| L4 真实企业 | 企业识别码/账号/MFA、内网准入 | ❌ 未验证（需人工） |

L2 已通过的项包括：代理三件套（HTTP/CONNECT/SOCKS5h）经隧道访问企业目标、分域与全量 DNS、
断隧道/撤路由/IPv6 拒止、**控制器崩溃 fail-closed**、旧连接不再续传（规划中）、
owned-only 清理与外来 nft 表保护、抓包证明引导接口无企业明文流量。

未实现的 4 项（`fault.old_tcp`、`auth.tls_wss`、`gateway.snat`、`gateway.syn_mss`）**计为失败**，不会被当作通过。

```bash
bash verify/all.sh --suite unit
bash verify/all.sh --suite mock        # 需要 Docker；使用隔离网络与卷
```

---

## 安全边界（请如实理解）

- 防泄漏的承诺范围是**经本项目代理/网关的流量**，不是宿主机全局 kill-switch，也不是对容器 root 的恶意对抗保证。
- host 模式共享宿主 netns：官方客户端本身仍可能改宿主路由，退出也不保证完全恢复。
- 管理入口的 Basic 认证**只保护管理界面**；原始代理没有用户名密码，靠"只绑回环 + 来源 ACL"保护。
- 秘密放在专用命名卷，容器内只读挂载；宿主机不会有明文副本（可选的本地凭据备份为 0600）。
- 本机若存在透明代理（mihomo 等），Docker bridge 出网可能被劫持；本项目**不会**自动改你的代理或默认路由，
  `run.sh` 预检失败会直接停下并打印诊断。

---

## 镜像发布

- 源仓库：`github.com/gloryhry/feilian-docker`，开发分支 `feat/corplink-inspired-runtime`
- 镜像：`ghcr.io/gloryhry/feilian-docker`（**私有**）
- 发布方式：推送 `release-v*` 标签触发 `.github/workflows/client-release.yml`，在**原生 amd64 + arm64** runner 上
  分别构建并做真实客户端无账号冒烟，再合成多架构 index；默认不推 `latest`
- 最近一次发布：索引 `sha256:724a9177f96941590b8e420999fd3e9105d1357b6f9f8bdfb8f38000c3b28a36`
  （amd64 `43163c5e…`、arm64 `0a1eca3c…`），匿名拉取被拒（401），按 digest 拉取成功

> 官方客户端为第三方专有软件。发布镜像前请自行确认所在组织的再分发许可；
> 本仓库默认不公开分发客户端镜像。

---

## 已知限制

- 真实企业登录/MFA/准入未验证；`UNCONFIGURED` 是正常状态，不是故障。
- 官方客户端 GUI 是 Electron 22，依赖已按 Debian 13 补齐；其它发行版需自行调整。
- 企业合规/EDR 模块在容器内核能力受限时可能降级，属预期。
- macvlan 在云主机上常被 anti-spoofing 丢弃；无线 STA 基本不可用。
- L2 仍有 4 项未实现的验收门禁，见上表。
