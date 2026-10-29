# 企业网络出口升级：已批准的执行计划

## 目标和完成边界

在保留 Debian slim、官方飞连 3.2.16、轻量 noVNC 和命名卷的基础上，分阶段实现安全企业网络出口。本计划已由用户通过计划审批批准。

- 源码交付：`github.com/gloryhry/feilian-docker` 的独立 `feat/corplink-inspired-runtime` 分支；不强推、不直接合并 main。
- 镜像交付：`ghcr.io/gloryhry/feilian-docker`，必须为私有包。真实双架构客户端镜像、私有性及 digest 拉取均验证后才完成发布目标。
- 本次包含代码、隔离模拟网络验收及真实客户端无账号冒烟；真实企业登录/MFA/内网准入、物理 WiFi/macvlan 联调另列，不能虚报已通过。
- 宿主只允许项目网桥/子网/接口范围内可回滚的调整。不改 mihomo 全局、宿主默认路由/DNS、全局防火墙策略或 Docker daemon 配置。
- 不添加 privileged、SYS_ADMIN、host PID 或 docker.sock；不以升级权限掩盖兼容问题。

## 持久 Goal

批准后创建的目标按 G0–G7 递进，最多 24 个自动续轮。每轮记录变更、实际测试、失败、未验证项和下一步；不是用轮数代替验收。没有 GitHub/GHCR 权限、ARM 资源或官方客户端再分发批准时保留外部门禁，不降标、不公开发布、不用 mock 镜像替代正式镜像。

遇到阻塞先请求需要的输入，并继续独立工作；同一硬阻塞持续至少三轮且无独立任务后才按工具规则标 blocked。达到轮数上限仍未完成时准确交接。恢复后由用户请求继续时 resume 原目标。

## 固定架构

- 官方客户端：deb 解包而不执行 maintainer scripts；GUI 非 root。
- GUI：Xvfb/x11vnc/noVNC，内部后端加 Nginx 认证/TLS 管理入口；不迁 Kasm 桌面。
- 代理：Debian Privoxy + Dante；HTTP 经本机 SOCKS5 转发，统一 DNS/目标和 VPN 出口。Privoxy 没有客户端认证，Web 认证不等于正向代理认证。
- 代理默认本机/明确受信来源，远程用 SSH 隧道，不直接开放 LAN/公网原始代理；第一版 SOCKS TCP-only。
- DNS/状态：Python 标准库小控制器 + dnsmasq，单一 resolver owner；分离 liveness/readiness，不把公网 HTTP/进程存在当企业 VPN 就绪。
- 防火墙：仅隔离容器 netns 的 nft 专属表；不 flush ruleset，不改第三方规则和默认策略。
- 秘密：专用命名卷、离线 helper/stdin 初始化；不挂宿主目录，不把密码放镜像、Docker 配置环境、日志或 git。单文件 secret 是明确的可选例外。
- 配置：CLI > 进程环境 > 受限 dotenv > 锁定值/安全默认；不 eval/source 用户配置，Compose 不再次自行解释配置文件。

### 模式边界

| 模式 | 允许 | 限制 |
| --- | --- | --- |
| bridge | 管理、代理、托管 DNS、防泄漏、可选网关/MSS | 主支持；不自动切 host；宿主调整限本项目。 |
| host | 显式兼容的客户端/本机 GUI | 双 opt-in；禁止托管代理、DNS 53 监听、网关/MSS/额外 guard；不承诺隔离或停止必然恢复。 |
| macvlan | 容器内隔离出口 | 显式有线 parent/子网/空闲 IP、安全管理路径；TLS/认证/source ACL；shim 需明确开启且 /32。 |

X11 显式 opt-in，不能声称与默认 noVNC 隔离等价。原始代理不因管理 TLS 自动变安全。

## 阶段和门禁

### G0 配置与安全资源基础

统一配置、别名迁移、模式约束、dry-run；预检先于破坏性操作。取消自动 host 与预检前 `rm -f`。宿主网络 doctor/plan/apply/cleanup 只针对有 owner 的项目资源，macvlan 配置一致复用，不先删同名网络。补忽略规则、严格契约测试。

### G1 锁定下载与双架构构建

`config/client.lock.json` schema v1 是唯一客户端版本源：每架构 URL、完整 hash、DEB header、来源，基础镜像 index digest。默认只锁定下载；discover 只候选，不 fallback。缓存复核，临时下载、有限重试、原子归位、offline。构建用独立包 context，TARGETARCH 精确选包并镜像内二次核验。单架构 load，多架构 OCI/显式 push，不自动安装 binfmt。

官方无签名时记录“官方 HTTPS + 维护者审阅后字节锁定”，不把本地 hash 当厂商签名。

### G2 认证/TLS、秘密与生命周期

Nginx 认证/TLS/WebSocket，非回环缺安全配置 fail-closed；秘密生成/导入/轮换和命名卷；进程组清理、有界重启，等待认证不重启风暴；显式 capabilities 并以测试收敛。

### G3 DNS、VPN 状态和就绪

状态 UNCONFIGURED/WAITING_AUTH/VALIDATING/READY/DEGRADED/DISCONNECTED/DRAINING。以 DNS、接口/目标路由、内部 HTTPS 证书/期望状态联合判断。防半写/陈旧/null JSON，限制字段和大小。split 企业域无公网 fallback；断开恢复公共 bootstrap 但企业域仍封锁。保留解析文件 inode，运行配置原子更新、清缓存，按 owner 恢复。

### G4 代理与数据面防泄漏

READY 才接受企业业务；source/目标 CIDR/CONNECT 端口 ACL；阻止自管地址、metadata、loopback、后台服务和重绑定。Dante 外连 VPN 地址，无 eth0 回落；HTTP 无直接公网旁路。容器专属规则阻断隧道撤销、旧连接重路由和失效控制器后的泄漏。第一版明确阻断未支持的企业 IPv6 数据面。

防泄漏范围只承诺本项目代理/网关，不是宿主全局 kill-switch，不是对容器 root 的恶意对抗证明。

### G5 网关/MSS 与回收

网关默认关，独立受信 access 网、稳定 IP、显式源/企业目的。仅容器 IP forward、限域 FORWARD 和 SNAT、必要回程；消费者只添加企业路由。MSS 仅相应 FORWARD，检查真实 SYN。退出先撤就绪并保护/停止数据面，再停客户端、恢复 DNS、撤 owned 规则；默认保留数据卷和外部网络。

### G6 CI、私有发布与数据配套回滚

PR/push 单元/Compose/mock，不公开官方包/真实缓存/会话/截图。受保护发布 workflow 用 amd64+原生 ARM64 冒烟后组合 index；最小 packages 权限、私有 GHCR、许可/审批门禁。版本+revision+wrapper+commit 不可变 tag，digest 部署，不默认覆盖 latest。plan/apply/rollback 要同时考虑镜像和数据迁移，独立测试卷演练。

### G7 集成与真实交付

全量模拟和 amd64 无账号 smoke 后推独立分支；运行远端检查、ARM64 smoke；明确 tag 触发受保护发布（新 workflow 未进默认分支时不依赖 dispatch）。认证拉取、GitHub API private、含匿名 token 流程的匿名拉取拒绝；index/digest 匹配。完善 README、配置、安全、代理/DNS/网关、升级/回滚、人工验收与结果矩阵。

## 测试等级

1. L0：Python unittest、bash 语法、系统命令桩，无 daemon/network 修改。
2. L1：Compose JSON 契约，dummy 配置，无真实秘密。
3. L2：隔离本地 DNS/测试 CA HTTPS/模拟隧道/公共出口记录器/消费容器；测试断线、旧连接、IPv6、ACL、认证、清理。
4. L3：amd64/ARM64 官方客户端无账号，登录页不是隧道成功；原生/模拟分别记录。
5. L4：真实企业人工登录，用户自己输入账号/MFA，本次不作为完成条件。
6. 发布：真实私有 GHCR/digest/index/认证和匿名拉取/配套数据回滚。

PASS/FAIL/WAITING_AUTH/SKIP 明确区分，必需项 SKIP 不能结清目标；Docker health 仅适配 0/1。隔离依据挂载/namespace/capability/设备契约，不依赖读取宿主 shadow 或一次截图作绝对证明。

## 最终完成清单

- 双代理、DNS/状态、认证/TLS、限域 guard、网关/MSS 的正负模拟验收通过。
- 配置、锁定下载、生命周期、owned-only 回收通过，第三方服务/宿主全局网络未擅改。
- 两架构构建链路完整且实际无账号 smoke 有证据。
- 测试卷完成镜像+数据升级回滚。
- 独立 GitHub 分支推送、远端必需检查通过。
- 双架构真实客户端镜像私有 GHCR 发布和 digest/私有性验证通过。
- 文档、配置、验收报告齐全，未验真实企业/物理环境清楚列出。
