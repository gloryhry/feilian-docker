# 实施进度与验收记录

## 基线

- 已批准方案： [执行计划](implementation-plan.md)。
- 基线提交：`d74a5f00d0cfbe528b190545d8d345320b344a6e`，实施前工作树干净。
- 实施分支：`feat/corplink-inspired-runtime`，不直接合并 main、不强推。
- 已有回退镜像：`feilian-gui:3.2.16`；开始时无飞连运行容器。
- 现有 mihomo/OpenResty 保持不变；本机 amd64，原 builder 仅报告 amd64。
- Goal：24 轮上限；真实企业登录不属本轮完成条件，真实 GitHub/GHCR 和双架构交付是门禁。

## 阶段状态

| 阶段 | 状态 | 当前证据 |
| --- | --- | --- |
| G0 配置/安全启动/所有权 | PASS (L0/L1) | 75项配置/资源/lifecycle/Compose隔离检查通过；尚未启动正式客户端。 |
| G1 锁定下载/Buildx | PASS (L0 + real deps build) | 双架构锁+24项artifact测试；依赖层已真实构建成功。 |
| G2 管理/秘密/生命周期 | IN_PROGRESS | 秘密/网关模块+42测试，运行时编排进行中。 |
| G3 DNS/状态/就绪 | IN_PROGRESS | 模块+88测试；DNS上游接口绑定已补，未做真实dnsmasq/隧道联调。 |
| G4 双代理/guard | IN_PROGRESS | 渲染器+单元测试；数据面未在隔离网络实跑。 |
| G5 网关/MSS/清理 | IN_PROGRESS | 渲染器已实现；真实 SNAT/MSS 包级验收未做。 |
| G6 CI/回滚 | IN_PROGRESS | 工作流已在远端真实运行并发布双架构镜像；`scripts/deploy.sh` digest 升级/回滚已实现（8 项离线测试），真实卷演练待做。 |
| G7 集成/GitHub/GHCR | PUBLISHED | 分支 + 标签已推送；双架构镜像已发布到私有 GHCR 并按 digest 验证。 |

## 执行记录

### 启动轮

- 只读核对 cwd、git status、分支和基线提交；结果工作树干净。
- 创建独立分支成功；未停止/重建容器、未修改宿主网络。
- 并行任务：config-contract 仅负责统一配置及专属单元测试；artifact-lock 仅负责锁定下载与专属单元测试；Lead 负责共享入口、网络资源工具、Compose 和整合。
- Lead已独立整合运行 `PYTHONPATH=tests/unit python3 -m unittest -v test_config test_network_resources test_lifecycle test_compose test_artifacts`：99项全部PASS（8.096s），其中G0为75项、artifact为24项；七个脚本bash -n、git diff --check均PASS。单元用命令桩，Compose只做JSON渲染。
- 通过边界包含配置优先级/注入拒绝/无partial export、host显式授权与非法功能拒绝、bridge失败不删除服务/不升级host、owned-only清理、UFW关闭时持久规则回收、IPv6管理回环长端口语法。
- Lead已read完整artifact实现并独立validate锁、fetch --arch all --offline复核两架构cache，全部通过；原amd64基线包保留。来源为官方HTTPS字节审阅固定摘要，不是厂商签名验证。
- 为确认G2接口，实际运行了四个一次性network-none/cap-drop ALL的基线帮助/假密码进程，均已自动删除：websockify帮助、xmessage存在性、Unix listener语法（2秒预期超时）、x11vnc stdin生成8字节测试密码文件。未运行官方客户端/GUI、未挂宿主目录、未建立对外网络。Unix后端无需source端口，支持--unix-listen和0660模式。
- 真实依赖层构建：`docker buildx build --target runtime-dependencies --platform linux/amd64 --load` 成功（264s，镜像 `feilian-runtime-deps:3.2.16-dev`），显式 `--network host` 仅用于适配本机代理。构建后实测镜像内 microsocks/privoxy/nginx/websockify/nft/dnsmasq/x11vnc/xmessage 均存在，feilian/feilian-socks/feilian-http 与 feilian-proxy 组已创建，zh_CN.utf8 locale 已生成。
- 发现并修正两个真实缺陷：Debian trixie **没有 dante-server 包**（APT 报 Unable to locate），数据面改为同源可用包 microsocks（`-b` 绑定出站 VPN 源地址，ACL 由 nft guard 承担）；vpn-state 中断导致 DNS 严格接口校验与测试不同步，已补齐夹具后 24 项 DNS 测试恢复全绿。
- 当前整体离线测试：243 项全部 PASS（11.97s），由 Lead 实际执行。
- 真实 production 镜像构建成功：`docker buildx build --target production --platform linux/amd64 --load --build-context client_dist=dist/3.2.16`（镜像 `feilian-official:3.2.16-dev`，672,543,394 字节）。镜像内构建阶段打印 `/tmp/feilian-dist/amd64/client.deb: OK`，即 SHA256 与 DEB 头二次校验通过后才解包。容器内实测 `corplink`/`corplink-service` 存在，`ldd` 未发现缺失共享库（0/0），labels 含 `io.feilian.client.kind=official`、`runtime.schema=1`。
- 运行时编排真实冒烟（mock 镜像 `feilian-mock:smoke1`，--network none，按 Compose 显式能力清单）：system dbus 就绪；supervisor 托管 service/controller/dnsmasq/x11vnc/nginx；`supervisor.py health` 退出 0；`vpn_state.py status` 返回 `state=UNCONFIGURED, ready=false, reason=corporate_probe_not_configured`；dnsmasq 仅监听 127.0.0.1:53，x11vnc 127.0.0.1:5900，mock 服务 31055/31056；`docker stop -t 25` 正常排空退出。数据面保持 closed，未伪造 READY。
- 期间发现并修复：`--cap-drop ALL` 会让 dbus-daemon 无法降权而启动失败（`Failed to drop capabilities`），必须使用 Compose 中的显式能力清单；entrypoint 已按此运行。
- G7 进展：功能分支 `feat/corplink-inspired-runtime` 已推送到 `github.com/gloryhry/feilian-docker`（`ls-remote` 显示 `36e58b1...`，随后追加 CI 提交 `03699e8`）。`git push --dry-run` 预检与实际推送均成功，未强推、未合并 main。
- G6 进展：`.github/workflows/check.yml`（PR/push 仅离线：语法、单元、Compose 渲染、禁止提交安装包/秘密）与 `client-release.yml`（仅 workflow_dispatch、`private-release` 受保护环境、`vars.CLIENT_REDISTRIBUTION_APPROVED=true` 门禁、amd64+arm64 原生 runner、拒绝非 official 标签镜像）已落盘，并用真实 YAML 解析器校验通过；尚未在远端实际运行。
- **GHCR 发布门禁（仍未完成）**：YG 已在本地完成 `docker login ghcr.io`（`~/.docker/config.json` 出现 `ghcr.io` 条目，凭据未读取）。但三次 `docker push` 均在同一阶段失败：`failed commit on ref "layer-sha256:...": Put https://ghcr.io/v2/... net/http: timeout awaiting response headers`。已尝试拆小镜像层（apt 安装拆成 4 个 RUN，最大单层由 830MB 降到 751MB）后重推，仍在新的大 blob 上超时。结论：这是本机到 `ghcr.io` 的**上行链路超时**，不是层大小或凭据问题。
  - 可行路径 A：在 GitHub Actions 上构建并推送（`.github/workflows/client-release.yml` 已实现，需要先把工作流合入默认分支才可用 `workflow_dispatch`，并配置 `private-release` 受保护环境 + `vars.CLIENT_REDISTRIBUTION_APPROVED=true`）。
  - 可行路径 B：在带宽/代理更稳定的机器上用同一 tag 执行 `docker push`。
  - 未伪造任何"已发布"结论。
- **GHCR 发布已打通（本轮完成）**：本机大层上传受链路限制，改由 GitHub Actions 在**原生 runner** 上构建发布（`release-v*` 标签触发）。过程中用诊断分支定位到真实错误 `denied: permission_denied: write_package` —— 包先前由用户级 PAT 创建、未关联仓库；YG 在包设置中授予仓库访问后，CI 推送成功。
  - 运行 `release-v3.2.16-r8362-r4`：`gate` / `build (amd64)` / `build (arm64)` / `index` 全部 **success**，两架构都在各自原生 runner 通过真实客户端**无账号冒烟**（supervisor health 退出 0）。
  - 索引 digest `sha256:724a9177f96941590b8e420999fd3e9105d1357b6f9f8bdfb8f38000c3b28a36`；amd64 `sha256:43163c5e…`，arm64 `sha256:0a1eca3c…`。
  - 私有性：`visibility=private`、已关联 `gloryhry/feilian-docker`；匿名 token/manifest 均 401。
  - digest 拉取成功，标签核对 `schema=1 kind=official version=3.2.16`。
  - 包内另有早期探针标签 `conn-probe-r1`，可按需删除。
- 管理网关鉴权+TLS 端到端已实跑通过（临时秘密卷，用后删除）：未认证 401、认证后 200、后端仅 Unix socket。
- **L2 隔离验收（进行中）**：`verify/all.sh --suite mock` 已能真实执行并产出结构化报告。当前：`mock.kind` PASS、`mock.waiting_auth` PASS（无可信隧道不进入 READY）、`proxy.before_ready` PASS（未就绪拒绝数据面）、`cleanup.owned_resources` PASS（只清理带 owner 的资源）；`mock.driver` 仍 FAIL 于 `runtime_status_timeout`，但每轮都在前移：
  1. 修掉**生产缺陷**：`dnsmasq --no-daemon` 不会自己写 pid 文件，DNS 属主因此永远判定未激活（`dns_active:false`，resolv 不切换）。改为由 supervisor 作为父进程原子发布 `/run/feilian/dnsmasq.pid`（0600），并补单元测试。修复后容器内实测 `dns_active:true`、`/etc/resolv.conf` 已切到 `nameserver 127.0.0.1`。
  2. 修掉**夹具缺陷**：测试 CA 缺少 `basicConstraints/keyUsage`，OpenSSL 3 拒绝（`CA cert does not include key usage extension`）——生产端严格校验是正确的，夹具补 `-addext` 后 TLS 链路可通。
  3. 容器内直连验证：到 `10.91.0.80:443` 的 TLS 与绑源连接均成功。
  4. 修掉**控制器与 DNS 属主的接口断裂**：task-10 给 `DNSManager.apply` 加了 `vpn_interface/vpn_ifindex` 严格参数，`vpn_state.once()` 仍在用旧签名，于是每次成功探测后都被判 `dns_configuration_failed`。现在探针把 `evidence.interface_ifindex` 作为受控证据发布（含类型边界），`once()` 用它绑定 DNS 上游；同名隧道重建后旧绑定会被拒。修复后容器内实测 `https_status: 200`、`dns_active: true`。
  5. 修掉**数据面 context 形状错误**：`vpn_ipv4` 被套成嵌套数组、还塞了模块不认识的 `vpn_ifindex`，导致 guard 直接拒收（`guard_apply_failed`）。改为按模块真实契约输出；索引改为 supervisor 侧开闸前置条件（`evidence.interface_ifindex` 或实际查询），模块暂不支持索引钉住，已记入待办。
- **L2 当前结果**（`mock17`）：`mock.kind`、`mock.waiting_auth`、`proxy.before_ready`、`mock.real_kernel_tun`（真实内核 TUN + UDP 测试传输）、`fault.interface_down`（断隧道后无代理回落）、`dns.disconnected_no_public_fallback`、`cleanup.owned_resources` 均 **PASS**；`proxy.http/connect/socks5h`、`dns.connected_split` FAIL，`mock.driver` 报 `runtime_status_timeout`。
  - 手动在容器内执行 `egress_policy.py apply` 与 `proxy_config.py prepare` 都返回 `status=READY`，说明两个模块本身可用。
  - 为定位时序，给 supervisor 增加**有界状态迁移追踪**（`runtime.json.transitions`，最多 10 条，只含 ready/plane/state/reason/时间戳，不含敏感信息）。实测（`mock19`）：
    ```
    t0    plane=closed ready=False state=WAITING_AUTH  reason=route_probe_failed
    t+5   plane=closed ready=False state=VALIDATING    reason=success_threshold_pending
    t+10  plane=closed ready=True  state=READY         reason=all_probes_passed
    t+12  plane=ready  ready=True  state=READY         reason=all_probes_passed
    t+20  plane=ready  ready=False state=DISCONNECTED  reason=route_probe_failed
    t+23  plane=closed ready=False state=DISCONNECTED  reason=route_probe_failed
    ```
    即：READY 后约 2 秒打开数据面，约 8 秒后因 `route_probe_failed` 掉到 DISCONNECTED 并撤下 —— 该时间点与套件自身的 `labtun0 down` 故障注入吻合，属于**预期的 fail-closed**；但代理 curl 断言恰好落在这段窗口内失败（三发 `--max-time 6`）。
  - 已核对 guard 规则只匹配 `meta skuid {1001,1002}`，root（dnsmasq 的 VPN DNS 出站、控制面探测）不受影响，因此 DNS 被误封的假设不成立。
  6. 修复**私有可诊断性缺口**：受管进程的 stdout/stderr 原本全部丢到 `/dev/null`，导致“代理没起来”无从判断。现在每个 wrapper 进程写 `/var/log/feilian/<name>.log`（命名卷内，官方客户端日志仍不默认 tail 到 stdout）。
  7. 修复**真实缺陷：privoxy 访问规则顺序**。原渲染把 `deny-access 0.0.0.0/0` 排在 `permit-access` 之前，而 privoxy 是首次匹配生效 —— 等于全部拒绝。现已改为 permit 在前，并加顺序断言。
  8. 修复**“状态 READY 但端口不监听”**：`open_data_plane` 现在启动代理后最多等 15 秒直到两个端口接受 TCP 连接，超时则撤下并记 `proxy_listen_timeout`，绝不提前报 ready。
  9. `scripts/status.sh` 增加 `data_plane` 与 `proxy_usable`（= VPN ready 且数据面 ready），把“能用代理”变成可观测信号。
  10. 套件侧：代理断言改为先等数据面就绪；失败行现在携带 curl/getent 的真实报错（不再只有布尔）。
- **L2 当前结果（`mock24`）**：7 项 PASS（含真实内核 TUN、断隧道 no-fallback、断开时不回落公网 DNS、owned-only 清理）；`proxy.http/connect` 报 `Recv failure: Connection reset by peer`、`proxy.socks5h` 报 `cannot complete SOCKS5 connection (1)`、`dns.connected_split` getent 为空 —— 三者曾指向同一处。
  11. 修复**守卫未放行代理 UID**：`egress_policy.render_policy` 用 `context["proxy_ready"]` 决定是否写放行规则，而 supervisor 的 context 从没提供 `proxy_enabled`，导致生成的守卫**只有两条 drop**（`meta skuid {1001,1002} drop`），代理所有出站（含 127.0.0.1:53 DNS）被一把全拒。现已显式传入 `proxy_enabled`。
  12. 记录一处**取证陷阱**：上述 `nft list` 是在套件结束、数据面已关闭之后看的，当时守卫已被重渲染成 closed 版（只有 drop）。因此“规则缺失”不能由该现场直接推断，需要在数据面开启窗口内取证。
  - dnsmasq 日志显示分域转发**确实生效过**（`using nameserver 10.91.0.53#53 for domain corp.test`），随后随断线故障回退为 `using only locally-known addresses for corp.test`——符合设计。
  13. 实现**企业上游绑定隧道接口**：`dns_manager` 现在渲染 `server=/corp.test/10.91.0.53@labtun0`（公共 bootstrap 上游不绑）。单元测试同步固定“企业上游绑接口、公共上游不绑”的契约。
  14. 套件新增**数据面窗口内取证**（避免再次在关闭后误判）。`mock31` 关键证据：
      ```
      servers-file: server=127.0.0.11 | server=/corp.test/10.91.0.53@labtun0   ← 配置正确
      via-corp-dns: ok(50 bytes)        ← 直连企业 DNS 正常
      tcp-corp-443: ok                  ← 隧道与回程正常
      via-local-resolver: TimeoutError  ← dnsmasq 对 127.0.0.1:53 不回答（12s 超时）
      ```
  - 已排除的假设：dnsmasq 配置错误（文件内容正确）、dnsmasq 因 `@labtun0` 崩溃（单独容器用同一配置启动正常、不退出）、接口未就绪（窗口内接口存在且直连可用）。
  - 已加 `FEILIAN_DNS_DEBUG=1` 时 dnsmasq 的 `--log-queries --log-facility=-`（默认关闭，隐私与日志量考虑）。追踪结果（`mock32`）：
    ```
    dnsmasq[61]: query[A] health.corp.test from 127.0.0.1
    dnsmasq[61]: forwarded health.corp.test to 10.91.0.53
    （重复转发 6 次，没有任何 “reply ... is ...” 行）
    ```
  - 中继侧日志证明**去程到达**：`{"kind":"dns","name":"health.corp.test","source":"10.254.0.1"}` 共 6 条。即丢包发生在**回程**。
  - 已证伪：`bind-interfaces → bind-dynamic` 无效（`mock33`，已回退，不保留无证据改动）；用 `SO_BINDTODEVICE=labtun0` 手工构造的查询**能收到回包**（`via-corp-dns-bound: ok(50 bytes)`），说明设备绑定本身不是原因。
  - 决定不再追这个黑盒，改走**自管转发器**（`runtime/dns_forward.py`，~230 行）：监听 `127.0.0.1:53`，直接消费 DNS 属主已渲染的同一份策略文件（`server=/corp.test/10.91.0.53@labtun0`、`server=/corp.test/` 表示封锁、裸 `server=` 为 bootstrap），按最长后缀匹配、`SO_BINDTODEVICE` 绑定、失败返回 SERVFAIL 而绝不回落公网。所有权校验沿用 `PidReloader`（可配置 exe/参数标记，仍校验 pid+netns+参数）。
  - 期间修掉两个真实缺陷：SIGHUP 曾被当成退出信号（而属主正是用 SIGHUP 重载，导致重启风暴）；转发器早于策略文件启动会直接退出，现改为有界等待。
  - **结果（`mock40`）**：`dns.connected_split` 与 `proxy.socks5h` **由 FAIL 转 PASS**，PASS 数升到 8。
  - **DNS 侧已完全打通**（`mock44`）：`via-local-resolver: ok(50 bytes)`、`via-corp-dns: ok`、`tcp-corp-443: ok`，`dns.connected_split` 与 `proxy.socks5h` 均 PASS。
  - 剩余失败：`proxy.http`（`Connection reset by peer`）与 `proxy.connect`（`Proxy CONNECT aborted`）。已排除的：
    * privoxy 未运行：未退出（无 `privoxy_exited` 记录，日志有启动横幅）；
    * 请求被访问规则拒绝：`permit-access` 已排在 `deny-access` 之前；
    * 到 1080 的连通性：同一 netns 的 `proxy.socks5h` 通过，说明守卫与回环路径对 1080 正常。
  - 新增诊断能力：子进程退出码记入 `transitions` 之外的 `notes`（并折叠重复条目，避免 nginx/websockify 的启动失败把其它信息淹没）；`FEILIAN_PROXY_DEBUG=1` 可打开 privoxy `debug`。当前无 secrets 时 nginx/websockify 会反复退出（预期：管理入口需要认证材料），属已知的噪声源。
  - **根因找到（`mock48`）**：Privoxy 的 ACL 是**最后匹配生效**，且被 `deny-access` 拒绝时它**直接重置连接、不返回 403**。我两轮前把顺序“修”成 `permit` 在前 `deny` 在后，恰好把 loopback 也拒掉了。用最小容器逐条二分验证：`permit-access` 单独可用；`permit` 后接 `deny-access 0.0.0.0/0` → RST；`deny` 在前 `permit` 在后 → 正常返回。已改回 deny 在前、permit 在后，并同步单元断言与注释。
  - **L2 结果（`mock48`）：11 项 PASS**
    ```
    PASS mock.kind / mock.waiting_auth / proxy.before_ready / diag.data_plane_window
    PASS mock.real_kernel_tun
    PASS proxy.http / proxy.connect / proxy.socks5h      ← 三个代理断言全部转绿
    PASS dns.connected_split                             ← 分域 DNS 经隧道解析
    PASS fault.interface_down                            ← 断隧道后无代理回落
    PASS dns.disconnected_no_public_fallback             ← 断开时不回落公网 DNS
    PASS cleanup.owned_resources                         ← 只清理 owned 资源
    FAIL mock.driver -> runtime_status_timeout
    ```
  - 接口恢复超时的根因是**夹具**：`ip link down` 时内核删除了经 tun 的路由，夹具只把 link up 却未恢复路由，于是产品正确地停在 `DISCONNECTED/route_probe_failed`。夹具补回 `ip route replace` 后恢复路径正常。
  - **L2 结果（`mock50`）：14 项 PASS**
    ```
    PASS mock.kind / mock.waiting_auth / proxy.before_ready / mock.real_kernel_tun
    PASS proxy.http / proxy.connect / proxy.socks5h
    PASS dns.connected_split / dns.disconnected_no_public_fallback
    PASS fault.interface_down / fault.route_withdrawn / fault.ipv6_literal
    PASS cleanup.owned_resources / diag.data_plane_window
    FAIL packets.no_plain_corporate_bootstrap      ← 真实失败，待修
    NOT_IMPLEMENTED: gateway.snat / gateway.syn_mss / auth.tls_wss / fault.old_tcp
                     / fault.controller_exit / dns.full_mode / cleanup.foreign_marker
    ```
    未实现的检查**如实标为 NOT_IMPLEMENTED 并计为失败**，没有被放过。
  - 继续修复两处夹具缺陷并补一项真实断言：抓包读取时 tcpdump 会尝试降权（`Couldn't change to 'tcpdump' uid=100`），隔离容器 `--cap-drop ALL` 下失败，改用 `-Z root`；断言原本在**宿主机**上探测 127.0.0.1 而非容器内，导致误判，已改为容器内探测。
  - 新增并通过 `fault.controller_exit`：杀掉 `vpn_state.py` 后，数据面必须在有界时间内关闭、两个代理端口必须停止接受连接（fail-closed）。
  - **L2 当前（`mock57`）：16 项 PASS / 6 项 NOT_IMPLEMENTED**
    ```
    PASS  mock.kind / mock.waiting_auth / proxy.before_ready / mock.real_kernel_tun
    PASS  proxy.http / proxy.connect / proxy.socks5h
    PASS  dns.connected_split / dns.disconnected_no_public_fallback
    PASS  fault.interface_down / fault.route_withdrawn / fault.ipv6_literal
    PASS  fault.controller_exit
    PASS  packets.no_plain_corporate_bootstrap
    PASS  cleanup.owned_resources / diag.data_plane_window
    FAIL(NOT_IMPLEMENTED) gateway.snat / gateway.syn_mss / auth.tls_wss / fault.old_tcp
    ```
  - 新增并通过 `cleanup.foreign_marker`：在 app netns 里造一张**外来** nft 表，执行 `egress_policy.py cleanup` 后断言外来表仍在、自有 `feilian_guard` 已移除 —— 这才让“清理是安全的”成为可验证事实，而不是口号。
  - 新增并通过 `dns.full_mode`：以 `DNS_MODE=full` 重建 app 并重建隧道，断言策略里**唯一默认上游**是 `10.91.0.53@labtun0`、公共 bootstrap 上游完全消失，且一个**非企业域名** `example.test` 确实在企业解析器上出现查询计数（经由 relay 侧日志证实），证明全 DNS 模式真的把所有名字送进隧道解析器。
  - 期间修掉夹具簿记缺陷：重建容器会被重复登记，导致 `cleanup.owned_resources` 误判；以及移除时对“已被探针删掉”的资源报错。现按 (kind,name) 去重，且移除仅在**已校验所有权**后容错执行。
  - **L2 当前（`mock61`）：18 项 PASS / 4 项 NOT_IMPLEMENTED**。剩余：`fault.old_tcp`（旧连接在撤路由后不得重路由）→ `auth.tls_wss`（秘密卷 + TLS/WebSocket 端到端）→ `gateway.snat` / `gateway.syn_mss`（网关 SNAT 与 SYN MSS 实测）。
  - 修复两处阻断验收的真实缺陷：(1) 探针镜像构建沿用统一 `BUILD_NETWORK`（本机默认网络 DNS 被透明代理打断）；(2) 隔离容器 `--cap-drop ALL` 失去 `DAC_OVERRIDE` 后读不了属主不同的 0600 测试证书，仅对一次性测试 TLS 材料放宽为 0644（每轮独立隔离网络内的临时材料）。
- **仍未执行**：L2 其余包级断言（代理经测试 TUN、guard 阻断、DNS 分域切换、网关 SNAT/MSS 真实包）、`scripts/deploy.sh` 的 digest 升级/回滚演练、README 重写。
- Git 作者身份已配置；非交互 git push --dry-run 预检 exit 0，远端可接受目标功能分支。未实际推送。GitHub CLI 不存在，不因此安装系统工具。
- 旧 README 实测不自动当作新代码验收证据。

### L2 剩余门禁的尝试记录（避免重复踩坑）

- `auth.tls_wss` 尝试两版后**回退**（不留半成品）：
  1. 直接在容器内跑 `secrets_volume.py ensure` 生成秘密 → 网关拒绝启动（`secrets volume incomplete`）：helper 直调生成的 `web.htpasswd` 组属主不是 `www-data`，与 `web_gateway.py` 的严格校验不符。
  2. 改用宿主侧 `scripts/secrets-cli.py ensure`（它负责正确属主）→ 命令返回成功，但实验室卷 `<run>-secrets` **仍为空**，容器因此进入 "secrets volume incomplete" 分支，nginx 未监听 6080。
  - **根因已查明**：`scripts/secrets-cli.py ensure` **拒绝接管不是自己创建的卷**（正确的所有权行为）。实验室先建了同名卷，CLI 因而失败、卷保持为空。手工验证：CLI 自己建卷时 `web.htpasswd`/`tls.*`/`vnc.pass`/`access.json` 全部正确写入，属主 `root:www-data`、目录 0750、htpasswd 0640（此前判定"缺失"是我 `head -8` 截断所致）。
  - **第二个耦合点也找到了**：`app()` 以命名卷挂载 `/run/feilian-secrets`，Docker 会**自动创建空卷**，于是 CLI 又拒绝接管。正确顺序：先删 app 容器 → 删空卷 → 让 CLI 建卷 → 再重建 app。
  - 修正后 `auth.tls_wss` **通过**（`mock70`）：未认证 **401**、认证后 **200**、`/websockify` 升级 **101**，全部在真实 TLS + Basic Auth 下验证。
  - 至此 **L2：19 项 PASS / 3 项 NOT_IMPLEMENTED**（`gateway.snat`、`gateway.syn_mss`、`fault.old_tcp`）。
  - 该路径在**手工验证**中曾通过（临时项目 `fl-e2e`：未认证 401、认证后 200、后端仅 Unix socket），但手工验证不算 L2，不计入验收。

## 外部门禁

- Git作者身份、GitHub独立分支非交互push --dry-run已通过；尚未实际推送，GHCR/Actions权限与保护环境仍待验证；不在对话或日志中索取/打印token。
- GHCR 包必须 private，发布前需客户端再分发/组织策略批准；不能以公开仓库代码可见性替代包私有性验证。
- ARM64 原生 runner/已授权模拟资源尚未验证；不能把 index 存在当作 ARM 实测。
- 无企业账号/内网测试目标；真实登录、MFA、DNS schema/准入兼容、物理 macvlan/WiFi 单列待人工验收，不虚报完成。

## 回滚约束

保留已有基线镜像/命名卷；每阶段通过后提交。清理仅针对带明确 owner 且仍匹配记录的资源；不使用全局 flush、down -v 或前缀批量删除，不覆盖第三方并发变更。
