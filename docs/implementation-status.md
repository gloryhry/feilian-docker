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
| G6 CI/回滚 | IN_PROGRESS | check/client-release 工作流已落并通过 YAML 校验；未在远端运行。 |
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
- **L2 隔离验收（进行中）**：`verify/all.sh --suite mock` 已能真实执行并产出结构化报告。当前：`mock.kind` PASS、`mock.waiting_auth` PASS（无可信隧道不进入 READY）、`proxy.before_ready` PASS（未就绪拒绝数据面）、`cleanup.owned_resources` PASS（只清理带 owner 的资源）；`mock.driver` FAIL 于 `runtime_status_timeout`（应用容器未在时限内产出 status.json），下一轮继续定位。
  - 修复两处阻断验收的真实缺陷：(1) 探针镜像构建沿用统一 `BUILD_NETWORK`（本机默认网络 DNS 被透明代理打断）；(2) 隔离容器 `--cap-drop ALL` 失去 `DAC_OVERRIDE` 后读不了属主不同的 0600 测试证书，仅对一次性测试 TLS 材料放宽为 0644（每轮独立隔离网络内的临时材料）。
- **仍未执行**：L2 其余包级断言（代理经测试 TUN、guard 阻断、DNS 分域切换、网关 SNAT/MSS 真实包）、`scripts/deploy.sh` 的 digest 升级/回滚演练、README 重写。
- Git 作者身份已配置；非交互 git push --dry-run 预检 exit 0，远端可接受目标功能分支。未实际推送。GitHub CLI 不存在，不因此安装系统工具。
- 旧 README 实测不自动当作新代码验收证据。

## 外部门禁

- Git作者身份、GitHub独立分支非交互push --dry-run已通过；尚未实际推送，GHCR/Actions权限与保护环境仍待验证；不在对话或日志中索取/打印token。
- GHCR 包必须 private，发布前需客户端再分发/组织策略批准；不能以公开仓库代码可见性替代包私有性验证。
- ARM64 原生 runner/已授权模拟资源尚未验证；不能把 index 存在当作 ARM 实测。
- 无企业账号/内网测试目标；真实登录、MFA、DNS schema/准入兼容、物理 macvlan/WiFi 单列待人工验收，不虚报完成。

## 回滚约束

保留已有基线镜像/命名卷；每阶段通过后提交。清理仅针对带明确 owner 且仍匹配记录的资源；不使用全局 flush、down -v 或前缀批量删除，不覆盖第三方并发变更。
