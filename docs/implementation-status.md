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
| G1 锁定下载/Buildx | IN_PROGRESS | 双架构官方包锁定和24项artifact测试通过；Buildx代码待整合验收。 |
| G2 管理/秘密/生命周期 | IN_PROGRESS | 秘密/Web模块并行开发，接口帮助探测已完成，未做功能验收。 |
| G3 DNS/状态/就绪 | IN_PROGRESS | 控制器/DNS模块已落草稿，单元和整合验收待执行。 |
| G4 双代理/guard | PENDING | 未实施。 |
| G5 网关/MSS/清理 | PENDING | 未实施。 |
| G6 CI/回滚 | PENDING | 未实施。 |
| G7 集成/GitHub/GHCR | PENDING | 未实施、未推送、未发布。 |

## 执行记录

### 启动轮

- 只读核对 cwd、git status、分支和基线提交；结果工作树干净。
- 创建独立分支成功；未停止/重建容器、未修改宿主网络。
- 并行任务：config-contract 仅负责统一配置及专属单元测试；artifact-lock 仅负责锁定下载与专属单元测试；Lead 负责共享入口、网络资源工具、Compose 和整合。
- Lead已独立整合运行 `PYTHONPATH=tests/unit python3 -m unittest -v test_config test_network_resources test_lifecycle test_compose test_artifacts`：99项全部PASS（8.096s），其中G0为75项、artifact为24项；七个脚本bash -n、git diff --check均PASS。单元用命令桩，Compose只做JSON渲染。
- 通过边界包含配置优先级/注入拒绝/无partial export、host显式授权与非法功能拒绝、bridge失败不删除服务/不升级host、owned-only清理、UFW关闭时持久规则回收、IPv6管理回环长端口语法。
- Lead已read完整artifact实现并独立validate锁、fetch --arch all --offline复核两架构cache，全部通过；原amd64基线包保留。来源为官方HTTPS字节审阅固定摘要，不是厂商签名验证。
- 为确认G2接口，实际运行了四个一次性network-none/cap-drop ALL的基线帮助/假密码进程，均已自动删除：websockify帮助、xmessage存在性、Unix listener语法（2秒预期超时）、x11vnc stdin生成8字节测试密码文件。未运行官方客户端/GUI、未挂宿主目录、未建立对外网络。Unix后端无需source端口，支持--unix-listen和0660模式。
- Git 作者身份已配置；非交互 git push --dry-run 预检 exit 0，远端可接受目标功能分支。未实际推送。GitHub CLI 不存在，不因此安装系统工具。
- 旧 README 实测不自动当作新代码验收证据。

## 外部门禁

- Git作者身份、GitHub独立分支非交互push --dry-run已通过；尚未实际推送，GHCR/Actions权限与保护环境仍待验证；不在对话或日志中索取/打印token。
- GHCR 包必须 private，发布前需客户端再分发/组织策略批准；不能以公开仓库代码可见性替代包私有性验证。
- ARM64 原生 runner/已授权模拟资源尚未验证；不能把 index 存在当作 ARM 实测。
- 无企业账号/内网测试目标；真实登录、MFA、DNS schema/准入兼容、物理 macvlan/WiFi 单列待人工验收，不虚报完成。

## 回滚约束

保留已有基线镜像/命名卷；每阶段通过后提交。清理仅针对带明确 owner 且仍匹配记录的资源；不使用全局 flush、down -v 或前缀批量删除，不覆盖第三方并发变更。
