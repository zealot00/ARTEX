<div align="center">

# ARTEX

AI 自主渗透测试与企业内网横向防御演练平台（Go 后端 + Next.js 前端）

[English README](README.md) · **中文 README** · [中文使用手册](docs/USER_MANUAL_zh.md) · [更新日志](CHANGELOG.md)

基于 Autumn-27 开源版本独立维护演进的企业内网增强分支 · AGPL-3.0

</div>

---

## 定位与安全声明

本分支聚焦**企业内部授权业务渗透测试、常态化横向防御演练与等保 2.0 合规闭环**，在不依赖高风险/高成本外部红队及过度恶意武器化的前提下，提供工程级的边界控制与可审计验证能力：

- **本地源码构建**：[docker-compose.yml](docker-compose.yml) 默认从当前仓库源码本地构建（`image: artex:local`），不拉取任何第三方 Docker Hub 预构建镜像，避免外部镜像供应链投毒风险。
- **最小暴露面**：默认仅绑定 `127.0.0.1:8787`（Web UI / API / SSE / OOB 回调）与 `127.0.0.1:8788`（录包代理）。
- **严格护栏**：内置电子围栏（`guard/fence.go`）、立足点门控（`lateral_gate`）、生产安全模式（`prod_safe_mode`）与 LLM 出站白名单。

---

## 核心能力一览

- **多智能体探索与双图架构**：Planner + 并行 Worker + MainAgent 协同，维护探索图（Exploration Graph）与资产覆盖图（Asset Graph），配合 S1 机器校验型漏洞验证、HTTP 录包证据绑定（`traffic_refs`）及独立复测 Agent（`Retester`）。
- **PoC 选择、内网 OOB 盲打与二次利用**：
  - 镜像预置离线 `nuclei-templates`（`/opt/nuclei-templates`），支持纯断网内网开箱扫描。
  - 提供企业私有 PoC 仓库（`GET/POST/DELETE /api/pocs`），支持 `nuclei_yaml` 与 `python_script`，通过 `search_pocs` 与 `run_poc` 受控检索与执行。
  - 内置轻量级内网 OOB 回调接收器（`/oob/{token}`、`oob_create_token`、`oob_poll_hits`），无需公网 `interactsh` 即可验证 Blind SSRF / XXE / RCE。
  - 保留非破坏性二次利用能力（[skills/poc-verify-exploit](skills/poc-verify-exploit/SKILL.md)）：立足点确认、凭据沉淀至 `task_credentials`、配合持久化深度会话衔接验证。
- **加密且模型盲态的字典保险库**：通过 `/system/settings` 或 Admin API（`/api/wordlists`）上传字典，使用 AES-256-GCM 加密存储于 `<keyDir>/wordlists/`（不进入 PostgreSQL、工作区及 LLM 上下文），支持 `run_credential_audit`（`hydra`）与防锁定低频密码喷洒 `run_password_spray`（`nxc`，单轮上限 1–3 个密码）。
- **持久化深度会话与多跳穿透**：通过 `depth_session_open` / `exec` / `list` / `close` 管理任务级 `pty`、`ssh`（支持 `jump_session_id` 多跳级联、内置 `127.0.0.1` SOCKS5 代理与服务端凭据解析）和 `tunnel` 进程，任务结束或删除时自动清理。
- **资产驱动攻击面矩阵与灰盒/白盒深度联动**：
  - **资产驱动挖掘矩阵（`plan_asset_hunt`）**：服务端实时分析任务已登记的 `http_service`、`endpoint`、`other_service` / `ip` 与 Intent 覆盖状态，按参数语义（IDOR、SSRF、并发竞态、文件/模板、注入）与开源指纹（内置 25 类常见开源系统仓库映射）生成未覆盖高优挖掘清单并注入每一轮 Planner。
  - **前端 JS / OpenAPI 契约自动提取（`extract_web_contracts`）**：自动拉取目标站点 Swagger/OpenAPI（`/v3/api-docs`、`/swagger.json` 等）与同源 `.js` Bundle，提取隐藏接口与参数并自动回写任务资产图谱。
  - **开源组件源码获取与语义级代码审计（`oss_fetch_source` + `code_scan_semgrep`）**：识别到开源组件或提供 `.zip`/`.jar`/`.war` 制品后，按版本号受控拉取/解压至任务审计目录 `<task_dir>/oss-src/<component>`，联动 Semgrep 与原生多语言汇点/路由鉴权缺失扫描器（`code_map_entrypoints`、`code_scan_sinks`、`code_audit_auth_gaps`、`code_trace_symbol`、`code_read_context`、`code_audit_deps`），再回连在线资产进行动态灰盒验证。
- **高强度业务逻辑与代理鉴权增强**：内置基于录制流量的批量跨角色鉴权核查工具 `traffic_fuzz_audit`、双账号/无账号越权对比工具 `authz_replay`、同步并发条件竞争探测工具 `race_probe`（`prod_safe_mode` 下限流 5 并发）、[skills/biz-logic-audit](skills/biz-logic-audit/SKILL.md) 逻辑跳步/敏感字段泄漏审计剧本，以及按 Host 严格隔离的代理鉴权头自动注入（`/api/tasks/{id}/proxy-headers`）。
- **任务外联审计与报告自证**：自动记录任务执行期间的外部网络外联（`task_outbound_logs`、`GET /api/tasks/{id}/outbound`），并自动写入标准渗透报告与等保 2.0 报告，便于上层流量监控溯源核查。
- **电子围栏与立足点门控**：支持 CIDR / IP / 域名 / 通配符 / URL 前缀 Fail-Closed 拦截（含 `30x` 跳转校验），以及 `wait_for_task_id` 零消耗休眠挂起、`POST /api/tasks/{id}/lateral/approve` 原地审批恢复横向移动。
- **等保 2.0 合规检查矩阵**：内置 12 域 `task_checks`（含 `AD-DIR`、`WIN-SVC`），支持阳性漏洞与阴性“已通过”证据记录及 Markdown 报告导出（`GET /api/tasks/{id}/report/mlps`）。
- **工单 API 与 100% 中英双语 UI**：支持 Scoped Machine Key（`artex_ak_`）、`Idempotency-Key` 幂等任务创建与聚合轮询；Web 控制台支持 `zh-CN` / `en` 一键切换，并在 `/system/settings` 与 `/function/tasks/detail`（`Depth & Fence` 标签页）提供可视化管理。

---

## 快速安装

> 运行依赖 **PostgreSQL** 数据库与 **LLM**（支持 Anthropic / OpenAI / OpenAI-Responses / 本地 Ollama）。

### 方式一：Docker Compose 本地构建（推荐）

```bash
git clone https://github.com/zealot00/ARTEX.git
cd ARTEX
cp .env.example .env          # 设置 POSTGRES_PASSWORD，按需配置 LLM Key 或内网变量
docker compose up -d --build  # 基于本地源码构建 artex:local 并启动 postgres
```

启动后访问 `http://127.0.0.1:8787`。首次进入 `/setup` 页面时，需从启动日志获取一次性初始化令牌：

```bash
docker compose logs artex | grep "Setup token"
```

### 方式二：源码编译单二进制

```bash
# 1) 前端静态导出
cd web && npm ci && npm run build:static && cd ..
# 2) 复制到 Go embed 目录
cp -r web/out server/webui/dist
# 3) 编译并启动（需携带 -tags embedui）
CGO_ENABLED=0 go build -tags embedui -o artex ./cmd/artex
./start.sh
```

---

## 关键环境变量与配置

| 变量名 | 说明 | 默认值 / 示例 |
| :--- | :--- | :--- |
| `ARTEX_PG_DSN` | PostgreSQL 连接串（也可在 `config.json` 中配置） | `postgres://artex:pass@postgres:5432/artex?sslmode=disable` |
| `ARTEX_BIND_ADDR` | Docker 端口绑定宿主机地址 | `127.0.0.1`（跨机访问需改配并配合反代/HTTPS） |
| `ARTEX_LLM_HOST_ALLOWLIST` | LLM 出站域名/CIDR 白名单（防提示注入或配置漂移外泄） | `127.0.0.1:11434,.internal.corp,10.0.0.0/8` |
| `ARTEX_LLM_REQUIRE_BASE_URL` | 设为 `1` 时强制要求显式填写 `base_url` | 空（关闭） |
| `ARTEX_LLM_DISABLE_ENV_FALLBACK` | 设为 `1` 时禁止回退读取进程环境中的公网 API Key | 空（关闭） |
| `ARTEX_DISABLE_WEB_SEARCH` | 设为 `1` 时强制禁用出站 `web_search` | 空（关闭） |
| `ARTEX_NUCLEI_TEMPLATES_DIR` | 离线 `nuclei-templates` 目录路径 | `/opt/nuclei-templates` |
| `ARTEX_OOB_BASE_URL` | 供目标主机回连的内网 OOB 基准地址 | `http://10.10.0.5:8787` |
| `ARTEX_TRUSTED_PROXIES` | 反向代理可信来源 CIDR（用于登录限流识别真实客户端 IP） | `172.17.0.1/32` |

---

## 内网渗透与横向防御能力地图

| 能力域 | ARTEX 核心实现与工具链 | 就绪度 | 说明与边界 |
| :--- | :--- | :--- | :--- |
| **资产测绘与侦察** | `bbot`、`subfinder`、`httpx`、`nmap`、`katana`、`playwright`、ScopeSentry 同步 | **生产可用** | 双图探索 + 资产覆盖追踪 |
| **Web / API / 中间件 & PoC** | `nuclei` + 离线模板（`/opt/nuclei-templates`）、私有 PoC 库（`search_pocs` / `run_poc`）、内网 OOB（`oob_create_token` / `oob_poll_hits`）、`ffuf`、`dalfox`、`sqlmap`、`sslscan`、`skills/poc-verify-exploit` | **生产可用** | 支持断网离线扫描、内网盲打验证及围栏保护下的二次利用 |
| **认证审计与加密字典库** | AES-256-GCM 加密库（`wordlists/vault.go`）、`list_wordlists`、`run_credential_audit`（`hydra`）、`run_password_spray`（`nxc`） | **生产可用** | 明文不入库、不进模型；喷洒单轮 1–3 密码防锁定 |
| **AD / Windows 横向审计** | `impacket`、`netexec`（`nxc`）、`bloodhound-python`、`certipy-ad`、`adidnsdump`、`ldap-utils`、`krb5-user`、`smbclient` | **就绪（Linux 远程协议栈）** | 覆盖 SMB/WinRM/LDAP/Kerberos/ADCS；不含 Windows 原生 C2/免杀编译链 |
| **云原生与主机提权审计** | `kubectl`、`skills/cloud-k8s-audit`、`skills/host-privesc-audit` | **就绪（API/RBAC/Linux）** | 覆盖 K8s RBAC/Pod 逃逸面与 Linux 主机提权排查 |
| **穿透与持久化会话** | `sessions/manager.go`、`depth_session_open`/`exec`/`list`/`close`、SSH SOCKS5 + `jump_session_id` 多跳级联、`chisel`、`proxychains4`、`socat` | **生产可用** | 任务级生命周期绑定，结束/删除自动清理 |
| **越界与生产安全护栏** | 电子围栏（`guard/fence.go`）、`lateral_gate`、`prod_safe_mode`、LLM 白名单、Scoped API Key（`artex_ak_`） | **生产可用** | 对 CIDR/域名/URL/`30x` 重定向 Fail-Closed 阻断 |
| **等保 2.0 合规报告** | 12 域 `task_checks`（`AD-DIR`、`WIN-SVC` 等）、阴性“已通过”证据、`GET /api/tasks/{id}/report/mlps` | **生产可用** | 阳性漏洞与阴性合规证据统一导出 |
| **Web UI 与双语运维** | `/system/settings`（加密字典）、`/function/tasks/detail`（`Depth & Fence`）、`zh-CN` / `en` 双语（`web/src/lib/i18n/`） | **生产可用** | 纯静态导出（`NEXT_EXPORT=1`）兼容，100% 页面覆盖 |

---

## 延伸阅读

- [详细中文使用手册（部署、控制台、PoC/OOB、等保与 API 集成）](docs/USER_MANUAL_zh.md)
- [English README](README.md)
- [CHANGELOG 更新日志](CHANGELOG.md)
