# ARTEX 中文使用手册

本手册面向企业内网安全工程师、渗透测试人员及平台运维人员，说明如何部署、配置并使用 ARTEX 开展授权内网业务渗透测试、横向防御演练与等保 2.0 合规评估。

---

## 目录

1. [部署、初始化与安全基线](#1-部署初始化与安全基线)
2. [Web 控制台基础与双语切换](#2-web-控制台基础与双语切换)
3. [LLM 接入与内网出站隔离](#3-llm-接入与内网出站隔离)
4. [加密字典库管理与防锁定口令审计](#4-加密字典库管理与防锁定口令审计)
5. [PoC 选择、内网 OOB 盲打与二次利用实战](#5-poc-选择内网-oob-盲打与二次利用实战)
6. [电子围栏、立足点门控与持久化深度会话](#6-电子围栏立足点门控与持久化深度会话)
7. [等保 2.0 合规检查矩阵与报告导出](#7-等保-20-合规检查矩阵与报告导出)
8. [外部工单系统 / Agent API 集成](#8-外部工单系统--agent-api-集成)
9. [日常备份、升级与故障排查](#9-日常备份升级与故障排查)

---

## 1. 部署、初始化与安全基线

### 1.1 Docker Compose 部署（推荐）

```bash
git clone https://github.com/zealot00/ARTEX.git
cd ARTEX
cp .env.example .env
```

在 `.env` 中至少配置数据库密码，按需补充内网变量：

```dotenv
POSTGRES_PASSWORD=请替换为强密码
ARTEX_BIND_ADDR=127.0.0.1
# 若目标主机需要从内网回连 ARTEX 的 OOB 回调端点，请填写内网可达地址：
ARTEX_OOB_BASE_URL=http://10.10.0.5:8787
# 若在纯内网强制限制 LLM 只允许访问本地 Ollama 或企业内部网关：
ARTEX_LLM_HOST_ALLOWLIST=127.0.0.1:11434,.internal.corp,10.0.0.0/8
ARTEX_LLM_REQUIRE_BASE_URL=1
ARTEX_DISABLE_WEB_SEARCH=1
```

构建并启动：

```bash
docker compose up -d --build
```

> **安全基线提醒**：`docker-compose.yml` 已固定采用本地源码构建（`image: artex:local`），切勿手动替换为外部第三方 Docker Hub 预构建镜像。

### 1.2 首次访问与管理员密码初始化

1. 浏览器访问 `http://127.0.0.1:8787`（若通过 Nginx 反代暴露 HTTPS，请确保关闭 `proxy_buffering` 以支持 SSE 实时流，详见 [README_zh.md](README_zh.md) 与 [README.md](../README.md#L272-L307)）。
2. 首次访问会自动跳转 `/setup`，需要填写一次性 **Setup Token**（从日志获取）：
   ```bash
   docker compose logs artex | grep "Setup token"
   ```
3. 默认管理员用户名为 `ARTEX`，密码长度要求至少 12 个字符（不超过 72 字节）。

---

## 2. Web 控制台基础与双语切换

- **中英双语切换**：顶部导航栏右侧提供 `zh-CN` / `en` 语言切换开关，切换后实时生效并持久化到本地浏览器存储（覆盖全部 77 个前端模块，支持纯静态导出部署）。
- **核心功能入口**：
  - **仪表盘与任务列表**（`/function/tasks`）：创建任务、查看资产覆盖、启停或删除任务。
  - **任务详情页**（`/function/tasks/detail`）：查看执行会话、探索图（Exploration Graph）、漏洞发现（Findings）、资产图（Assets）、录制流量（Traffic）、人工对话（Chat）以及 **`Depth & Fence`（深度控制与围栏）** 标签页。
  - **系统设置**（`/system/settings`）：配置并发数、**加密字典库（Encrypted Wordlists）**、API Keys、通知与审批策略。

---

## 3. LLM 接入与内网出站隔离

1. 在左侧菜单 **LLM 配置** 页面添加模型配置（支持 Anthropic、OpenAI、OpenAI-Responses 及内网无密钥 **Ollama**，Ollama 默认地址为 `http://127.0.0.1:11434/v1`）。
2. **格式差异提醒**：
   - Anthropic 格式的 Base URL **不要带** `/v1` 后缀（如 `https://api.anthropic.com`）。
   - OpenAI / Ollama 格式的 Base URL **需要带** `/v1` 后缀（如 `http://127.0.0.1:11434/v1`）。
3. **企业内网加固**：
   - 配置 `ARTEX_LLM_HOST_ALLOWLIST` 后，系统会拦截任何指向未授权域名的 LLM 配置或探测请求，并拒绝 HTTP `30x` 重定向，防止内网资产信息和源码外泄至公网。
   - 若无需模型自动回退到环境变量密钥，设置 `ARTEX_LLM_DISABLE_ENV_FALLBACK=1`。

---

## 4. 加密字典库管理与防锁定口令审计

为了避免内网密码字典进入 PostgreSQL、任务工作区或大模型的上下文窗口，ARTEX 实现了**模型盲态的加密字典库**：

1. **上传字典**（仅 Admin JWT 权限，在 `/system/settings` 的 **Encrypted Wordlists** 卡片或调用 `POST /api/wordlists`）：
   - 支持三种类型：`username`（用户名表）、`password`（密码表）、`userpass`（`user:pass` 组合表）。
   - 明文在服务端标准化去重后，使用 AES-256-GCM 加密写入 `<keyDir>/wordlists/`（与 `jwt.key` 同级目录，文件管理器不可浏览）。
2. **Agent 调用方式**：
   - Agent 调用 `list_wordlists` 仅能看到 `id`、`name`、`kind`、`entry_count`、`sha256` 元数据，无法读取字典明文。
   - 针对 SSH/MySQL/PostgreSQL/Redis/FTP/HTTP 等服务认证审计，Agent 调用 `run_credential_audit`（底层驱动 `hydra`，受电子围栏与 `prod_safe_mode` 并发限制）。
   - 针对内网 AD / SMB / WinRM / LDAP，Agent 调用 `run_password_spray`（底层驱动 `nxc`），**单次最多喷洒 3 个密码（`prod_safe_mode` 下自动收紧至 1 个）** 并强制轮间延迟，最大限度降低域账号锁定风险；匹配成功的口令在返回给模型的 JSON 中自动脱敏。

---

## 5. PoC 选择、内网 OOB 盲打与二次利用实战

### 5.1 离线 `nuclei-templates` 与企业私有 PoC 库

- **离线模板**：Docker 镜像已在 `/opt/nuclei-templates` 预置固定版本的官方 `nuclei-templates`（可通过 `ARTEX_NUCLEI_TEMPLATES_DIR` 指定自定义挂载目录），断网内网可直接使用。
- **上传企业私有 PoC**（仅 Admin JWT 权限，通过 `POST /api/pocs`）：
  ```bash
  curl -X POST http://127.0.0.1:8787/api/pocs \
    -H "Authorization: Bearer <ADMIN_JWT>" \
    -H "Content-Type: application/json" \
    -d '{
      "name": "internal-oa-rce-2025",
      "kind": "nuclei_yaml",
      "severity": "critical",
      "cve": "INTERNAL-2025-001",
      "tags": "oa,rce,intranet",
      "description": "内部 OA 接口命令执行验证模板",
      "exploit_guidance": "确认触发后仅读取 id 与 /etc/hostname 证明权限边界，勿写入持久文件",
      "content": "id: internal-oa-rce-2025\ninfo:\n  name: Internal OA RCE\n  severity: critical\nhttp:\n  - method: GET\n    path:\n      - \"{{BaseURL}}/api/ping?host=127.0.0.1\"\n    matchers:\n      - type: status\n        status: [200]"
    }'
  ```
  `kind` 支持 `nuclei_yaml` 与 `python_script`。查询与删除接口为 `GET /api/pocs` 和 `DELETE /api/pocs/{id}`。

### 5.2 内网 OOB 盲打验证（无需公网 `interactsh`）

1. 确保 `.env` 中 `ARTEX_OOB_BASE_URL` 设置为目标内网可访问的 ARTEX 地址（如 `http://10.10.0.5:8787`）。
2. Agent 在探测 Blind SSRF / XXE / Blind RCE / Fastjson 时：
   - 调用 `oob_create_token(task_id, label)` 获取唯一回调路径 `/oob/<token>` 及完整 URL。
   - 调用 `run_poc`（传入 `oob_token` 参数，Python PoC 可直接读取环境变量 `ARTEX_OOB_URL` / `ARTEX_OOB_TOKEN`）或在定制探测请求中嵌入该 URL。
   - 调用 `oob_poll_hits(task_id, token, wait_seconds=5)` 轮询目标是否发起回连，获得来源 IP、请求方法、路径与 Body 摘要作为机器确认证据。
3. 运维人员也可通过 `GET /api/tasks/{id}/oob` 查看当前任务分配的 OOB 令牌及命中计数。

### 5.3 保留非破坏性二次利用

验证 PoC 命中后，Agent 遵循 [skills/poc-verify-exploit/SKILL.md](../skills/poc-verify-exploit/SKILL.md) 保留合理二次利用能力：
1. 根据 `run_poc` 返回的 `exploit_guidance` 或漏洞类型，获取**非破坏性实锤证明**（如当前进程权限 `id`、主机标识、数据库表结构边界、只读配置验证）。
2. 将发现的 SSH/DB/服务口令沉淀到任务凭据库 `task_credentials`。
3. 必要时调用 `depth_session_open` 建立持久化 `pty`/`ssh` 会话或 SOCKS5 隧道；如开启了 `lateral_gate`，系统会在立足点确认后自动暂停，等待人工审批后继续横向验证。
4. 最终通过 `traffic_search` -> `traffic_get` 核对真实录包并绑定 `traffic_refs` 提交漏洞报告，严禁凭版本猜测直接上报。

---

## 6. 电子围栏、立足点门控与持久化深度会话

可在创建任务时通过 API 开启，也可在任务运行中打开 `/function/tasks/detail` -> **`Depth & Fence`** 标签页可视化管理：

1. **电子围栏（Electronic Fence）**：
   - 配置 `fence_enabled: true` 及 `fence_rules`（支持 CIDR 如 `10.10.0.0/16`、单 IP、域名 `*.corp.local`、URL 前缀 `https://portal.corp.local:8443`）。
   - Planner、Worker、MainAgent 的所有工具调用（含 `run_poc`、`run_credential_audit`、`run_password_spray`、`depth_session_open` 以及 `WebFetch` 的 `30x` 跳转）均受 Fail-Closed 校验，越界即阻断。
2. **立足点门控（Lateral Gate）与零消耗挂起**：
   - 开启 `lateral_gate: true` 后，Guard 会拦截跳板/隧道工具（`proxychains4`、`socat`、`chisel`、`ssh -D/-L/-R`、`impacket-*` 等），并在发现立足点时暂停任务，直到运维在 UI 点击审批或调用 `POST /api/tasks/{id}/lateral/approve` 原地恢复。
   - 若通过 `wait_for_task_id` 创建待命横向任务，该任务会保持 `paused` 状态且**不消耗 LLM 额度与并发槽位**，直到上游任务确认符合 `foothold_vuln_classes` 的立足点漏洞。
3. **持久化深度会话（Depth Sessions）**：
   - 支持 `pty`、`ssh`（可传 `credential_id` 自动解析凭据、`jump_session_id` 多跳级联、`socks_port` 拉起本地 `127.0.0.1` SOCKS5 代理）和 `tunnel`。
   - 在 `Depth & Fence` 标签页可实时查看所有存活会话并随时一键终止；任务结束或删除时后端也会自动回收全部会话进程。

---

## 7. 等保 2.0 合规检查矩阵与报告导出

创建任务时传入 `compliance_profile: "mlps"` 与 `prod_safe_mode: true`：

- 系统自动初始化 12 个等保渗透检查域（含 `AD-DIR` 域目录服务与 `WIN-SVC` Windows/SMB/打印服务）。
- `prod_safe_mode` 自动拦截 DoS/压测工具、破坏性 SQL 及高并发爆破参数，并将 `nuclei` 限制在低速率模式（`-rl 10 -c 5`）。
- Agent 与安全人员均可记录阳性漏洞及阴性“已通过（`passed`）”验证证据（`record_check_result` / `PUT /api/tasks/{id}/checks/{code}`）。
- 完成后通过 `GET /api/tasks/{id}/report/mlps` 导出完整的等保 2.0 Markdown 合规报告。

---

## 8. 外部工单系统 / Agent API 集成

1. **签发 Scoped API Key**：在管理界面或通过 Admin JWT 调用 `POST /api/api-keys` 签发 `artex_ak_...` 密钥，按需勾选权限范围（`tasks:create`、`tasks:read`、`tasks:control`、`findings:read`、`chat:write`、`intercept:decide`）。Machine Key 无法访问系统设置、LLM 配置、字典管理与 PoC 管理接口。
2. **幂等下发与聚合轮询**：

```bash
# 1) 幂等创建带电子围栏与立足点门控的等保内网测试任务
curl -X POST http://127.0.0.1:8787/api/tasks \
  -H "X-API-Key: artex_ak_..." \
  -H "Idempotency-Key: mlps-2026-internal-01" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Core-Biz-MLPS",
    "external_ref": "SEC-2026-01",
    "description": "核心业务系统与内网域控边界测试",
    "goal": "在授权边界内完成等保 2.0 12 域测试并验证关键立足点",
    "compliance_profile": "mlps",
    "prod_safe_mode": true,
    "lateral_gate": true,
    "fence_enabled": true,
    "fence_rules": ["10.10.0.0/16", "*.corp.local", "https://portal.corp.local:8443"]
  }'

# 2) 聚合轮询任务状态与待审批项
curl -H "X-API-Key: artex_ak_..." http://127.0.0.1:8787/api/tasks/1/workorder

# 3) 立足点确认后原地放行横向移动并导出报告
curl -X POST -H "X-API-Key: artex_ak_..." http://127.0.0.1:8787/api/tasks/1/lateral/approve
curl -H "X-API-Key: artex_ak_..." http://127.0.0.1:8787/api/tasks/1/report/mlps
```

---

## 9. 日常备份、升级与故障排查

### 9.1 备份重点目录
- `./keys/`：包含 `jwt.key` 与加密字典保险库 `./keys/wordlists/`，**丢失将导致已加密字典无法解密**，请与 PostgreSQL 数据库一并定期备份。
- `./data/`：任务工作区与附件数据。
- `./skills/`：自定义 Skill 目录。

### 9.2 常见问题排查
- **离线环境下 `search_pocs` 未返回模板**：确认容器内 `/opt/nuclei-templates` 是否存在，或是否通过 `ARTEX_NUCLEI_TEMPLATES_DIR` 挂载了宿主机模板目录。
- **OOB 盲打收不到回连**：确认 `.env` 中 `ARTEX_OOB_BASE_URL` 配置为目标网段可路由的宿主机 IP:端口（同时注意 `ARTEX_BIND_ADDR` 不能仅监听 `127.0.0.1`，或需经内网反向代理将 `/oob/` 转发至 ARTEX 8787 端口）。
- **页面活动流一直转圈**：检查 Nginx 等反向代理是否关闭了 `proxy_buffering off;` 及 `proxy_cache off;`。
