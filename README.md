# Manage Your Node

本地 Web 面板：录入 VPS、部署并管理 3x-ui 节点、发放客户端/订阅，以及把多台机器编排成链式代理。

面向自用 / 小规模运维。核心流程已可跑；公网暴露前请按下文完成密钥、SSH 校验与反向代理。

---

## 能做什么

| 能力 | 说明 |
| --- | --- |
| 控制台 | 本地 HTTP 面板，默认 `127.0.0.1:8787`，登录鉴权 |
| 服务器 | 录入 VPS，SSH 连通性检测，主机密钥 TOFU |
| 部署 | dry-run 演练，或 native 真实安装 3x-ui + 默认 `VLESS + REALITY` |
| 客户端 | 创建、启停、重置流量、改额度与到期 |
| 订阅 | 默认订阅与自定义订阅链接分发 |
| 代理链 | 例如 `A → C → B`：用户连 A，经 C，从 B 出口；远端为独立 `myn-chain-*` systemd 服务 |
| 容器 | `Dockerfile` + `docker-compose.yml` |

---

## 快速开始

```powershell
pip install -r requirements.txt
$env:APP_SECRET = "replace-with-a-long-random-secret"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "replace-with-a-strong-password"
python -m app.server
```

浏览器打开：<http://127.0.0.1:8787>

本地若未设 `ADMIN_PASSWORD`，会回退为 `APP_SECRET`（仅 loopback / 开发模式）。非本地绑定会强制要求显式密钥，否则拒绝启动。

### Docker

```powershell
Copy-Item .env.example .env
# 编辑 .env：至少填写 APP_SECRET、ADMIN_PASSWORD
docker compose up --build
```

容器内 `HOST=0.0.0.0`，进入安全模式；密钥从 `.env` 读取（已在 `.gitignore`）。

---

## 推荐使用流程

1. **服务器** — 添加 VPS → 测试 SSH  
2. **部署** — 创建 3x-ui 部署（先 dry-run 熟悉流程，再 native）  
3. **客户端** — 部署成功后创建客户端  
4. **订阅** — 配置并分发订阅链接  
5. **代理链**（可选）— 选择 ready 的 native 节点排序 → 保存 →「下发远端」

代理链语义（UI 从上到下）：

```text
用户 → A → C → B → Internet
```

- 第一台是入口（客户端只连它）  
- 中间是中继  
- 最后一台是出口  
- 订阅 `/sub/chains/{token}` 返回入口链接  

链路不改写 3x-ui 主配置，而是在每台机上装独立服务：

```text
/opt/manage-node/chains/myn-chain-*/
/etc/systemd/system/myn-chain-*.service
```

删除链路 / 部署 / 服务器时，会尽力停掉并移除对应远端服务。

---

## 部署模式

### Dry-run

只在本地写库、记任务日志、生成占位节点与订阅，不改远端。适合验 UI 和流程。

### Native

经 SSH 在目标机上：

1. 跑 3x-ui 官方 unattended 安装脚本  
2. 读 `/etc/x-ui/install-result.env`  
3. 经 **SSH 隧道** 调面板 API，建默认 `VLESS + REALITY` inbound  
4. 可选创建首个 client 并拉真实分享链接  

要求：

- SSH 可达；非 root 需无密码 sudo  
- 支持未加密私钥、密码或 ssh-agent；暂不支持带 passphrase 的私钥粘贴  
- 代理链节点须为 native + ready，且目标机有 systemd  
- 链路端口需在云防火墙与系统防火墙放行  

失败时：代理链会尽力清理已装的 `myn-chain-*`；若 native 安装结果已写入后再失败，会尝试卸载远端 3x-ui。清理均为 best-effort。

---

## 安全

### 安全模式 vs 本地开发

| | 本地开发（绑定 `127.0.0.1` / `localhost`） | 安全模式（如 `0.0.0.0`） |
| --- | --- | --- |
| 默认 | `APP_ALLOW_INSECURE` 自动为真 | 强制校验密钥 |
| `APP_SECRET` | 可用内置开发默认值 | 必须显式设置，且 ≥ 16 字符，不能是内置默认 |
| `ADMIN_PASSWORD` | 未设则回退 `APP_SECRET` | 必须显式设置 |

可用 `APP_ALLOW_INSECURE=1` 强制开发模式——**切勿对公网使用**。

### 已内置

- 敏感数据（SSH 密钥、面板密码、API token）用 Fernet + scrypt 加密；旧 `v1` 密文可读，下次写入升为 `v2`  
- 登录失败限流：默认 5 分钟内失败 5 次 → 锁定 15 分钟（429）  
- SSH 主机密钥 TOFU：首次记录指纹，之后校验；指纹变化拒绝连接（重装机器则删服务器记录后重加）  
- 3x-ui API 一律经 SSH 隧道访问 `127.0.0.1`，面板凭据不走公网明文  
- Session Cookie：`HttpOnly`、`SameSite=Strict`；非本地默认 `Secure`  
- `X-Forwarded-For` **默认不信任**；仅在受信反向代理后设 `TRUST_X_FORWARDED_FOR=1`  
- 500 对外只回通用信息，细节进服务端日志  
- 管理变更操作写入 `myn.audit` 进程日志（非持久化审计表）  
- 启动时把上次遗留的 `running` 任务、卡住的部署/链路标为 `failed`  

### 公网前还要做的

- 前面加反向代理终结 TLS（应用本身不提供 HTTPS）  
- 绑定 `127.0.0.1`，只让代理访问面板  
- 设 `TRUST_X_FORWARDED_FOR=1`  
- 定期备份 `data/`，并保管好 `APP_SECRET`（丢了旧密文解不开）  

`examples/Caddyfile` 与 `examples/nginx.conf` 有现成示例。

---

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `APP_DATA_DIR` | `data` | SQLite 目录 |
| `APP_SECRET` | `development-only-secret` | 加密与 session 签名；安全模式必填且足够强 |
| `ADMIN_USERNAME` | `admin` | 管理员用户名 |
| `ADMIN_PASSWORD` | （无） | 管理员密码；安全模式必填 |
| `SESSION_HOURS` | `12` | Session 有效小时数 |
| `HOST` | `127.0.0.1` | 监听地址 |
| `PORT` | `8787` | 监听端口 |
| `APP_ALLOW_INSECURE` | loopback 时为真 | 强制开发模式 |
| `SESSION_COOKIE_SECURE` | 非 loopback 时为真 | Cookie 是否带 `Secure` |
| `TRUST_X_FORWARDED_FOR` | `0` | 是否采信 `X-Forwarded-For` |
| `MAX_BODY_BYTES` | `1048576` | 请求体上限 |
| `REALITY_DEST` | `www.microsoft.com:443` | REALITY 回落目标 `host:port` |
| `REALITY_SNI` | `REALITY_DEST` 的 host | REALITY SNI |

更换已有数据的 `APP_SECRET` 后，旧的 SSH 密钥 / 面板密码 / API token 将无法解密。

---

## 备份

整目录备份 `data/`（含 `manage_node.db` 与 WAL）。备份本身建议再加密存放。

一致性在线备份示例：

```powershell
python -c "import sqlite3; sqlite3.connect('data/manage_node.db').backup(sqlite3.connect('backup.db'))"
```

---

## 测试

```powershell
pip install -r requirements-dev.txt
pytest
```

覆盖：密文（含旧 `v1`）、session / 登录限流、安全模式配置、`X-Forwarded-For` 开关、业务逻辑片段、孤儿任务恢复、代理链失败回滚触发。

---

## 项目结构

```text
app/
  auth.py           Session 签名、校验、登录限流
  config.py         环境变量与安全模式
  database.py       SQLite schema / 迁移（WAL）
  provisioning.py   3x-ui 安装脚本生成
  security.py       密文封装（Fernet + scrypt）
  server.py         HTTP 路由与静态资源
  services.py       业务逻辑、部署、代理链下发与回滚
  ssh_runner.py     Paramiko + 主机密钥 TOFU
  ssh_tunnel.py     SSH 本地端口转发（面板 API）
  xui_api.py        3x-ui API 客户端
  static/           前端 HTML/CSS/JS
tests/              pytest
examples/           Caddy / Nginx 反向代理示例
.env.example        环境变量模板
```

---

## 已知限制

- 单管理员，无多用户 / RBAC  
- 审计仅为进程日志，无独立审计表  
- 代理链 Xray 服务不出现在 3x-ui 面板里  
- 远端失败清理是 best-effort  
- 订阅 token 泄露即可读取对应订阅内容  
- 暂不支持带 passphrase 的 SSH 私钥粘贴  
- 主密钥仍来自环境变量，未接 OS keychain / KMS  
