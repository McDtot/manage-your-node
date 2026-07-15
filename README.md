# Manage Your Node

本地 Web 面板：录入 VPS、部署并管理 3x-ui 节点、创建用户/订阅，以及把多台机器编排成链式代理。

面向自用 / 小规模运维。Docker 默认可通过公网 IP 访问；未配置域名与 HTTPS 时，WebUI 会持续显示安全提示。

---

## 当前版本：v0.7.0

[v0.7.0](https://github.com/McDtot/manage-your-node/releases/tag/v0.7.0) 支持直接从 WebUI 配置外部访问地址：

- 在“设置 → 外部访问设置”填写 HTTPS 域名，订阅链接会立即改用该地址
- 外部地址持久化到数据库，并同步更新 Host 白名单、CSRF 来源校验与 Secure Cookie
- `.env` 中的 `PUBLIC_ORIGIN` 保留为首次启动与恢复兜底，支持一键恢复服务器配置
- 严格校验并规范化协议、域名和端口；错误配置可通过 loopback / SSH 端口转发恢复
- 设置页已适配桌面与移动布局，并补充完整的配置、API 与安全回归测试

已有部署可进入原项目目录执行 `git pull --ff-only` 后重新运行 `sudo bash install.sh` 完成升级。

---

## 能做什么

| 能力 | 说明 |
| --- | --- |
| 控制台 | 本机运行默认 `127.0.0.1:8787`；Docker 默认发布 `0.0.0.0:8787`，带登录鉴权 |
| 服务器 | 录入 VPS，SSH 连通性检测，首次指纹需人工核验与批准 |
| 部署 | 通过 SSH 真实安装 3x-ui + 默认 `VLESS + REALITY` |
| 用户 | 在同一节点创建多个独立用户，支持启停、手动或周期重置流量、修改额度与到期时间 |
| 订阅 | 默认订阅与自定义订阅链接分发，支持为每条订阅单独设置节点显示名称 |
| 代理链 | 例如 `A → C → B`：入口固定 VLESS Reality，节点间可逐跳选择 SS2022 或 Reality；远端为独立 `myn-chain-*` systemd 服务 |
| 容器 | `Dockerfile` + `docker-compose.yml` |

---

## 用户一键部署

要求：一台使用 Ubuntu、Debian、Fedora、CentOS 或 RHEL 的 Linux 服务器。若未安装 Docker，脚本会通过 Docker 官方软件源自动安装 Engine、CLI、Buildx 和 Compose 插件。

```bash
git clone https://github.com/McDtot/manage-your-node.git
cd manage-your-node
sudo bash install.sh
```

脚本会自动完成：

- 检查 Docker 与 Compose 权限
- 未安装时从 Docker 官方软件源安装并启动 Docker
- 生成 `.env` 和应用主密钥
- 提示用户隐藏输入管理员密码，并要求再次确认
- 构建并启动容器
- 等待健康检查通过
- 输出访问地址和管理员用户名（不会回显用户设置的密码）

首次交互部署时，脚本会在终端中提示设置至少 12 个字符的管理员密码，输入内容不会显示。无交互终端且未提供密码文件时，脚本会生成随机密码并在部署完成后显示一次。

默认通过 `0.0.0.0:8787` 提供临时公网 HTTP 访问。常用选项：

```bash
# 自定义端口和管理员用户名
sudo bash install.sh --panel-port 8080 --admin-user operator

# 已经配置好 HTTPS 反向代理时使用；会默认只绑定 127.0.0.1
sudo bash install.sh --domain panel.example.com

# 使用预先创建的密码文件，避免密码进入命令历史
sudo bash install.sh --admin-password-file /root/manage-node-admin-password
```

重复执行脚本会保留已有 `.env`、密钥和 Docker 数据卷，用当前项目代码重新构建服务；已有 Docker 不会被重复安装，也不会覆盖已有项目配置。其他 Linux 发行版需先按 [Docker 官方文档](https://docs.docker.com/engine/install/)安装 Docker。

已经部署过时，请进入原项目目录执行升级，不要在项目目录里再次 `git clone` 出同名的嵌套目录。Docker 数据卷必须始终与原来的 `secrets/app_secret.txt` 配套；安装器会在启动前校验二者，发现旧数据卷但缺少原密钥或密钥不匹配时会安全停止，不会替换正在运行的服务。

自动安装需要 root / sudo 权限，且不会主动卸载系统中可能冲突的 `containerd`、`runc` 等软件；若包管理器报告冲突，脚本会停止并保留现场供管理员处理。

升级已部署实例：

```bash
git pull --ff-only
sudo bash install.sh
```

升级前建议按“备份”章节保存一次数据库与 `APP_SECRET`。

---

## 本地开发

```powershell
pip install -r requirements.txt
$env:APP_SECRET = "replace-with-a-long-random-secret"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "replace-with-a-strong-password"
python -m app.server
```

浏览器打开：<http://127.0.0.1:8787>

本地若未设 `ADMIN_PASSWORD`，会回退为 `APP_SECRET`（仅 loopback / 开发模式）。非本地绑定会强制要求显式密钥，否则拒绝启动。

### 手动使用 Docker

```powershell
Copy-Item .env.example .env
New-Item -ItemType Directory -Force secrets
python -c "from pathlib import Path; import secrets; Path('secrets/app_secret.txt').write_text(secrets.token_urlsafe(48))"
# 手工写入一个强管理员密码，不要复用 APP_SECRET
Set-Content -NoNewline secrets/admin_password.txt 'replace-with-a-strong-password'
# 域名与 HTTPS 可稍后配置；未配置时 WebUI 会提示
docker compose up --build -d
```

Compose 默认把端口发布到宿主机 `0.0.0.0:8787`；密钥通过 Docker secrets
挂载，应用以 UID/GID `10001` 非 root 运行，数据保存在命名卷
`manage-node-data`。在 Linux 上，一键脚本会把 `secrets/` 目录保持为 `0700`，
并把两个密钥文件设为 `0444`，使 Compose 绑定挂载后的文件可由容器内的非 root
进程读取；其他宿主机用户仍无法穿过私有目录读取密钥。配置本机反向代理后，
应把 `BIND_ADDRESS` 改成 `127.0.0.1`。

---

## 推荐使用流程

1. **服务器** — 添加 VPS → 测试 SSH → 通过云厂商控制台核验并批准指纹 → 再测试
2. **部署** — 创建 3x-ui 部署；伪装目标建议选“自动检测并固定”
3. **用户** — 部署成功后可在同一节点创建多个用户
4. **订阅** — 配置并分发订阅链接，可把普通节点用户与已下发的代理链汇总到同一链接
5. **代理链**（可选）— 选择 ready 的 native 节点排序 → 逐跳选择协议 → 保存 →「下发远端」

代理链语义（UI 从上到下）：

```text
用户 ─ VLESS + REALITY → A ─ SS2022 / Reality → C ─ SS2022 / Reality → B → Internet
```

- 第一台是入口（用户设备只连接它）
- 中间是中继  
- 最后一台是出口  
- 用户设备到入口固定为 `VLESS + REALITY`；节点间默认使用 `Shadowsocks 2022`，真正跨境的节点间链路可切回 Reality
- SS2022 使用 `2022-blake3-aes-256-gcm` 与逐跳独立密钥；密钥经 `APP_SECRET` 加密存库，不下发给用户设备
- 固定发布包内的 Xray 目前可以运行 SS2022，但已输出未来可能移除 Shadowsocks 的兼容性警告；新建链路时可逐跳选择 Reality
- 订阅 `/sub/chains/{token}?format=mihomo` 返回可直接导入 Mihomo / Clash 的 YAML；`format=base64` 返回传统 Base64 入口链接。无参数时会根据客户端 User-Agent 自动选择，其他客户端默认保持 Base64 兼容。

链路不改写 3x-ui 主配置，而是在每台机上装独立服务：

```text
/opt/manage-node/chains/myn-chain-*/
/etc/systemd/system/myn-chain-*.service
```

删除链路 / 部署 / 服务器时，会尽力停掉并移除对应远端服务。自动放行的系统防火墙端口不会擅自删除，避免移除用户原有规则；不用的端口应在确认后手动关闭。

---

## 部署流程

经 SSH 在目标机上：

1. 下载固定 commit 的 3x-ui unattended 安装器并校验 SHA-256
2. 安装固定的 3x-ui release，并按架构校验 release archive SHA-256
3. 强制面板只监听远端 `127.0.0.1`
4. 读 `/etc/x-ui/install-result.env`，敏感行不写任务日志
5. 从目标 VPS 对候选伪装站连续执行两次 TLS 1.3 与证书校验，把首个通过的目标固定保存到该部署；手动模式也会先校验
6. 经 **SSH 隧道** 调面板 API，使用该部署自己的伪装目标创建默认 `VLESS + REALITY` inbound
7. 部署完成后，在“用户”页面为该节点创建用户并获取分享链接

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
| `ADMIN_PASSWORD` | 未设则回退 `APP_SECRET` | 必须显式设置、≥ 12 字符，且不能等于 `APP_SECRET` |
| `PUBLIC_ORIGIN` | 自动使用本地地址 | 可暂不设置；WebUI 会提示缺少域名/HTTPS |

`APP_ALLOW_INSECURE=1` 只允许与 loopback 监听地址一起使用；非本地绑定会拒绝启动。

### 默认公网访问与域名提示

Docker Compose 默认把 `8787` 发布到 `0.0.0.0`，部署后可以先通过公网 IP 直接访问，不需要额外开关。未设置 HTTPS 域名时，登录后的 WebUI 顶部会显示黄色安全提示；强 `APP_SECRET`、强管理员密码、CSRF、登录限流与审计仍然启用。

非容器运行若也要对外监听，只需设置：

```text
HOST=0.0.0.0
```

以后配置好反向代理后，可以直接进入 WebUI 的“设置 → 外部访问设置”，填写 `https://域名`。保存后订阅链接、Host 白名单、CSRF 来源校验和安全 Cookie 会立即切换到新地址；配置持久化在数据库中，重启后仍然有效。`.env` 中的 `PUBLIC_ORIGIN` 继续作为首次启动和“恢复服务器配置”时的兜底。

如果反向代理与应用在同一台机器，仍应在 `.env` 中把 `BIND_ADDRESS` 改为 `127.0.0.1`，因为 Docker 的宿主机端口绑定无法由容器内的 WebUI 修改。WebUI 只接受完整的 HTTPS 公网域名，并要求应用已经关闭 `APP_ALLOW_INSECURE`、使用生产密钥。

保存时当前会话使用的旧访问地址会临时保留到进程重启，便于立即测试和撤销。若旧会话已经失效或错误配置后已经重启，可在服务器本机访问，或通过 SSH 将 `127.0.0.1:8787` 转发到本地；loopback 恢复入口会使用严格的同源校验和非 Secure 恢复 Cookie，不受错误公网域名阻断。

未配置 HTTPS 时仍是明文 HTTP，传输中的登录信息、SSH 密码或私钥可能被链路监听，因此只建议作为部署初期的过渡状态。

### 已内置

- 敏感数据（SSH 密钥、面板密码、API token）用 Fernet + scrypt 加密；旧 `v1` 密文可读，下次写入升为 `v2`  
- Starlette + Uvicorn 提供 ASGI Web 服务；请求 Host 白名单、请求体上限与就绪检查
- 登录失败限流持久化到 SQLite：默认 5 分钟内失败 5 次 → 锁定完整 15 分钟（429）
- SSH 首次主机密钥只记录为待批准；必须带外核验后才能认证和 native 部署；变化时拒绝连接
- 3x-ui 面板强制绑定远端 `127.0.0.1`，API 一律经固定主机指纹的 SSH 隧道访问
- 写 API 使用与 session 绑定的 CSRF 双提交令牌，并校验 Origin / Fetch Metadata
- Session Cookie：`HttpOnly`、`SameSite=Strict`；生产环境使用 `Secure` 与 `__Host-` 前缀
- CSP、HSTS、`nosniff`、拒绝 framing、无 Referrer 等安全响应头
- `X-Forwarded-For` 默认不信任；启用时还必须用 `TRUSTED_PROXY_IPS` 限制来源
- 公开订阅接口按来源地址限流，订阅与代理链 token 可在 UI 中轮换
- 500 对外只回通用信息，细节进服务端日志  
- 管理变更同时写进程日志和持久化 `audit_events` 表，可经 `/api/audit` 查询
- 部署使用数据库互斥锁；启动时恢复孤儿任务并清理遗留锁

### 正式公网前还要做的

- 前面加反向代理终结 TLS（应用本身不提供 HTTPS）  
- 绑定 `127.0.0.1`，只让代理访问面板  
- 在 WebUI 设置准确的外部访问地址，或使用 `PUBLIC_ORIGIN`、`ALLOWED_HOSTS` 作为服务器端兜底
- 只有确认反向代理来源地址后才启用 `TRUST_X_FORWARDED_FOR`
- 定期执行一致性备份与恢复演练，并离线保管 `APP_SECRET`

`examples/Caddyfile` 与 `examples/nginx.conf` 有现成示例。

---

## 环境变量

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `APP_DATA_DIR` | `data` | SQLite 目录 |
| `APP_SECRET` | `development-only-secret` | 加密与 session 签名；安全模式必填且足够强 |
| `APP_SECRET_FILE` | （无） | 从文件读取主密钥；优先于 `APP_SECRET` |
| `ADMIN_USERNAME` | `admin` | 管理员用户名 |
| `ADMIN_PASSWORD` | （无） | 管理员密码；安全模式必填 |
| `ADMIN_PASSWORD_FILE` | （无） | 从文件读取管理员密码；优先于环境变量 |
| `SESSION_HOURS` | `12` | Session 有效小时数 |
| `HOST` | `127.0.0.1` | 监听地址 |
| `PORT` | `8787` | 监听端口 |
| `APP_ALLOW_INSECURE` | loopback 时为真 | 强制开发模式 |
| `BIND_ADDRESS` | `0.0.0.0` | Docker 发布地址；配置本机反代后改为 `127.0.0.1` |
| `PANEL_PORT` | `8787` | Docker 发布到宿主机的管理面板端口 |
| `SESSION_COOKIE_SECURE` | HTTPS origin 时为真 | Cookie 是否带 `Secure` |
| `TRUST_X_FORWARDED_FOR` | `0` | 是否采信 `X-Forwarded-For` |
| `TRUSTED_PROXY_IPS` | `127.0.0.1,::1` | Uvicorn 可采信转发头的代理 IP/CIDR |
| `PUBLIC_ORIGIN` | 自动使用监听地址 | 外部访问地址的首次启动 / 恢复兜底；WebUI 保存值会优先使用 |
| `ALLOWED_HOSTS` | 未配域名时允许当前 Host | 服务器端附加 Host 白名单；WebUI 外部地址的域名会自动加入 |
| `MAX_BODY_BYTES` | `1048576` | 请求体上限 |
| `SUBSCRIPTION_RATE_LIMIT` | `120` | 单来源每分钟订阅请求上限 |
| `REALITY_CANDIDATES` | Yahoo、Apple、Amazon | 自动模式按顺序从目标 VPS 检测的 `host:port` 列表，逗号分隔 |
| `REALITY_DEST` | `www.yahoo.com:443` | 旧部署的全局回落目标；显式设置且未设置候选列表时，也作为唯一自动候选 |
| `REALITY_SNI` | `REALITY_DEST` 的 host | 旧部署 / 单一全局目标的 SNI |

更换已有数据的 `APP_SECRET` 后，旧的 SSH 密钥 / 面板密码 / API token 将无法解密。

---

## 备份

备份本身应加密并复制到另一台机器；`APP_SECRET` 必须独立离线保管。

一致性在线备份示例：

```powershell
python -m app.maintenance backup
python -m app.maintenance check
```

Docker 中可先写到数据卷，再复制出来：

```powershell
docker compose exec manage-your-node python -m app.maintenance backup /data/manage-node-backup.db
docker cp manage-your-node:/data/manage-node-backup.db ./backups/manage-node-backup.db
```

---

## 测试

```powershell
pip install -r requirements-dev.txt
pytest
```

覆盖：密文（含旧 `v1`）、session / CSRF、持久化登录限流、安全模式配置、
ASGI 路由与安全响应头、事务回滚、在线备份、订阅令牌轮换、SSH 指纹批准、
孤儿任务恢复、安装器固定与校验、代理链失败回滚触发。

---

## 项目结构

```text
app/
  auth.py           Session 签名、校验、登录限流
  config.py         环境变量与安全模式
  database.py       SQLite schema / 迁移（WAL）
  web_config.py     WebUI 外部地址持久化与运行时安全策略
  provisioning.py   3x-ui 安装脚本生成
  security.py       密文封装（Fernet + scrypt）
  server.py         Starlette 路由、中间件与 Uvicorn 启动
  maintenance.py    备份与数据库/主密钥检查
  services.py       业务逻辑、部署、代理链下发与回滚
  ssh_runner.py     Paramiko + SSH 主机密钥捕获/批准/固定
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
- 代理链 Xray 服务不出现在 3x-ui 面板里  
- 远端失败清理是 best-effort  
- 订阅 token 泄露即可读取对应订阅内容  
- 暂不支持带 passphrase 的 SSH 私钥粘贴  
- 无内置 MFA；正式环境应再通过 VPN、访问控制或支持 MFA 的身份代理保护管理面
- 支持文件型 secret，但未直接集成云 KMS / Vault，也未提供在线主密钥轮换
