# Manage Your Node

一个自托管的 VPS 节点管理面板。通过浏览器即可录入服务器、部署 3x-ui、创建独立用户和订阅，并把多台 VPS 编排成代理链。

[最新版本](https://github.com/McDtot/manage-your-node/releases/latest) · [更新记录](https://github.com/McDtot/manage-your-node/releases) · [问题反馈](https://github.com/McDtot/manage-your-node/issues)

> [!IMPORTANT]
> 本项目适合个人或小规模运维，当前为单管理员模式。应用本身不提供 HTTPS；公网使用前请配置反向代理和 TLS，并遵守所在地法律法规及服务商条款。

## v0.12.0 更新亮点

- WebUI 视觉全面重构为「液态玻璃 v2」：更通透的玻璃质感（低不透明度填充 + 高斯模糊 + 渐变折射描边）、悬浮玻璃侧栏、靛蓝紫新品牌色。
- 新增「外观与背景」设置：预设渐变 / 上传图片 / 图片 URL 三种自定义背景，背景与卡片遮罩强度可分别调节（设置保存在当前浏览器）。
- 新增手动主题切换：跟随系统 / 亮色 / 暗色三态，顶栏一键循环切换。
- 修复严格 CSP 导致的样式失效：内联与 JS 注入样式全部迁入样式表，`img-src` 放行 HTTPS 图片以支持外链背景。

完整变更见 [v0.12.0 发布说明](https://github.com/McDtot/manage-your-node/releases/tag/v0.12.0)。此前 v0.11.0 首次引入液态玻璃视觉，见 [v0.11.0](https://github.com/McDtot/manage-your-node/releases/tag/v0.11.0)。

## 主要功能

| 功能 | 说明 |
| --- | --- |
| Web 控制台 | 中文界面，登录鉴权，集中查看服务器、部署、用户和任务状态 |
| 服务器管理 | 保存 VPS SSH 信息、测试连通性，并在首次连接时人工核验主机指纹 |
| 健康监控 | 周期性探测每台服务器的 SSH 可达性与延迟，可一键批量检查 |
| 节点部署 | 通过 SSH 安装固定版本的 3x-ui，自动创建 VLESS + REALITY 或 Shadowsocks 2022 入站 |
| 用户管理 | 同一节点可创建多个独立用户，支持启停、流量额度、手动/周期重置和到期时间 |
| 流量统计 | 从 3x-ui 周期性同步真实用量到本地，支持一键手动刷新 |
| 订阅分发 | 按需创建订阅，自由组合普通用户和代理链，并为每个条目设置显示名称，可生成二维码 |
| 代理链 | 将多个可用节点按顺序组成入口、中继和出口，节点间支持 REALITY 或 SS2022 |
| 运维与安全 | 任务日志、审计记录、在线备份、敏感信息加密、登录限流和 CSRF 防护 |

## 快速部署

### 1. 准备管理服务器

一键安装脚本支持以下 Linux 发行版：

- Ubuntu / Debian
- Fedora / CentOS / RHEL

服务器需要能够访问 GitHub 和 Docker 官方软件源，并允许当前用户使用 root 或 sudo。未安装 Docker 时，脚本会自动安装 Docker Engine、CLI、Buildx 和 Compose 插件。

### 2. 运行安装脚本

~~~bash
git clone https://github.com/McDtot/manage-your-node.git
cd manage-your-node
sudo bash install.sh
~~~

首次安装时，脚本会提示设置管理员密码。密码至少 12 个字符，输入过程不会显示。

脚本会自动：

1. 检查或安装 Docker；
2. 生成 <code>.env</code> 和应用主密钥；
3. 构建并启动容器；
4. 等待健康检查通过；
5. 输出访问地址和管理员用户名。

默认访问地址：

~~~text
http://管理服务器IP:8787
~~~

默认管理员用户名为 <code>admin</code>。如果管理服务器启用了云防火墙或安全组，请临时放行 TCP 8787（或自定义的面板端口）；配置 HTTPS 后应关闭该公网端口。

### 常用安装选项

~~~bash
# 修改管理面板端口和管理员用户名
sudo bash install.sh --panel-port 8080 --admin-user operator

# 已经配置好 HTTPS 反向代理时，初始化域名并只监听本机
sudo bash install.sh --domain panel.example.com

# 从文件读取管理员密码，避免密码出现在命令历史中
sudo bash install.sh --admin-password-file /root/manage-node-admin-password
~~~

可运行 <code>sudo bash install.sh --help</code> 查看所有选项。

> [!NOTE]
> 安装选项只在首次生成 <code>.env</code> 时写入配置。重复运行脚本会保留现有 <code>.env</code>、密钥和 Docker 数据卷，并使用当前代码重新构建服务。

## 第一次使用

### 1. 添加 VPS

进入“服务器”，填写：

- 名称和 IP / 域名；
- SSH 端口与用户名；
- SSH 私钥、密码，或选择 SSH Agent / 默认密钥。

目标 VPS 需要满足：

- 管理服务器能够通过 SSH 访问；
- 使用 root，或使用具备免密码 sudo 权限的普通用户；
- 能够访问 GitHub 以下载经过版本与哈希固定的 3x-ui；
- 用于代理链时需使用 systemd；
- 代理端口已在云安全组、NAT 映射和系统防火墙中正确配置。

暂不支持直接粘贴带 passphrase 的私钥；可以改用 ssh-agent。

### 2. 核验 SSH 指纹

点击“测试 SSH”后，首次发现的主机指纹只会记录，不会直接信任。请通过云厂商控制台或 VPS 本机核对指纹，确认完全一致后点击“核验后信任”，再测试一次连接。

如果 VPS 重装后指纹发生变化，连接会被拒绝。确认是预期变更后，先重置旧指纹，再重新核验。

### 3. 部署节点

进入“部署”并选择已通过 SSH 测试的服务器：

- 协议模板：可选 VLESS + REALITY 或 Shadowsocks 2022（2022-blake3-aes-256-gcm）；
- REALITY 伪装目标：仅 VLESS + REALITY 需要，建议选择“自动检测并固定”；
- 代理端口：默认 443，必须在目标 VPS 上可从公网访问；Shadowsocks 2022 需同时放行 TCP 和 UDP；
- 面板端口：可留空自动生成，仅通过 SSH 隧道访问，无需向公网开放。

部署完成并显示“可用”后，3x-ui 面板会被限制在目标 VPS 的 <code>127.0.0.1</code>，Manage Your Node 通过固定主机指纹的 SSH 隧道调用其 API。

### 4. 创建用户

进入“用户”，选择一个可用部署并设置：

- 用户名；
- 流量额度；
- 到期日，或勾选“不限时”；
- 流量自动重置周期，填 0 表示不自动重置。

每名用户拥有独立 UUID，可随时启停、修改额度与到期时间，或手动重置流量。

### 5. 创建订阅

订阅不会自动创建。进入“订阅”：

1. 新建一条订阅；
2. 点击“分发和调整”；
3. 选择要加入的普通用户和已下发代理链；
4. 按需设置订阅内的显示名称与额度；
5. 保存并复制订阅链接。

订阅链接支持两种格式：

| 格式 | 用法 |
| --- | --- |
| Mihomo / Clash YAML | 在链接后添加 <code>?format=mihomo</code> |
| 通用 Base64 | 在链接后添加 <code>?format=base64</code> |

不指定格式时，会根据客户端 User-Agent 自动识别 Mihomo / Clash，其他客户端默认返回 Base64。订阅令牌泄露后，任何人都可以读取对应内容；请及时在面板中轮换令牌。

## 代理链

代理链适合把多台已部署节点组成固定路径。例如：

~~~text
用户 ─ VLESS + REALITY → 香港入口 ─ REALITY / SS2022 → 日本中继 ─ REALITY / SS2022 → 美国出口 → Internet
~~~

使用方法：

1. 确保至少两台 native 部署处于“可用”状态；
2. 进入“代理链”，按入口到出口的顺序添加节点；
3. 为每个节点填写 NAT 商家分配的、内外一致的链路端口；
4. 为节点间链路选择 VLESS + REALITY 或 SS2022；
5. 保存后点击“下发远端”；
6. 下发成功后复制独立订阅，或把代理链加入组合订阅。

端口规则：

- 用户设备到入口固定使用 VLESS + REALITY；
- REALITY 链路只需映射 TCP；
- SS2022 链路必须在同一端口同时映射 TCP 和 UDP；
- 入口端口供用户设备连接，其余节点端口供上一跳连接；
- 当前只支持公网端口与本机监听端口相同的 NAT 映射，不支持端口转换。

保存时会检查与 SSH、3x-ui 面板、普通代理及其他代理链的端口冲突；下发前还会检查远端实际监听占用。链路服务独立运行，不会改写 3x-ui 主配置：

~~~text
/opt/manage-node/chains/myn-chain-*
/etc/systemd/system/myn-chain-*.service
~~~

删除代理链、部署或服务器时，系统会尽力移除相关远端服务。自动添加的防火墙规则不会自动删除，以免误删已有规则；不再使用的端口请确认后手动关闭。

## 配置 HTTPS

默认的公网 HTTP 只适合首次安装。明文传输可能暴露登录信息、SSH 密码或私钥，正式使用前请完成以下配置：

1. 将域名的 A / AAAA 记录指向管理服务器；
2. 使用 Caddy、Nginx 或其他反向代理申请证书并转发到 <code>127.0.0.1:8787</code>（自定义端口时使用实际的 <code>PANEL_PORT</code>）；
3. 在 <code>.env</code> 中设置 <code>BIND_ADDRESS=127.0.0.1</code>；
4. 重新运行 <code>sudo bash install.sh</code>；
5. 从 HTTPS 域名登录，在“设置 → 外部访问设置”保存完整地址，例如 <code>https://panel.example.com</code>；
6. 关闭安全组中临时开放的 8787 端口，只保留 HTTPS 入口。

仓库提供了可直接修改的配置示例：

- [Caddy 配置](examples/Caddyfile)
- [Nginx 配置](examples/nginx.conf)

如果首次安装前已经配置好反向代理，可以直接运行：

~~~bash
sudo bash install.sh --domain panel.example.com
~~~

这会初始化 HTTPS 外部地址，并默认将 Docker 端口绑定到 <code>127.0.0.1</code>。

> [!WARNING]
> WebUI 中的“外部访问设置”会更新订阅地址、Host 白名单、CSRF 来源和 Secure Cookie，但不能修改 Docker 的宿主机端口绑定。是否公开监听仍由 <code>.env</code> 中的 <code>BIND_ADDRESS</code> 决定。

## 升级

请始终在原项目目录升级，不要重新克隆到嵌套目录：

~~~bash
cd /path/to/manage-your-node
git pull --ff-only
sudo bash install.sh
~~~

> [!NOTE]
> 从 v0.9.1 升级到 v0.10.0 时，应用会自动添加健康监控和 Shadowsocks 2022 所需的数据库列；重建镜像时会自动安装二维码依赖 `segno`。升级前仍建议先备份数据库、`.env` 与 `secrets/`。

安装器会保留现有配置、主密钥、管理员密码和 Docker 数据卷，并在替换运行中服务前检查数据库与主密钥是否匹配。

升级前建议先备份。不要删除或重新生成原来的 <code>secrets/app_secret.txt</code>，否则数据库中的 SSH 密钥、面板密码和 API token 将无法解密。

## 备份

完整备份至少需要同时保存：

- SQLite 数据库备份；
- <code>secrets/app_secret.txt</code>；
- <code>secrets/admin_password.txt</code> 和 <code>.env</code>（建议一并保存）。

Docker 部署可执行：

~~~bash
docker compose exec manage-your-node \
  python -m app.maintenance backup /data/manage-node-backup.db

docker cp manage-your-node:/data/manage-node-backup.db \
  ./backups/manage-node-backup.db
~~~

检查当前数据库与主密钥：

~~~bash
docker compose exec manage-your-node python -m app.maintenance check
~~~

备份应加密后复制到另一台机器，主密钥还应独立离线保管。不要运行 <code>docker compose down -v</code>，除非你明确要删除全部应用数据。

## 常用运维命令

~~~bash
# 查看服务状态
docker compose ps

# 持续查看日志
docker compose logs -f manage-your-node

# 重新构建并启动
sudo bash install.sh

# 停止服务但保留数据卷
docker compose down

# 启动已有服务
docker compose up -d
~~~

## 常见问题

### 安装完成后无法访问面板

依次检查：

1. <code>docker compose ps</code> 中服务是否健康；
2. <code>docker compose logs --tail=100 manage-your-node</code> 是否有启动错误；
3. 云安全组和系统防火墙是否允许当前面板端口；
4. <code>.env</code> 中的 <code>BIND_ADDRESS</code> 是否为 <code>0.0.0.0</code>；
5. 如果绑定为 <code>127.0.0.1</code>，是否已通过本机反向代理访问。

### 部署提示必须先信任主机指纹

这是正常的安全流程。第一次测试 SSH 只记录指纹，请从云厂商控制台核对后再批准，随后重新测试。

### 使用普通 SSH 用户时部署失败

普通用户必须具备免密码 sudo 权限。部署任务无法在后台交互输入 sudo 密码。

### 配错外部域名后无法登录

可以通过 SSH 把管理服务器的 loopback 端口转发到本机：

~~~bash
ssh -L 8787:127.0.0.1:8787 user@管理服务器IP
~~~

然后打开 <http://127.0.0.1:8787>，进入“设置”修正地址或恢复服务器配置。使用了自定义 <code>PANEL_PORT</code> 时，请同步替换 SSH 转发命令两处的 8787。

### 代理链下发失败

确认每台 VPS：

- 使用的是 native 且状态为“可用”的部署；
- 链路端口没有被其他程序占用；
- NAT 公网端口与本机监听端口一致；
- REALITY 已放行 TCP，SS2022 已同时放行 TCP 和 UDP；
- 系统使用 systemd，SSH 用户有 root 或免密码 sudo 权限。

## 安全设计

- SSH 密钥、面板密码和 API token 使用 Fernet + scrypt 加密后存入 SQLite；
- 首次 SSH 主机指纹必须带外核验，指纹变化时拒绝连接；
- 3x-ui 面板仅监听目标 VPS 的 loopback，API 通过 SSH 隧道访问；
- 管理端写操作使用与会话绑定的 CSRF 令牌，并校验 Origin；
- 登录失败次数持久化限流，默认 5 分钟内失败 5 次后锁定 15 分钟；
- Session Cookie 使用 <code>HttpOnly</code> 和 <code>SameSite=Strict</code>，HTTPS 下启用 <code>Secure</code>；
- 内置 Host 白名单、请求体上限、安全响应头、订阅限流和持久化审计记录；
- 容器使用非 root 用户、只读根文件系统、移除 Linux capabilities，并禁止提权。

如果启用 <code>TRUST_X_FORWARDED_FOR</code>，必须同时把 <code>TRUSTED_PROXY_IPS</code> 限制为真实反向代理的来源 IP 或网段。

## 环境变量

通常只需通过安装脚本和 WebUI 配置。需要手动调整时，编辑项目根目录下的 <code>.env</code>，然后重新运行 <code>sudo bash install.sh</code>。

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| <code>ADMIN_USERNAME</code> | <code>admin</code> | 管理员用户名 |
| <code>PANEL_PORT</code> | <code>8787</code> | Docker 发布到宿主机的面板端口 |
| <code>BIND_ADDRESS</code> | <code>0.0.0.0</code> | Docker 发布地址；本机反代后改为 <code>127.0.0.1</code> |
| <code>PUBLIC_ORIGIN</code> | 自动推导 | WebUI 外部地址的首次启动/恢复兜底 |
| <code>ALLOWED_HOSTS</code> | 自动推导 | 额外允许的 Host，多个值用逗号分隔 |
| <code>SESSION_HOURS</code> | <code>12</code> | 登录会话有效小时数 |
| <code>SUBSCRIPTION_RATE_LIMIT</code> | <code>120</code> | 单来源每分钟订阅请求上限 |
| <code>TRAFFIC_SYNC_SECONDS</code> | <code>300</code> | 从 3x-ui 同步真实流量用量的周期；设为 <code>0</code> 可关闭 |
| <code>HEALTH_CHECK_SECONDS</code> | <code>120</code> | 批量检查节点健康状态的周期；设为 <code>0</code> 可关闭 |
| <code>TRUST_X_FORWARDED_FOR</code> | <code>0</code> | 是否采信反向代理传入的客户端 IP |
| <code>TRUSTED_PROXY_IPS</code> | <code>127.0.0.1,::1</code> | 允许传递代理头的来源 IP/CIDR |
| <code>REALITY_CANDIDATES</code> | Yahoo、Apple、Amazon | 自动检测的 <code>host:port</code> 候选列表 |
| <code>REALITY_DEST</code> | <code>www.yahoo.com:443</code> | 旧部署/单一候选的回落目标 |
| <code>REALITY_SNI</code> | 目标域名 | 旧部署/单一全局目标的 SNI |

非容器运行还支持：

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| <code>APP_DATA_DIR</code> | <code>data</code> | SQLite 数据目录 |
| <code>HOST</code> | <code>127.0.0.1</code> | 应用监听地址 |
| <code>PORT</code> | <code>8787</code> | 应用监听端口 |
| <code>APP_SECRET</code> | 开发默认值 | 生产环境必须显式设置且至少 16 个字符 |
| <code>APP_SECRET_FILE</code> | 无 | 从文件读取主密钥，优先于 <code>APP_SECRET</code> |
| <code>ADMIN_PASSWORD</code> | 无 | 生产环境必须显式设置且至少 12 个字符 |
| <code>ADMIN_PASSWORD_FILE</code> | 无 | 从文件读取管理员密码，优先于环境变量 |
| <code>APP_ALLOW_INSECURE</code> | loopback 时开启 | 仅限本地开发，不能与公网监听同时使用 |
| <code>SESSION_COOKIE_SECURE</code> | HTTPS 时开启 | 是否为 Session Cookie 添加 <code>Secure</code> |
| <code>MAX_BODY_BYTES</code> | <code>1048576</code> | 请求体大小上限 |

完整示例见 [.env.example](.env.example)。

## 本地开发

需要 Python 3.12：

~~~powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements-dev.txt

$env:APP_SECRET = "replace-with-a-long-random-secret"
$env:ADMIN_USERNAME = "admin"
$env:ADMIN_PASSWORD = "replace-with-a-strong-password"

python -m app.server
~~~

浏览器打开 <http://127.0.0.1:8787>。

运行测试与静态检查（与 CI 相同）：

~~~powershell
pytest
ruff check app tests
mypy
~~~

## 项目结构

~~~text
app/
  auth.py           登录、Session 与限流
  config.py         环境变量与安全模式
  database.py       SQLite schema、迁移与备份
  maintenance.py    数据库备份和主密钥检查
  provisioning.py   3x-ui 安装脚本生成
  security.py       敏感信息加密
  server.py         Starlette 路由与中间件
  services/         部署、用户、订阅和代理链逻辑(按领域拆分)
  ssh_runner.py     SSH 连接与主机指纹
  ssh_tunnel.py     3x-ui API 的 SSH 隧道
  web_config.py     WebUI 外部地址与运行时安全策略
  xui_api.py        3x-ui API 客户端
  static/           前端页面、样式与脚本
examples/           Caddy / Nginx 配置示例
tests/              pytest 测试
install.sh          Linux 一键安装与升级脚本
docker-compose.yml  容器编排配置
~~~

## 已知限制

- 单管理员，不支持多用户或 RBAC；
- 不提供内置 HTTPS 和 MFA；
- 代理链的 Xray 服务不会显示在 3x-ui 面板中；
- NAT 代理链不支持公网端口与本机端口转换；
- 暂不支持直接粘贴带 passphrase 的 SSH 私钥；
- 远端失败清理为 best-effort：删除服务器或部署时若 SSH 不可达，仍会删除本地记录，远端残留服务和端口需手工检查；
- 订阅令牌本身就是访问凭据，泄露后需立即轮换；
- 主密钥没有在线轮换流程，也未直接集成 KMS 或 Vault。
