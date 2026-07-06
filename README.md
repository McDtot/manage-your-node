# Manage Your Node

Manage Your Node 是一个本地 Web 管理面板，用来录入 VPS、安装和管理 3x-ui 节点、生成客户端/订阅链接，并编排多台服务器组成链式代理。

当前版本仍偏 MVP：核心流程已经可跑，但生产使用前必须认真处理密钥、主机校验和网络暴露策略。

## 当前能力

- 本地 Web 控制台，默认端口 `8787`
- 管理面板登录鉴权，基于签名 session cookie
- SQLite 持久化，默认数据目录为 `data/`
- VPS 资产录入和 SSH 连通性检测
- 3x-ui dry-run 部署流程
- native 真实部署：通过 SSH 执行官方 3x-ui unattended 安装脚本
- 部署后通过 3x-ui API 创建默认 `VLESS + REALITY` inbound
- 创建客户端、禁用/启用、重置流量、修改额度和到期时间
- 默认订阅和自定义订阅分发
- 代理链编排：例如 `A -> C -> B` 表示用户连接 A，流量经 C，最后从 B 出口
- 代理链远端下发：为每个链路节点创建独立 `myn-chain-*` Xray systemd 服务
- Dockerfile 和 `docker-compose.yml`

## 快速开始

安装依赖：

```powershell
pip install -r requirements.txt
```

启动：

```powershell
python -m app.server
```

打开：

```text
http://127.0.0.1:8787
```

默认登录：

```text
用户名：admin
密码：如果设置了 ADMIN_PASSWORD，则使用 ADMIN_PASSWORD；否则使用 APP_SECRET
```

本地建议显式设置：

```powershell
$env:APP_SECRET="replace-with-a-long-random-secret"
$env:ADMIN_USERNAME="admin"
$env:ADMIN_PASSWORD="replace-with-a-strong-password"
python -m app.server
```

## Docker 运行

```powershell
docker compose up --build
```

`docker-compose.yml` 中的 `APP_SECRET` 和 `ADMIN_PASSWORD` 是占位值，真实使用前必须替换。

## 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `APP_DATA_DIR` | `data` | SQLite 数据库目录 |
| `APP_SECRET` | `development-only-secret` | 本地密文和登录 session 签名密钥 |
| `ADMIN_USERNAME` | `admin` | 管理面板用户名 |
| `ADMIN_PASSWORD` | `APP_SECRET` 的值 | 管理面板密码 |
| `SESSION_HOURS` | `12` | 登录 session 有效小时数 |
| `HOST` | `127.0.0.1` | Web 服务监听地址 |
| `PORT` | `8787` | Web 服务监听端口 |

注意：`APP_SECRET` 参与已有密文解密。已有数据创建后再更换 `APP_SECRET`，旧的 SSH 密钥、面板密码和 API token 将无法解密。

## 使用流程

1. 在「服务器」页添加 VPS。
2. 测试 SSH 连接。
3. 在「部署」页创建 3x-ui 部署。
4. 部署成功后，在「客户端」页创建客户端。
5. 在「订阅」页创建和分发订阅链接。
6. 如需链式代理，在「代理链」页选择 ready 部署节点并排序，例如 `A -> C -> B`。
7. 保存代理链后点击「下发远端」，查看任务日志。

## 代理链语义

代理链按 UI 中从上到下的顺序执行：

```text
用户 -> A -> C -> B -> Internet
```

- 第一台是入口节点，用户客户端只连接它。
- 中间节点只做中继。
- 最后一台是出口节点，最终访问互联网的源地址是它。
- 订阅链接 `/sub/chains/{token}` 返回入口节点链接。

## 代理链下发方式

为了降低对已有 3x-ui inbound 的影响，代理链不改写 3x-ui 主配置，而是在每台目标 VPS 上创建独立服务：

```text
/opt/manage-node/chains/myn-chain-*/
/etc/systemd/system/myn-chain-*.service
```

下发时会：

- 在每个节点生成或复用 REALITY X25519 keypair
- 为每个节点分配独立入站端口
- 从出口节点到入口节点逐台安装 Xray 配置
- 非出口节点 outbound 指向下一跳
- 出口节点 outbound 使用 `freedom`
- 尝试为链路端口放行 `ufw` 或 `firewall-cmd`

删除代理链时会尽力停止并移除对应的 `myn-chain-*` 服务。删除部署或服务器时，也会先尝试清理关联代理链。

## 部署模式

### Dry-run

Dry-run 只在本地生成部署记录、任务日志、订阅链接和占位节点，不修改远端服务器。它适合本地验证 UI 和流程。

### Native

Native 会通过 SSH 登录目标 VPS：

- 运行 3x-ui 官方 unattended 安装脚本
- 读取 `/etc/x-ui/install-result.env`
- 调用 3x-ui API 创建默认 `VLESS + REALITY` inbound
- 创建首个 client 并拉取真实分享链接

真实部署当前要求：

- 目标机可通过 SSH 登录
- 非 root 用户必须具备无密码 sudo
- 使用未加密私钥、密码或 ssh-agent；暂不支持带 passphrase 的私钥粘贴
- 代理链节点必须是 native + ready，且目标机可运行 systemd
- 链路端口需要在云防火墙和系统防火墙中允许入站

## 安全说明

当前实现适合本地或受控网络使用。生产暴露前至少需要处理：

- 替换 `APP_SECRET`
- 替换 `ADMIN_USERNAME` / `ADMIN_PASSWORD`
- 使用反向代理提供 HTTPS
- 加强 SSH host key 校验，目前会自动接受未知主机 key
- 替换 MVP 级本地密文方案，建议使用 OS keychain、KMS 或成熟加密库
- 重新启用 3x-ui API TLS 证书校验
- 为远端部署和代理链下发增加更完整的回滚策略

## 项目结构

```text
app/
  auth.py          登录 session 签名和校验
  config.py        环境变量配置
  database.py      SQLite schema 和迁移
  provisioning.py  3x-ui 安装脚本生成
  security.py      本地密文封装
  server.py        HTTP 路由和静态文件服务
  services.py      业务逻辑、部署任务、代理链下发
  ssh_runner.py    Paramiko SSH 执行器
  xui_api.py       3x-ui API 客户端
  static/          原生 HTML/CSS/JS 前端
```

## 已知限制

- 没有多用户、角色权限和审计日志
- 没有正式测试套件，目前主要靠编译检查和临时端到端脚本验证
- 代理链服务使用独立 Xray systemd 服务，不会出现在 3x-ui 面板里
- 代理链下发失败时会记录错误，但远端残留清理仍是 best-effort
- 订阅 token 泄露后，持有者可读取对应订阅内容
