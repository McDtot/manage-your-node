# Manage Your Node

3x-ui 节点部署器 v0.1。当前版本提供一个本地 Docker 化管理面板，用来录入 VPS、检测 SSH 端口、创建部署任务、管理客户端额度和到期时间，并为后续接入真实 SSH/3x-ui API 留出服务边界。

## 当前能力

- 本地 Web 控制台，默认端口 `8787`
- SQLite 持久化
- 服务器资产录入
- SSH 端口连通性检测
- 3x-ui dry-run 部署任务流程
- 通过 OpenSSH 执行官方 3x-ui unattended 安装脚本
- 真实部署后自动调用 3x-ui API 创建默认 `VLESS + REALITY` 入站
- 自动创建首个 3x-ui client，并拉取真实分享链接
- 客户端创建、禁用、重置流量、修改额度/到期时间
- Dockerfile 和 docker-compose 打包

## 本地运行

```powershell
pip install -r requirements.txt
```

```powershell
python -m app.server
```

打开：

```text
http://127.0.0.1:8787
```

## Docker 运行

```powershell
docker compose up --build
```

## 重要说明

部署支持两种模式：

- `真实部署：官方 3x-ui 安装脚本`：通过 OpenSSH 登录目标 VPS，运行 3x-ui 官方 unattended 安装脚本，并读取 `/etc/x-ui/install-result.env` 中的面板账号、密码、路径和 API token。
- 安装完成后会通过 3x-ui API 生成 Reality X25519 keypair，创建 `VLESS + REALITY` 入站，创建首个 client，拉取 `/panel/api/clients/links/{email}` 返回的真实节点链接，并请求 Xray 重启。
- `Dry-run`：只在本地走完任务日志、生成面板路径、订阅链接和客户端链接，不修改远端服务器。

真实部署当前限制：

- 非 root 用户必须具备无密码 sudo。
- 后续新增客户端会继续调用同一个 3x-ui inbound 创建真实 client；Dry-run 部署仍只创建本地占位记录。
- 粘贴加密私钥时暂不支持私钥 passphrase；可以改用密码、未加密私钥或 ssh-agent。

生产使用前必须替换：

- `APP_SECRET`
- SSH 密钥存储方式
- 真实 host key 校验
- 更严格的远端幂等部署逻辑
- 3x-ui API 错误回滚和更多协议模板
