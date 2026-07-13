#!/usr/bin/env bash
set -Eeuo pipefail

umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

ADMIN_USER="admin"
PANEL_PORT_VALUE="8787"
DOMAIN=""
BIND_ADDRESS_VALUE=""
PASSWORD_FILE=""
PASSWORD_CREATED=0

info() {
  printf '[manage-your-node] %s\n' "$*"
}

fail() {
  printf '[manage-your-node] 错误：%s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Manage Your Node 一键部署脚本

用法：
  sudo bash install.sh [选项]

选项：
  --admin-user NAME         管理员用户名（默认：admin）
  --panel-port PORT         对外访问端口（默认：8787）
  --domain HOST             已配置 HTTPS 反向代理时填写域名
  --bind-address ADDRESS    0.0.0.0 或 127.0.0.1
  --admin-password-file FILE
                            从文件读取管理员密码；不把密码放进命令行
  -h, --help                显示帮助

说明：
  - 首次执行会生成 .env、应用主密钥和管理员密码。
  - 重复执行会保留已有配置、密码与 Docker 数据卷，并重新构建服务。
  - 脚本要求 Docker Engine 与 Docker Compose 已安装。
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --admin-user)
      [[ $# -ge 2 ]] || fail "--admin-user 缺少参数"
      ADMIN_USER="$2"
      shift 2
      ;;
    --panel-port)
      [[ $# -ge 2 ]] || fail "--panel-port 缺少参数"
      PANEL_PORT_VALUE="$2"
      shift 2
      ;;
    --domain)
      [[ $# -ge 2 ]] || fail "--domain 缺少参数"
      DOMAIN="$2"
      shift 2
      ;;
    --bind-address)
      [[ $# -ge 2 ]] || fail "--bind-address 缺少参数"
      BIND_ADDRESS_VALUE="$2"
      shift 2
      ;;
    --admin-password-file)
      [[ $# -ge 2 ]] || fail "--admin-password-file 缺少参数"
      PASSWORD_FILE="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      fail "未知选项：$1"
      ;;
  esac
done

[[ -f docker-compose.yml && -f Dockerfile ]] || fail "请在 Manage Your Node 项目根目录运行此脚本"

[[ "$ADMIN_USER" =~ ^[A-Za-z0-9._-]{1,64}$ ]] || fail "管理员用户名只能包含字母、数字、点、下划线和连字符，最多 64 个字符"

[[ "$PANEL_PORT_VALUE" =~ ^[0-9]+$ ]] || fail "面板端口必须是数字"
(( PANEL_PORT_VALUE >= 1 && PANEL_PORT_VALUE <= 65535 )) || fail "面板端口必须在 1 到 65535 之间"

if [[ -n "$DOMAIN" ]]; then
  [[ ${#DOMAIN} -le 253 ]] || fail "域名过长"
  IFS='.' read -r -a domain_labels <<< "$DOMAIN"
  (( ${#domain_labels[@]} >= 2 )) || fail "请输入完整域名，例如 panel.example.com"
  for label in "${domain_labels[@]}"; do
    [[ "$label" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] || fail "域名格式不正确：$DOMAIN"
  done
  DOMAIN="${DOMAIN,,}"
fi

if [[ -z "$BIND_ADDRESS_VALUE" ]]; then
  if [[ -n "$DOMAIN" ]]; then
    BIND_ADDRESS_VALUE="127.0.0.1"
  else
    BIND_ADDRESS_VALUE="0.0.0.0"
  fi
fi
[[ "$BIND_ADDRESS_VALUE" == "0.0.0.0" || "$BIND_ADDRESS_VALUE" == "127.0.0.1" ]] || fail "绑定地址只支持 0.0.0.0 或 127.0.0.1"

if [[ -n "$PASSWORD_FILE" ]]; then
  [[ -f "$PASSWORD_FILE" && -r "$PASSWORD_FILE" ]] || fail "管理员密码文件不存在或不可读：$PASSWORD_FILE"
fi

command -v docker >/dev/null 2>&1 || fail "未检测到 Docker。请先安装 Docker Engine 与 Compose 插件：https://docs.docker.com/engine/install/"

DOCKER=(docker)
if ! docker info >/dev/null 2>&1; then
  if command -v sudo >/dev/null 2>&1 && sudo -n docker info >/dev/null 2>&1; then
    DOCKER=(sudo docker)
  else
    fail "当前用户无法访问 Docker；请使用 sudo 运行，或把用户加入 docker 组"
  fi
fi

if "${DOCKER[@]}" compose version >/dev/null 2>&1; then
  COMPOSE=("${DOCKER[@]}" compose)
elif command -v docker-compose >/dev/null 2>&1; then
  if [[ "${DOCKER[0]}" == "sudo" ]]; then
    COMPOSE=(sudo docker-compose)
  else
    COMPOSE=(docker-compose)
  fi
else
  fail "未检测到 Docker Compose 插件"
fi

random_hex() {
  local byte_count="$1"
  command -v od >/dev/null 2>&1 || fail "生成安全随机密钥需要 od 命令"
  od -An -N "$byte_count" -tx1 /dev/urandom | tr -d ' \n'
}

mkdir -p secrets
chmod 700 secrets

if [[ ! -s secrets/app_secret.txt ]]; then
  random_hex 48 > secrets/app_secret.txt
  chmod 600 secrets/app_secret.txt
  info "已生成应用主密钥"
fi

GENERATED_PASSWORD=""
if [[ ! -s secrets/admin_password.txt ]]; then
  if [[ -n "$PASSWORD_FILE" ]]; then
    ADMIN_PASSWORD_VALUE="$(<"$PASSWORD_FILE")"
    [[ "$ADMIN_PASSWORD_VALUE" != *$'\n'* ]] || fail "管理员密码不能包含换行符"
    (( ${#ADMIN_PASSWORD_VALUE} >= 12 )) || fail "管理员密码至少需要 12 个字符"
  else
    ADMIN_PASSWORD_VALUE="$(random_hex 18)"
    GENERATED_PASSWORD="$ADMIN_PASSWORD_VALUE"
  fi
  printf '%s' "$ADMIN_PASSWORD_VALUE" > secrets/admin_password.txt
  chmod 600 secrets/admin_password.txt
  PASSWORD_CREATED=1
  info "已生成管理员密码"
fi

APP_SECRET_VALUE="$(<secrets/app_secret.txt)"
ADMIN_PASSWORD_CHECK="$(<secrets/admin_password.txt)"
[[ "$APP_SECRET_VALUE" != *$'\n'* && "$ADMIN_PASSWORD_CHECK" != *$'\n'* ]] || fail "密钥文件不能包含换行符"
(( ${#APP_SECRET_VALUE} >= 16 )) || fail "应用主密钥至少需要 16 个字符"
(( ${#ADMIN_PASSWORD_CHECK} >= 12 )) || fail "管理员密码至少需要 12 个字符"
[[ "$APP_SECRET_VALUE" != "$ADMIN_PASSWORD_CHECK" ]] || fail "管理员密码不能与应用主密钥相同"

if [[ ! -f .env ]]; then
  PUBLIC_ORIGIN_VALUE=""
  ALLOWED_HOSTS_VALUE=""
  SESSION_COOKIE_SECURE_VALUE="0"
  if [[ -n "$DOMAIN" ]]; then
    PUBLIC_ORIGIN_VALUE="https://$DOMAIN"
    ALLOWED_HOSTS_VALUE="$DOMAIN"
    SESSION_COOKIE_SECURE_VALUE="1"
  fi
  cat > .env <<EOF
ADMIN_USERNAME=$ADMIN_USER
PANEL_PORT=$PANEL_PORT_VALUE
BIND_ADDRESS=$BIND_ADDRESS_VALUE
PUBLIC_ORIGIN=$PUBLIC_ORIGIN_VALUE
ALLOWED_HOSTS=$ALLOWED_HOSTS_VALUE
SESSION_COOKIE_SECURE=$SESSION_COOKIE_SECURE_VALUE
SESSION_HOURS=12
SUBSCRIPTION_RATE_LIMIT=120
REALITY_CANDIDATES=
REALITY_DEST=www.yahoo.com:443
REALITY_SNI=
TRUST_X_FORWARDED_FOR=0
TRUSTED_PROXY_IPS=127.0.0.1,::1
EOF
  chmod 600 .env
  info "已写入 .env"
else
  info "检测到现有 .env，将保留原配置"
fi

"${COMPOSE[@]}" config >/dev/null
info "正在构建并启动服务"
"${COMPOSE[@]}" up --build -d

info "正在等待健康检查"
READY=0
for _ in {1..45}; do
  if "${COMPOSE[@]}" exec -T manage-your-node python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/api/health/ready', timeout=2).read()" >/dev/null 2>&1; then
    READY=1
    break
  fi
  sleep 2
done

if (( READY != 1 )); then
  "${COMPOSE[@]}" ps >&2 || true
  fail "服务未在预期时间内就绪；请运行 docker compose logs 查看原因"
fi

if [[ -f .env ]]; then
  ACTIVE_PORT="$(sed -n 's/^PANEL_PORT=//p' .env | tail -n 1)"
  ACTIVE_BIND="$(sed -n 's/^BIND_ADDRESS=//p' .env | tail -n 1)"
  ACTIVE_ORIGIN="$(sed -n 's/^PUBLIC_ORIGIN=//p' .env | tail -n 1)"
  ACTIVE_USER="$(sed -n 's/^ADMIN_USERNAME=//p' .env | tail -n 1)"
fi
ACTIVE_PORT="${ACTIVE_PORT:-8787}"
ACTIVE_BIND="${ACTIVE_BIND:-0.0.0.0}"
ACTIVE_USER="${ACTIVE_USER:-admin}"

if [[ -n "${ACTIVE_ORIGIN:-}" ]]; then
  ACCESS_URL="$ACTIVE_ORIGIN"
elif [[ "$ACTIVE_BIND" == "127.0.0.1" ]]; then
  ACCESS_URL="http://127.0.0.1:$ACTIVE_PORT"
else
  HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"
  ACCESS_URL="http://${HOST_IP:-服务器IP}:$ACTIVE_PORT"
fi

printf '\n'
info "部署完成"
printf '访问地址：%s\n' "$ACCESS_URL"
printf '管理员：%s\n' "$ACTIVE_USER"
if (( PASSWORD_CREATED == 1 )) && [[ -n "$GENERATED_PASSWORD" ]]; then
  printf '初始密码：%s\n' "$GENERATED_PASSWORD"
  printf '请立即登录并把密码保存到安全的密码管理器。\n'
else
  printf '管理员密码：沿用 secrets/admin_password.txt 中的现有值\n'
fi
printf '查看日志：%s logs -f\n' "${COMPOSE[*]}"
