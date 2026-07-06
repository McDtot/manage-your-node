import shlex


def shell_quote(value: str | int) -> str:
    return shlex.quote(str(value))


def native_3xui_script(
    panel_port: int,
    panel_path: str,
    panel_username: str,
    panel_password: str,
    server_host: str,
) -> str:
    web_base_path = panel_path.strip("/")
    return f"""#!/usr/bin/env bash
set -Eeuo pipefail

log() {{
  printf '[myn] %s\\n' "$1"
}}

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required when SSH user is not root" >&2
    exit 20
  fi
  SUDO="sudo"
fi

log "checking host"
uname -a
if [ -f /etc/os-release ]; then
  . /etc/os-release
  echo "os=$ID version=$VERSION_ID"
fi

log "checking curl"
if ! command -v curl >/dev/null 2>&1; then
  if command -v apt-get >/dev/null 2>&1; then
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get update
    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y curl ca-certificates
  elif command -v dnf >/dev/null 2>&1; then
    $SUDO dnf install -y curl ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    $SUDO yum install -y curl ca-certificates
  else
    echo "cannot install curl automatically on this OS" >&2
    exit 21
  fi
fi

log "running official 3x-ui unattended installer"
$SUDO env \\
  XUI_NONINTERACTIVE=1 \\
  XUI_PANEL_PORT={shell_quote(panel_port)} \\
  XUI_WEB_BASE_PATH={shell_quote(web_base_path)} \\
  XUI_USERNAME={shell_quote(panel_username)} \\
  XUI_PASSWORD={shell_quote(panel_password)} \\
  XUI_SSL_MODE=none \\
  XUI_SERVER_IP={shell_quote(server_host)} \\
  bash -c 'curl -Ls https://raw.githubusercontent.com/MHSanaei/3x-ui/master/install.sh | bash'

log "checking x-ui service"
if command -v systemctl >/dev/null 2>&1; then
  $SUDO systemctl enable --now x-ui >/dev/null 2>&1 || true
  $SUDO systemctl --no-pager --full status x-ui || true
fi

log "reading install result"
echo "__MYN_RESULT_BEGIN__"
if $SUDO test -f /etc/x-ui/install-result.env; then
  $SUDO cat /etc/x-ui/install-result.env
else
  echo "XUI_PANEL_PORT={shell_quote(panel_port)}"
  echo "XUI_WEB_BASE_PATH={shell_quote(web_base_path)}"
  echo "XUI_USERNAME={shell_quote(panel_username)}"
  echo "XUI_PASSWORD={shell_quote(panel_password)}"
fi
echo "__MYN_RESULT_END__"
"""
