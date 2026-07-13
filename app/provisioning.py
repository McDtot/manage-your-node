import shlex

XUI_RELEASE_VERSION = "v3.2.0"
XUI_INSTALL_REF = "4e928a1ce0945a6e956aa63365034ec24d2b1387"
XUI_INSTALL_SHA256 = "f2f8caa11778d811a037fe84b20ebf5e2547fd665afe6fe16d69f1cd9f3fe88f"
XUI_RELEASE_SHA256 = {
    "386": "e35d63ad14ddc421331d2831f5c32701fe4eb0039d93547c36543788ae60807a",
    "amd64": "bc0c7c5d8deb77fea194e0b40a69e17951fe7f4109d465855c2a76259d83eb69",
    "arm64": "8506c294b8b538e6dcae56d17e1af3bba5e349a9db5767ee49ec6a8bc32bf441",
    "armv5": "a37cc541559c27352f8ff1df52cced9fb74725520e41e1b01730067bd6c6109a",
    "armv6": "156b31ee0f862517e63af2a5b40f470b9186e840463abb11f3628ed264335ca5",
    "armv7": "abf5417150226b437252e6991864f58614db0f53ab82ef7126690155a53a9f77",
    "s390x": "847f9cbfa88989732bd04843407e80a64e04275de3c2d71a112cbe5661afb59b",
}


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

log "downloading verified 3x-ui installer {XUI_INSTALL_REF}"
$SUDO install -d -m 0755 /opt/manage-node/downloads
INSTALLER=/opt/manage-node/downloads/3x-ui-install-{XUI_INSTALL_REF}.sh
$SUDO curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 \\
  https://raw.githubusercontent.com/MHSanaei/3x-ui/{XUI_INSTALL_REF}/install.sh \\
  -o "$INSTALLER"
printf '%s  %s\\n' {shell_quote(XUI_INSTALL_SHA256)} "$INSTALLER" | $SUDO sha256sum --check --status
$SUDO chmod 0700 "$INSTALLER"
$SUDO sed -i 's#/MHSanaei/3x-ui/main/#/MHSanaei/3x-ui/{XUI_INSTALL_REF}/#g' "$INSTALLER"
$SUDO sed -i "/    local xui_script_temp=/i\\    case \\$(arch) in 386) MYN_RELEASE_SHA={XUI_RELEASE_SHA256['386']} ;; amd64) MYN_RELEASE_SHA={XUI_RELEASE_SHA256['amd64']} ;; arm64) MYN_RELEASE_SHA={XUI_RELEASE_SHA256['arm64']} ;; armv5) MYN_RELEASE_SHA={XUI_RELEASE_SHA256['armv5']} ;; armv6) MYN_RELEASE_SHA={XUI_RELEASE_SHA256['armv6']} ;; armv7) MYN_RELEASE_SHA={XUI_RELEASE_SHA256['armv7']} ;; s390x) MYN_RELEASE_SHA={XUI_RELEASE_SHA256['s390x']} ;; *) echo unsupported-architecture >&2; exit 1 ;; esac; echo \\$MYN_RELEASE_SHA'  '\\${{xui_folder}}-linux-\\$(arch).tar.gz | sha256sum --check --status || exit 1" "$INSTALLER"

log "installing pinned 3x-ui release {XUI_RELEASE_VERSION}"
$SUDO env \\
  XUI_NONINTERACTIVE=1 \\
  XUI_PANEL_PORT={shell_quote(panel_port)} \\
  XUI_WEB_BASE_PATH={shell_quote(web_base_path)} \\
  XUI_USERNAME={shell_quote(panel_username)} \\
  XUI_PASSWORD={shell_quote(panel_password)} \\
  XUI_SSL_MODE=none \\
  XUI_SERVER_IP={shell_quote(server_host)} \\
  bash "$INSTALLER" {shell_quote(XUI_RELEASE_VERSION)}

log "binding 3x-ui panel to SSH-only loopback"
if ! $SUDO test -x /usr/local/x-ui/x-ui; then
  echo "3x-ui binary not found; refusing to leave the HTTP panel exposed" >&2
  exit 22
fi
$SUDO /usr/local/x-ui/x-ui setting -listenIP 127.0.0.1 >/dev/null

log "checking x-ui service"
if command -v systemctl >/dev/null 2>&1; then
  $SUDO systemctl enable --now x-ui >/dev/null 2>&1
  $SUDO systemctl restart x-ui
  $SUDO systemctl --no-pager --full status x-ui || true
fi

log "reading install result"
echo "__MYN_RESULT_BEGIN__"
if $SUDO test -f /etc/x-ui/install-result.env; then
  $SUDO grep -E '^(XUI_PANEL_PORT|XUI_WEB_BASE_PATH|XUI_USERNAME|XUI_PASSWORD|XUI_API_TOKEN)=' /etc/x-ui/install-result.env || true
else
  echo "XUI_PANEL_PORT={shell_quote(panel_port)}"
  echo "XUI_WEB_BASE_PATH={shell_quote(web_base_path)}"
  echo "XUI_USERNAME={shell_quote(panel_username)}"
fi
echo "__MYN_RESULT_END__"
"""
