import base64
import json
import shlex
from typing import Any

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


SINGBOX_VERSION = "1.13.14"
SINGBOX_SHA256 = {
    "386": "4d1c66260dfcb2120fde6c1c5ad125ce0f94769843c34aab4eef53c8d3bf3ae9",
    "amd64": "f48703461a15476951ac4967cdad339d986f4b8096b4eb3ff0829a500502d697",
    "arm64": "4742df6a4314e8ecc41736849fca6d73b8f9e91b6e8b06ee794ff17ba180579e",
    "armv5": "e4c3f2b0196300be47cc70dbe1943abf0c9c30573ec40446d9f0b4bd7fdd2949",
    "armv6": "035e4fee4e0598018b7c30f879c9e36f42c65c6942061c0dc5b3feda6000812a",
    "armv7": "e01a58d28512b1447ab6156017afdeeaa306169a95d27abc00e112599e4ae46c",
    "s390x": "94d720f3d7973c3aacf3267b11a2d70b7216088d1a9099bc44c8ec82ffdc5ed0",
}
SINGBOX_ROOT = "/opt/manage-node/singbox"
SINGBOX_BIN = f"{SINGBOX_ROOT}/bin/sing-box"


def shell_quote(value: str | int) -> str:
    return shlex.quote(str(value))


def anytls_service_name(deployment_id: str) -> str:
    """Deterministic systemd unit name for a deployment's sing-box service."""
    return f"myn-anytls-{deployment_id}"


def singbox_install_dir(service_name: str) -> str:
    return f"{SINGBOX_ROOT}/{service_name}"


def singbox_cert_paths(service_name: str) -> tuple[str, str]:
    """Return ``(certificate_path, key_path)`` for a self-signed AnyTLS service."""
    install_dir = singbox_install_dir(service_name)
    return f"{install_dir}/cert.pem", f"{install_dir}/key.pem"


def singbox_acme_dir(service_name: str) -> str:
    return f"{singbox_install_dir(service_name)}/acme"


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


def _sudo_preamble() -> str:
    return """if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required when SSH user is not root" >&2
    exit 20
  fi
  SUDO="sudo"
fi"""


def _singbox_arch_case() -> str:
    arms = " ".join(
        f"{arch}) SB_SHA={SINGBOX_SHA256[arch]} ;;"
        for arch in ("386", "amd64", "arm64", "armv5", "armv6", "armv7", "s390x")
    )
    return arms


def _encode_config(config: dict[str, Any]) -> str:
    return base64.b64encode(
        json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def native_singbox_script(
    service_name: str,
    config: dict[str, Any],
    proxy_port: int,
    server_host: str,
    self_signed: bool,
    acme_http_port: int = 80,
) -> str:
    """Install a pinned sing-box binary and start a per-deployment AnyTLS service.

    The full sing-box configuration is rendered by the service layer and pushed
    here base64-encoded. Self-signed deployments generate a local certificate at
    the paths referenced by the config; ACME deployments let sing-box obtain a
    real certificate on first start.
    """
    install_dir = singbox_install_dir(service_name)
    cert_path, key_path = singbox_cert_paths(service_name)
    config_b64 = _encode_config(config)
    self_signed_block = (
        f"""if [ ! -s {shell_quote(cert_path)} ] || [ ! -s {shell_quote(key_path)} ]; then
  log "generating self-signed certificate"
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate a self-signed AnyTLS certificate" >&2
    exit 51
  fi
  $SUDO openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \\
    -keyout {shell_quote(key_path)} -out {shell_quote(cert_path)} \\
    -subj "/CN={server_host}" >/dev/null 2>&1
  $SUDO chmod 0600 {shell_quote(key_path)}
fi
"""
        if self_signed
        else ""
    )
    acme_port_rules = (
        _firewall_rules(acme_http_port, allow_udp=False) if not self_signed else ""
    )
    return f"""#!/usr/bin/env bash
set -Eeuo pipefail

log() {{
  printf '[myn] %s\\n' "$1"
}}

{_sudo_preamble()}

log "checking host"
uname -a

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

case "$(uname -m)" in
  x86_64|amd64) SB_ARCH=amd64 ;;
  i386|i686) SB_ARCH=386 ;;
  aarch64|arm64) SB_ARCH=arm64 ;;
  armv5*) SB_ARCH=armv5 ;;
  armv6*) SB_ARCH=armv6 ;;
  armv7*) SB_ARCH=armv7 ;;
  s390x) SB_ARCH=s390x ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 50 ;;
esac
case "$SB_ARCH" in {_singbox_arch_case()} *) echo unsupported >&2; exit 50 ;; esac

SB_VERSION={shell_quote(SINGBOX_VERSION)}
SB_TARBALL="sing-box-$SB_VERSION-linux-$SB_ARCH.tar.gz"
SB_URL="https://github.com/SagerNet/sing-box/releases/download/v$SB_VERSION/$SB_TARBALL"
$SUDO install -d -m 0755 /opt/manage-node/downloads {SINGBOX_ROOT}/bin {shell_quote(install_dir)}
DL="/opt/manage-node/downloads/$SB_TARBALL"

if [ ! -x {SINGBOX_BIN} ] || ! {SINGBOX_BIN} version 2>/dev/null | grep -q "$SB_VERSION"; then
  log "downloading pinned sing-box $SB_VERSION ($SB_ARCH)"
  $SUDO curl --fail --location --silent --show-error --proto '=https' --tlsv1.2 "$SB_URL" -o "$DL"
  printf '%s  %s\\n' "$SB_SHA" "$DL" | $SUDO sha256sum --check --status
  TMP_EXTRACT="$($SUDO mktemp -d)"
  $SUDO tar -xzf "$DL" -C "$TMP_EXTRACT"
  $SUDO install -m 0755 "$TMP_EXTRACT/sing-box-$SB_VERSION-linux-$SB_ARCH/sing-box" {SINGBOX_BIN}
  $SUDO rm -rf "$TMP_EXTRACT"
fi
log "sing-box version: $({SINGBOX_BIN} version | head -n1)"

{self_signed_block}
CONFIG_FILE={shell_quote(install_dir)}/config.json
CONFIG_B64={shell_quote(config_b64)}
printf '%s' "$CONFIG_B64" | base64 -d | $SUDO tee "$CONFIG_FILE" >/dev/null
$SUDO chmod 0600 "$CONFIG_FILE"

if ! $SUDO {SINGBOX_BIN} check -c "$CONFIG_FILE" >/tmp/{service_name}.check.log 2>&1; then
  cat /tmp/{service_name}.check.log >&2 || true
  exit 52
fi

UNIT_FILE="/etc/systemd/system/{service_name}.service"
$SUDO tee "$UNIT_FILE" >/dev/null <<EOF
[Unit]
Description=Manage Your Node AnyTLS service {service_name}
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory={install_dir}
ExecStart={SINGBOX_BIN} run -c $CONFIG_FILE
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

$SUDO systemctl daemon-reload
$SUDO systemctl enable {service_name} >/dev/null
$SUDO systemctl restart {service_name}
sleep 1
$SUDO systemctl is-active --quiet {service_name}

{_firewall_rules(proxy_port, allow_udp=False)}
{acme_port_rules}
log "sing-box AnyTLS service {service_name} is active"
echo "__MYN_RESULT_BEGIN__"
echo "MYN_ANYTLS_SERVICE={service_name}"
echo "__MYN_RESULT_END__"
"""


def singbox_config_push_script(
    service_name: str,
    config: dict[str, Any],
) -> str:
    """Rewrite an existing AnyTLS service's config and restart it."""
    install_dir = singbox_install_dir(service_name)
    config_b64 = _encode_config(config)
    return f"""#!/usr/bin/env bash
set -Eeuo pipefail

log() {{
  printf '[myn] %s\\n' "$1"
}}

{_sudo_preamble()}

if [ ! -x {SINGBOX_BIN} ]; then
  echo "sing-box binary is missing on this host" >&2
  exit 53
fi
CONFIG_FILE={shell_quote(install_dir)}/config.json
TMP_CONFIG={shell_quote(install_dir)}/config.tmp.json
CONFIG_B64={shell_quote(config_b64)}
$SUDO install -d -m 0755 {shell_quote(install_dir)}
printf '%s' "$CONFIG_B64" | base64 -d | $SUDO tee "$TMP_CONFIG" >/dev/null
$SUDO chmod 0600 "$TMP_CONFIG"
if ! $SUDO {SINGBOX_BIN} check -c "$TMP_CONFIG" >/tmp/{service_name}.check.log 2>&1; then
  cat /tmp/{service_name}.check.log >&2 || true
  exit 52
fi
$SUDO mv "$TMP_CONFIG" "$CONFIG_FILE"
$SUDO systemctl restart {service_name}
sleep 1
$SUDO systemctl is-active --quiet {service_name}
log "AnyTLS service {service_name} reloaded"
"""


def singbox_uninstall_script(service_name: str) -> str:
    install_dir = singbox_install_dir(service_name)
    return f"""#!/usr/bin/env bash
set -u
{_sudo_preamble_lenient()}
SERVICE_NAME={shell_quote(service_name)}
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"
echo "Stopping $SERVICE_NAME"
$SUDO systemctl stop "$SERVICE_NAME" 2>/dev/null || true
$SUDO systemctl disable "$SERVICE_NAME" 2>/dev/null || true
$SUDO rm -f "$UNIT_FILE"
$SUDO rm -rf {shell_quote(install_dir)}
$SUDO systemctl daemon-reload 2>/dev/null || true
$SUDO systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
echo "Removed $SERVICE_NAME"
"""


def _sudo_preamble_lenient() -> str:
    return """if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi"""


def _firewall_rules(port: int, allow_udp: bool = False) -> str:
    udp_ufw = (
        f"  $SUDO ufw allow {shell_quote(port)}/udp >/dev/null 2>&1 || true\n"
        if allow_udp
        else ""
    )
    udp_fw = (
        f"  $SUDO firewall-cmd --permanent --add-port={shell_quote(port)}/udp "
        ">/dev/null 2>&1 || true\n"
        if allow_udp
        else ""
    )
    return f"""if command -v ufw >/dev/null 2>&1; then
  $SUDO ufw allow {shell_quote(port)}/tcp >/dev/null 2>&1 || true
{udp_ufw.rstrip()}
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  $SUDO firewall-cmd --permanent --add-port={shell_quote(port)}/tcp >/dev/null 2>&1 || true
{udp_fw.rstrip()}
  $SUDO firewall-cmd --reload >/dev/null 2>&1 || true
fi"""
