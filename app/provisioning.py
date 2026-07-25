import base64
import json
import re
import shlex
from typing import Any

SINGBOX_VERSION = "1.13.14"
TLS_CERT_SHA256_MARKER = "__MYN_TLS_CERT_SHA256__="
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


def node_service_name(deployment_id: str) -> str:
    """Deterministic systemd unit name for a deployment's sing-box service."""
    return f"myn-node-{deployment_id}"


def chain_service_name(chain_id: str, position: int) -> str:
    """Deterministic systemd unit name for one hop of a proxy chain."""
    return f"myn-chain-{chain_id}-{position}"


def singbox_install_dir(service_name: str) -> str:
    return f"{SINGBOX_ROOT}/{service_name}"


def singbox_cert_paths(service_name: str) -> tuple[str, str]:
    """Return ``(certificate_path, key_path)`` for a self-signed TLS service."""
    install_dir = singbox_install_dir(service_name)
    return f"{install_dir}/cert.pem", f"{install_dir}/key.pem"


def singbox_acme_dir(service_name: str) -> str:
    return f"{singbox_install_dir(service_name)}/acme"


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


def _sudo_preamble_lenient() -> str:
    return """if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi"""


def _singbox_arch_case() -> str:
    return " ".join(
        f"{arch}) SB_SHA={SINGBOX_SHA256[arch]} ;;"
        for arch in ("386", "amd64", "arm64", "armv5", "armv6", "armv7", "s390x")
    )


def _encode_config(config: dict[str, Any]) -> str:
    return base64.b64encode(
        json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")


def tls_cert_sha256_from_output(lines: list[str]) -> str:
    """Return the normalized SHA-256 certificate fingerprint emitted by the installer."""
    pattern = re.compile(r"^(?:[0-9A-F]{2}:){31}[0-9A-F]{2}$")
    for line in reversed(lines):
        if not line.startswith(TLS_CERT_SHA256_MARKER):
            continue
        fingerprint = line.removeprefix(TLS_CERT_SHA256_MARKER).strip().upper()
        if not pattern.fullmatch(fingerprint):
            raise ValueError("remote installer returned an invalid TLS certificate fingerprint")
        return fingerprint
    return ""


def singbox_install_script(
    service_name: str,
    config: dict[str, Any],
    proxy_port: int,
    server_host: str,
    allow_udp: bool = False,
    self_signed_cert: bool = False,
    acme_http_port: int = 0,
) -> str:
    """Install a pinned sing-box binary and start one service for it.

    The binary is shared by every service on the host; each service owns a
    directory holding its rendered configuration and, for self-signed TLS, its
    certificate. ``acme_http_port`` opens the HTTP-01 challenge port and should
    be left at ``0`` unless the configuration requests ACME.
    """
    install_dir = singbox_install_dir(service_name)
    cert_path, key_path = singbox_cert_paths(service_name)
    config_b64 = _encode_config(config)
    self_signed_block = (
        f"""if [ ! -s {shell_quote(cert_path)} ] || [ ! -s {shell_quote(key_path)} ]; then
  log "generating self-signed certificate"
  if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate a self-signed certificate" >&2
    exit 51
  fi
  $SUDO openssl req -x509 -newkey rsa:2048 -sha256 -days 3650 -nodes \\
    -keyout {shell_quote(key_path)} -out {shell_quote(cert_path)} \\
    -subj "/CN={server_host}" >/dev/null 2>&1
  $SUDO chmod 0600 {shell_quote(key_path)}
fi
CERT_FINGERPRINT="$($SUDO openssl x509 -in {shell_quote(cert_path)} -noout -fingerprint -sha256)"
CERT_FINGERPRINT="${{CERT_FINGERPRINT#*=}}"
printf '{TLS_CERT_SHA256_MARKER}%s\\n' "$CERT_FINGERPRINT"
"""
        if self_signed_cert
        else ""
    )
    acme_port_rules = (
        _firewall_rules(acme_http_port, allow_udp=False) if acme_http_port else ""
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
Description=Manage Your Node sing-box service {service_name}
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

{_firewall_rules(proxy_port, allow_udp=allow_udp)}
{acme_port_rules}
log "sing-box service {service_name} is active"
"""


def singbox_config_push_script(
    service_name: str,
    config: dict[str, Any],
) -> str:
    """Rewrite an existing service's configuration and restart it."""
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
log "sing-box service {service_name} reloaded"
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
