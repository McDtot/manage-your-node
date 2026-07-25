"""Pure sing-box configuration builders.

Every managed node runs sing-box and the panel owns the whole configuration:
it renders the complete JSON locally, pushes it over SSH and restarts the unit.
Keeping these builders free of database, SSH and secret-box access makes the
protocol mapping directly unit-testable.

Callers pass plaintext secrets in, so the service layer stays responsible for
decrypting whatever it stores.
"""

import base64
import secrets
from typing import Any

from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

from ..provisioning import node_service_name, singbox_acme_dir, singbox_cert_paths
from .helpers import (
    CHAIN_PROTOCOL_HYSTERIA2,
    CHAIN_PROTOCOL_SHADOWSOCKS_2022,
    CHAIN_PROTOCOL_VLESS_REALITY,
    CHAIN_PROTOCOL_VMESS,
    CHAIN_SS_METHOD,
    DEPLOYMENT_PROTOCOL_ANYTLS,
    DEPLOYMENT_PROTOCOL_HYSTERIA2,
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
    DEPLOYMENT_PROTOCOL_VLESS_REALITY,
    DEPLOYMENT_PROTOCOL_VMESS,
    DEPLOYMENT_SS_METHOD,
    _deployment_reality_settings,
    parse_reality_destination,
)

VLESS_FLOW = "xtls-rprx-vision"
NODE_INBOUND_TAG = "node-in"
CHAIN_INBOUND_TAG = "myn-chain-in"
CHAIN_OUTBOUND_TAG = "myn-chain-next"
DIRECT_OUTBOUND_TAG = "direct"
UTLS_FINGERPRINT = "chrome"
LISTEN_ANY = "::"


def _log_section() -> dict[str, Any]:
    return {"level": "warn", "timestamp": True}


def _raw_base64(raw: bytes) -> str:
    """Encode raw key bytes the way sing-box reads REALITY keys."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def new_reality_keypair() -> tuple[str, str]:
    """Return ``(private_key, public_key)`` for a REALITY inbound.

    Produces the same raw X25519 keys in base64 RawURLEncoding that
    ``sing-box generate reality-keypair`` prints, so no remote round-trip is
    needed to provision a node.
    """
    private = x25519.X25519PrivateKey.generate()
    raw_private = private.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_public = private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    return _raw_base64(raw_private), _raw_base64(raw_public)


def new_short_id() -> str:
    return secrets.token_hex(4)


def _handshake(target: str) -> tuple[str, int]:
    """Split a validated ``host:port`` REALITY target for sing-box."""
    normalized, host = parse_reality_destination(target, "realityDest")
    return host, int(normalized.rsplit(":", 1)[1])


def _reality_tls(
    reality_source: dict[str, Any],
    private_key: str,
    short_id: str,
) -> dict[str, Any]:
    target, server_name = _deployment_reality_settings(reality_source)
    handshake_server, handshake_port = _handshake(target)
    return {
        "enabled": True,
        "server_name": server_name,
        "reality": {
            "enabled": True,
            "handshake": {
                "server": handshake_server,
                "server_port": handshake_port,
            },
            "private_key": private_key,
            "short_id": [short_id],
        },
    }


def _tls_from_domain(
    deployment: dict[str, Any],
    *,
    service_name: str | None = None,
    alpn: list[str] | None = None,
) -> dict[str, Any]:
    """TLS for AnyTLS / Hysteria2 / VMess: ACME when a domain is set, else self-signed."""
    resolved_service = service_name or node_service_name(deployment["id"])
    domain = str(deployment.get("anytls_domain") or "").strip()
    if domain:
        tls: dict[str, Any] = {
            "enabled": True,
            "server_name": domain,
            "acme": {
                "domain": [domain],
                "data_directory": singbox_acme_dir(resolved_service),
            },
        }
    else:
        certificate_path, key_path = singbox_cert_paths(resolved_service)
        tls = {
            "enabled": True,
            "certificate_path": certificate_path,
            "key_path": key_path,
        }
    if alpn:
        tls["alpn"] = alpn
    return tls


def _self_signed_tls(service_name: str, *, alpn: list[str] | None = None) -> dict[str, Any]:
    certificate_path, key_path = singbox_cert_paths(service_name)
    tls: dict[str, Any] = {
        "enabled": True,
        "certificate_path": certificate_path,
        "key_path": key_path,
    }
    if alpn:
        tls["alpn"] = alpn
    return tls


def vless_reality_inbound(
    deployment: dict[str, Any],
    users: list[dict[str, str]],
) -> dict[str, Any]:
    """VLESS + REALITY inbound. Each user needs ``name`` and ``uuid``."""
    private_key = str(deployment.get("reality_private_key") or "").strip()
    if not private_key:
        raise ValueError("REALITY private key is missing for this deployment")
    short_id = str(deployment.get("reality_short_id") or "").strip()
    if not short_id:
        raise ValueError("REALITY short id is missing for this deployment")
    return {
        "type": "vless",
        "tag": NODE_INBOUND_TAG,
        "listen": LISTEN_ANY,
        "listen_port": int(deployment["proxy_port"]),
        "users": [
            {"name": user["name"], "uuid": user["uuid"], "flow": VLESS_FLOW}
            for user in users
        ],
        "tls": _reality_tls(deployment, private_key, short_id),
    }


def shadowsocks_inbound(
    deployment: dict[str, Any],
    users: list[dict[str, str]],
) -> dict[str, Any]:
    """Multi-user Shadowsocks 2022 inbound. Each user needs ``name`` and ``password``."""
    server_password = str(deployment.get("ss_password") or "").strip()
    if not server_password:
        raise ValueError("Shadowsocks server password is missing for this deployment")
    return {
        "type": "shadowsocks",
        "tag": NODE_INBOUND_TAG,
        "listen": LISTEN_ANY,
        "listen_port": int(deployment["proxy_port"]),
        "method": deployment.get("ss_method") or DEPLOYMENT_SS_METHOD,
        "password": server_password,
        "users": [
            {"name": user["name"], "password": user["password"]} for user in users
        ],
    }


def anytls_inbound(
    deployment: dict[str, Any],
    users: list[dict[str, str]],
) -> dict[str, Any]:
    """AnyTLS inbound. Each user needs ``name`` and ``password``.

    Without a domain the node serves a locally generated self-signed
    certificate; with one, sing-box obtains and renews a real certificate over
    ACME.
    """
    return {
        "type": "anytls",
        "tag": NODE_INBOUND_TAG,
        "listen": LISTEN_ANY,
        "listen_port": int(deployment["proxy_port"]),
        "users": [
            {"name": user["name"], "password": user["password"]} for user in users
        ],
        "tls": _tls_from_domain(deployment),
    }


def hysteria2_inbound(
    deployment: dict[str, Any],
    users: list[dict[str, str]],
) -> dict[str, Any]:
    """Hysteria2 inbound. Each user needs ``name`` and ``password``."""
    obfs_password = str(deployment.get("hy2_obfs_password") or "").strip()
    if not obfs_password:
        raise ValueError("Hysteria2 obfuscation password is missing for this deployment")
    return {
        "type": "hysteria2",
        "tag": NODE_INBOUND_TAG,
        "listen": LISTEN_ANY,
        "listen_port": int(deployment["proxy_port"]),
        "users": [
            {"name": user["name"], "password": user["password"]} for user in users
        ],
        "obfs": {"type": "salamander", "password": obfs_password},
        "tls": _tls_from_domain(deployment, alpn=["h3"]),
    }


def vmess_inbound(
    deployment: dict[str, Any],
    users: list[dict[str, str]],
) -> dict[str, Any]:
    """VMess inbound with TLS. Each user needs ``name`` and ``uuid``."""
    return {
        "type": "vmess",
        "tag": NODE_INBOUND_TAG,
        "listen": LISTEN_ANY,
        "listen_port": int(deployment["proxy_port"]),
        "users": [
            {"name": user["name"], "uuid": user["uuid"], "alterId": 0}
            for user in users
        ],
        "tls": _tls_from_domain(deployment),
    }


_NODE_INBOUND_BUILDERS = {
    DEPLOYMENT_PROTOCOL_VLESS_REALITY: vless_reality_inbound,
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022: shadowsocks_inbound,
    DEPLOYMENT_PROTOCOL_ANYTLS: anytls_inbound,
    DEPLOYMENT_PROTOCOL_HYSTERIA2: hysteria2_inbound,
    DEPLOYMENT_PROTOCOL_VMESS: vmess_inbound,
}


def build_node_config(
    deployment: dict[str, Any],
    users: list[dict[str, str]],
) -> dict[str, Any]:
    """Render the complete sing-box configuration for a node deployment."""
    protocol = str(deployment.get("protocol") or "")
    builder = _NODE_INBOUND_BUILDERS.get(protocol)
    if builder is None:
        raise ValueError(f"unsupported deployment protocol: {protocol}")
    return {
        "log": _log_section(),
        "inbounds": [builder(deployment, users)],
        "outbounds": [{"type": "direct", "tag": DIRECT_OUTBOUND_TAG}],
        "route": {"final": DIRECT_OUTBOUND_TAG},
    }


def chain_inbound(node: dict[str, Any]) -> dict[str, Any]:
    """Inbound accepting the previous hop (or the end user on the entry node)."""
    protocol = node.get("inbound_protocol") or CHAIN_PROTOCOL_VLESS_REALITY
    if protocol == CHAIN_PROTOCOL_SHADOWSOCKS_2022:
        password = str(node.get("ss_password") or "").strip()
        if not password:
            raise ValueError(f"Shadowsocks password is missing for {node['server_name']}")
        return {
            "type": "shadowsocks",
            "tag": CHAIN_INBOUND_TAG,
            "listen": LISTEN_ANY,
            "listen_port": int(node["inbound_port"]),
            "method": node.get("ss_method") or CHAIN_SS_METHOD,
            "password": password,
        }
    if protocol == CHAIN_PROTOCOL_HYSTERIA2:
        password = str(node.get("hy2_password") or "").strip()
        if not password:
            raise ValueError(f"Hysteria2 password is missing for {node['server_name']}")
        service_name = str(node.get("remote_service_name") or "").strip()
        if not service_name:
            raise ValueError(
                f"Hysteria2 service name is missing for {node['server_name']}"
            )
        return {
            "type": "hysteria2",
            "tag": CHAIN_INBOUND_TAG,
            "listen": LISTEN_ANY,
            "listen_port": int(node["inbound_port"]),
            "users": [
                {
                    "name": f"myn-chain-{node['position']}",
                    "password": password,
                }
            ],
            "tls": _self_signed_tls(service_name, alpn=["h3"]),
        }
    if protocol == CHAIN_PROTOCOL_VMESS:
        client_uuid = str(node.get("node_client_uuid") or "").strip()
        if not client_uuid:
            raise ValueError(f"VMess UUID is missing for {node['server_name']}")
        return {
            "type": "vmess",
            "tag": CHAIN_INBOUND_TAG,
            "listen": LISTEN_ANY,
            "listen_port": int(node["inbound_port"]),
            "users": [
                {
                    "name": f"myn-chain-{node['position']}",
                    "uuid": client_uuid,
                    "alterId": 0,
                }
            ],
        }
    if protocol != CHAIN_PROTOCOL_VLESS_REALITY:
        raise ValueError(f"unsupported chain protocol on {node['server_name']}: {protocol}")
    private_key = str(node.get("private_key") or "").strip()
    if not private_key:
        raise ValueError(f"REALITY private key is missing for {node['server_name']}")
    return {
        "type": "vless",
        "tag": CHAIN_INBOUND_TAG,
        "listen": LISTEN_ANY,
        "listen_port": int(node["inbound_port"]),
        "users": [
            {
                "name": f"myn-chain-{node['position']}",
                "uuid": node["node_client_uuid"],
                "flow": VLESS_FLOW,
            }
        ],
        "tls": _reality_tls(node, private_key, node["short_id"]),
    }


def chain_outbound(next_node: dict[str, Any] | None) -> dict[str, Any]:
    """Outbound dialing the next hop, or a direct exit for the last node."""
    if not next_node:
        return {"type": "direct", "tag": DIRECT_OUTBOUND_TAG}
    protocol = next_node.get("inbound_protocol") or CHAIN_PROTOCOL_VLESS_REALITY
    if protocol == CHAIN_PROTOCOL_SHADOWSOCKS_2022:
        password = str(next_node.get("ss_password") or "").strip()
        if not password:
            raise ValueError(
                f"Shadowsocks password is missing for {next_node['server_name']}"
            )
        return {
            "type": "shadowsocks",
            "tag": CHAIN_OUTBOUND_TAG,
            "server": next_node["host"],
            "server_port": int(next_node["inbound_port"]),
            "method": next_node.get("ss_method") or CHAIN_SS_METHOD,
            "password": password,
        }
    if protocol == CHAIN_PROTOCOL_HYSTERIA2:
        password = str(next_node.get("hy2_password") or "").strip()
        if not password:
            raise ValueError(
                f"Hysteria2 password is missing for {next_node['server_name']}"
            )
        return {
            "type": "hysteria2",
            "tag": CHAIN_OUTBOUND_TAG,
            "server": next_node["host"],
            "server_port": int(next_node["inbound_port"]),
            "password": password,
            "tls": {
                "enabled": True,
                "insecure": True,
                "alpn": ["h3"],
            },
        }
    if protocol == CHAIN_PROTOCOL_VMESS:
        client_uuid = str(next_node.get("node_client_uuid") or "").strip()
        if not client_uuid:
            raise ValueError(f"VMess UUID is missing for {next_node['server_name']}")
        return {
            "type": "vmess",
            "tag": CHAIN_OUTBOUND_TAG,
            "server": next_node["host"],
            "server_port": int(next_node["inbound_port"]),
            "uuid": client_uuid,
            "security": "auto",
            "alter_id": 0,
        }
    if protocol != CHAIN_PROTOCOL_VLESS_REALITY:
        raise ValueError(
            f"unsupported chain protocol on {next_node['server_name']}: {protocol}"
        )
    _, server_name = _deployment_reality_settings(next_node)
    return {
        "type": "vless",
        "tag": CHAIN_OUTBOUND_TAG,
        "server": next_node["host"],
        "server_port": int(next_node["inbound_port"]),
        "uuid": next_node["node_client_uuid"],
        "flow": VLESS_FLOW,
        "tls": {
            "enabled": True,
            "server_name": server_name,
            "utls": {"enabled": True, "fingerprint": UTLS_FINGERPRINT},
            "reality": {
                "enabled": True,
                "public_key": next_node["public_key"],
                "short_id": next_node["short_id"],
            },
        },
    }


def build_chain_config(
    node: dict[str, Any],
    next_node: dict[str, Any] | None,
) -> dict[str, Any]:
    """Render the sing-box configuration for one hop of a proxy chain."""
    outbound = chain_outbound(next_node)
    return {
        "log": _log_section(),
        "inbounds": [chain_inbound(node)],
        "outbounds": [outbound],
        "route": {"final": outbound["tag"]},
    }
