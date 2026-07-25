import base64
import ipaddress
import os
import secrets
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlencode, urlparse

import yaml

DEFAULT_REALITY_DEST = "www.yahoo.com:443"
DEFAULT_REALITY_CANDIDATES = (
    DEFAULT_REALITY_DEST,
    "www.apple.com:443",
    "www.amazon.com:443",
)
CHAIN_PROTOCOL_VLESS_REALITY = "vless_reality"
CHAIN_PROTOCOL_SHADOWSOCKS_2022 = "shadowsocks_2022"
CHAIN_PROTOCOLS = {
    CHAIN_PROTOCOL_VLESS_REALITY,
    CHAIN_PROTOCOL_SHADOWSOCKS_2022,
}
CHAIN_SS_METHOD = "2022-blake3-aes-256-gcm"
DEPLOYMENT_PROTOCOL_VLESS_REALITY = "VLESS + REALITY"
DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022 = "Shadowsocks 2022"
DEPLOYMENT_PROTOCOL_ANYTLS = "AnyTLS"
DEPLOYMENT_PROTOCOLS = {
    DEPLOYMENT_PROTOCOL_VLESS_REALITY,
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
    DEPLOYMENT_PROTOCOL_ANYTLS,
}
DEPLOYMENT_SS_METHOD = CHAIN_SS_METHOD
MAX_JOB_LOG_ENTRIES = 2000
MAX_JOB_LOG_LINE = 4096
MIHOMO_SUBSCRIPTION_FORMATS = {"clash", "mihomo", "yaml"}
BASE64_SUBSCRIPTION_FORMATS = {"base64", "v2ray"}
ACME_HTTP_PORT = 80
# Users are enforced by rendering: a disabled or expired user is simply left
# out of the node configuration and of every subscription.
ACTIVE_CLIENT_CONDITION = (
    "c.enabled = 1 AND (c.expires_at = '' OR c.expires_at >= date('now'))"
)


def _mihomo_proxy_from_vless(
    share_link: str,
    index: int,
    used_names: set[str],
) -> dict[str, Any]:
    parsed = urlparse(share_link)
    if parsed.scheme.lower() != "vless":
        raise ValueError("Mihomo subscriptions currently support VLESS links only")

    client_uuid = unquote(parsed.username or "").strip()
    server = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid VLESS subscription port") from exc
    if not client_uuid or not server or port is None:
        raise ValueError("invalid VLESS subscription link")

    query = {
        key: values[-1]
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
        if values
    }
    if query.get("security", "").lower() != "reality":
        raise ValueError("Mihomo subscriptions currently require VLESS Reality links")
    public_key = query.get("pbk", "").strip()
    short_id = query.get("sid", "").strip()
    if not public_key:
        raise ValueError("VLESS Reality public key is missing")

    base_name = unquote(parsed.fragment).strip() or f"节点 {index}"
    name = base_name
    suffix = 2
    while name in used_names or name in {"AUTO", "DIRECT", "PROXY", "REJECT"}:
        name = f"{base_name} {suffix}"
        suffix += 1
    used_names.add(name)

    proxy: dict[str, Any] = {
        "name": name,
        "type": "vless",
        "server": server,
        "port": port,
        "uuid": client_uuid,
        "udp": True,
    }
    flow = query.get("flow", "").strip()
    if flow:
        proxy["flow"] = flow
    proxy["packet-encoding"] = "xudp"
    proxy["tls"] = True
    server_name = query.get("sni", "").strip()
    if server_name:
        proxy["servername"] = server_name
    fingerprint = query.get("fp", "").strip()
    if fingerprint:
        proxy["client-fingerprint"] = fingerprint
    reality_opts = {"public-key": public_key}
    if short_id:
        reality_opts["short-id"] = short_id
    proxy["reality-opts"] = reality_opts
    proxy["encryption"] = ""
    proxy["network"] = "tcp" if query.get("type", "tcp") in {"raw", "tcp"} else query["type"]
    return proxy


def vless_reality_share_link(
    client_uuid: str,
    host: str,
    port: int,
    name: str,
    public_key: str,
    short_id: str,
    sni: str,
    fingerprint: str = "chrome",
) -> str:
    """Build a ``vless://`` REALITY link for a node client or a chain entry.

    ``pbk`` and ``sid`` are mandatory for Mihomo subscriptions, so callers pass
    the REALITY public key and short id persisted alongside the inbound.
    """
    params = {
        "security": "reality",
        "type": "tcp",
        "flow": "xtls-rprx-vision",
        "pbk": public_key,
        "fp": fingerprint,
        "sni": sni,
        "sid": short_id,
        "spx": "/",
    }
    tag = quote(name)
    return f"vless://{client_uuid}@{url_host(host)}:{port}?{urlencode(params)}#{tag}"


def new_ss2022_password() -> str:
    """Return a base64-encoded 32-byte PSK for 2022-blake3-aes-256-gcm."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def new_anytls_password() -> str:
    """Return a base64-encoded 32-byte password for an AnyTLS user."""
    return base64.b64encode(secrets.token_bytes(32)).decode("ascii")


def anytls_share_link(
    password: str,
    host: str,
    port: int,
    name: str,
    sni: str = "",
    insecure: bool = True,
) -> str:
    """Build an ``anytls://`` share link understood by sing-box/mihomo clients.

    Self-signed deployments advertise ``insecure=1`` so imported clients skip
    certificate verification without any manual toggling.
    """
    params: dict[str, str] = {}
    if insecure:
        params["insecure"] = "1"
    if sni:
        params["sni"] = sni
    query = f"?{urlencode(params)}" if params else ""
    tag = quote(name)
    return (
        f"anytls://{quote(password, safe='')}@{url_host(host)}:{port}{query}#{tag}"
    )


def _mihomo_proxy_from_anytls(
    share_link: str,
    index: int,
    used_names: set[str],
) -> dict[str, Any]:
    parsed = urlparse(share_link)
    password = unquote(parsed.password or parsed.username or "").strip()
    server = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid AnyTLS subscription port") from exc
    if not password or not server or port is None:
        raise ValueError("invalid AnyTLS subscription link")

    query = {
        key: values[-1]
        for key, values in parse_qs(parsed.query, keep_blank_values=True).items()
        if values
    }

    base_name = unquote(parsed.fragment).strip() or f"节点 {index}"
    name = base_name
    suffix = 2
    while name in used_names or name in {"AUTO", "DIRECT", "PROXY", "REJECT"}:
        name = f"{base_name} {suffix}"
        suffix += 1
    used_names.add(name)

    proxy: dict[str, Any] = {
        "name": name,
        "type": "anytls",
        "server": server,
        "port": port,
        "password": password,
        "udp": True,
    }
    sni = query.get("sni", "").strip()
    if sni:
        proxy["sni"] = sni
    insecure = query.get("insecure", "").strip() in {"1", "true", "True"}
    if insecure:
        proxy["skip-cert-verify"] = True
    return proxy


def ss_share_link(
    method: str,
    server_password: str,
    user_password: str,
    host: str,
    port: int,
    name: str,
) -> str:
    """Build a SIP002-style Shadowsocks 2022 share link.

    Multi-user SS2022 uses ``serverPSK:userPSK`` as the client password, and the
    userinfo section carries ``method:serverPSK:userPSK`` base64-encoded, which
    is the layout mainstream clients expect.
    """
    userinfo = f"{method}:{server_password}:{user_password}"
    encoded = base64.b64encode(userinfo.encode("utf-8")).decode("ascii")
    tag = quote(name)
    return f"ss://{encoded}@{url_host(host)}:{port}#{tag}"


def _decode_ss_userinfo(share_link: str) -> tuple[str, str]:
    """Return ``(method, password)`` from a Shadowsocks share link userinfo."""
    parsed = urlparse(share_link)
    userinfo = parsed.username or ""
    if parsed.password is not None:
        userinfo = f"{parsed.username or ''}:{parsed.password}"
    userinfo = unquote(userinfo)
    if ":" not in userinfo:
        try:
            padded = userinfo + "=" * (-len(userinfo) % 4)
            userinfo = base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ValueError("invalid Shadowsocks subscription link") from exc
    method, separator, password = userinfo.partition(":")
    if not separator or not method or not password:
        raise ValueError("invalid Shadowsocks subscription link")
    return method, password


def _mihomo_proxy_from_ss(
    share_link: str,
    index: int,
    used_names: set[str],
) -> dict[str, Any]:
    parsed = urlparse(share_link)
    method, password = _decode_ss_userinfo(share_link)
    server = parsed.hostname
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid Shadowsocks subscription port") from exc
    if not server or port is None:
        raise ValueError("invalid Shadowsocks subscription link")

    base_name = unquote(parsed.fragment).strip() or f"节点 {index}"
    name = base_name
    suffix = 2
    while name in used_names or name in {"AUTO", "DIRECT", "PROXY", "REJECT"}:
        name = f"{base_name} {suffix}"
        suffix += 1
    used_names.add(name)

    return {
        "name": name,
        "type": "ss",
        "server": server,
        "port": port,
        "cipher": method,
        "password": password,
        "udp": True,
    }


def _mihomo_proxy_from_link(
    share_link: str,
    index: int,
    used_names: set[str],
) -> dict[str, Any]:
    scheme = urlparse(share_link).scheme.lower()
    if scheme == "ss":
        return _mihomo_proxy_from_ss(share_link, index, used_names)
    if scheme == "anytls":
        return _mihomo_proxy_from_anytls(share_link, index, used_names)
    return _mihomo_proxy_from_vless(share_link, index, used_names)


def _render_subscription_links(share_links: list[str], output_format: str = "base64") -> str:
    normalized = str(output_format or "base64").strip().lower()
    links = [str(link).strip() for link in share_links if str(link).strip()]
    if normalized in BASE64_SUBSCRIPTION_FORMATS:
        raw = "\n".join(links)
        return base64.b64encode(raw.encode("utf-8")).decode("ascii")
    if normalized not in MIHOMO_SUBSCRIPTION_FORMATS:
        raise ValueError("unsupported subscription format; use mihomo or base64")

    used_names: set[str] = set()
    proxies = [
        _mihomo_proxy_from_link(link, index, used_names)
        for index, link in enumerate(links, start=1)
    ]
    proxy_names = [proxy["name"] for proxy in proxies]
    config: dict[str, Any] = {
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": [],
        "rules": [],
    }
    if proxies:
        config["proxy-groups"] = [
            {
                "name": "PROXY",
                "type": "select",
                "proxies": ["AUTO", "DIRECT", *proxy_names],
            },
            {
                "name": "AUTO",
                "type": "url-test",
                "url": "https://www.gstatic.com/generate_204",
                "interval": 300,
                "tolerance": 50,
                "proxies": proxy_names,
            },
        ]
        config["rules"] = ["MATCH,PROXY"]
    return yaml.safe_dump(config, allow_unicode=True, sort_keys=False)


def _share_link_with_display_name(share_link: str, display_name: str) -> str:
    """Return a share link with a subscription-specific fragment/remark."""
    link = str(share_link).strip()
    name = str(display_name).strip()
    if not link or not name:
        return link
    parsed = urlparse(link)
    return parsed._replace(fragment=quote(name, safe="")).geturl()


def reality_dest() -> str:
    """REALITY handshake target (``host:port``). Configurable via REALITY_DEST."""
    return (os.getenv("REALITY_DEST") or DEFAULT_REALITY_DEST).strip()


def parse_reality_destination(value: str, key: str = "realityDest") -> tuple[str, str]:
    """Validate a REALITY target and return normalized ``host:port`` plus host."""
    raw = str(value or "").strip()
    if not raw or "://" in raw or any(char.isspace() for char in raw):
        raise ValueError(f"{key} must use host:port format")
    try:
        parsed = urlparse(f"//{raw}")
        host = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"{key} must use host:port format") from exc
    if (
        not host
        or port is None
        or not 1 <= port <= 65535
        or parsed.username
        or parsed.password
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{key} must use host:port format")
    normalized_host = host_field({"host": host})
    return f"{url_host(normalized_host)}:{port}", normalized_host


def reality_candidates() -> list[tuple[str, str]]:
    """Return configured auto-selection candidates as ``(target, SNI)`` pairs."""
    configured = (os.getenv("REALITY_CANDIDATES") or "").strip()
    configured_dest = (os.getenv("REALITY_DEST") or "").strip()
    configured_sni = (os.getenv("REALITY_SNI") or "").strip()
    if configured:
        raw_candidates = [item.strip() for item in configured.split(",") if item.strip()]
    elif configured_dest and (
        configured_dest != DEFAULT_REALITY_DEST or configured_sni
    ):
        raw_candidates = [reality_dest()]
    else:
        raw_candidates = list(DEFAULT_REALITY_CANDIDATES)
    if not raw_candidates:
        raise ValueError("REALITY_CANDIDATES must contain at least one host:port target")

    pairs: list[tuple[str, str]] = []
    seen: set[str] = set()
    for index, raw in enumerate(raw_candidates):
        target, target_host = parse_reality_destination(raw, "REALITY_CANDIDATES")
        sni = target_host
        if index == 0 and not configured and configured_sni:
            sni = host_field({"sni": os.environ["REALITY_SNI"]}, "sni")
        if target in seen:
            continue
        pairs.append((target, sni))
        seen.add(target)
    return pairs


def reality_server_name() -> str:
    """SNI advertised for REALITY. Defaults to the host of REALITY_DEST."""
    override = (os.getenv("REALITY_SNI") or "").strip()
    if override:
        return override
    return parse_reality_destination(reality_dest(), "REALITY_DEST")[1]


def _deployment_reality_settings(deployment: dict[str, Any]) -> tuple[str, str]:
    stored_target = str(deployment.get("reality_dest") or "").strip()
    target, target_host = parse_reality_destination(
        stored_target or reality_dest(),
        "realityDest",
    )
    stored_sni = str(deployment.get("reality_sni") or "").strip()
    if stored_sni:
        return target, stored_sni
    return target, target_host if stored_target else reality_server_name()


def now_iso() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(10)}"


def require_text(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def int_field(payload: dict[str, Any], key: str, default: int) -> int:
    value = payload.get(key, default)
    if value is None or (isinstance(value, str) and not value.strip()):
        value = default
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number") from exc


def boolean_field(payload: dict[str, Any], key: str, default: bool = False) -> bool:
    raw = payload.get(key, default)
    if isinstance(raw, bool):
        return raw
    if raw in (0, 1):
        return bool(raw)
    raise ValueError(f"{key} must be a boolean")


def port_field(payload: dict[str, Any], key: str, default: int) -> int:
    value = int_field(payload, key, default)
    if not 1 <= value <= 65535:
        raise ValueError(f"{key} must be between 1 and 65535")
    return value


def host_field(payload: dict[str, Any], key: str = "host") -> str:
    value = require_text(payload, key).rstrip(".")
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError:
        pass
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"{key} must be a valid IP address or hostname") from exc
    labels = ascii_host.split(".")
    if (
        len(ascii_host) > 253
        or not labels
        or any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isalnum() or char == "-" for char in label)
            for label in labels
        )
    ):
        raise ValueError(f"{key} must be a valid IP address or hostname")
    return ascii_host.lower()


def url_host(value: str) -> str:
    return f"[{value}]" if ":" in value and not value.startswith("[") else value
