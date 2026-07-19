import base64
import ipaddress
import os
import re
import secrets
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs, quote, unquote, urlparse

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
MAX_JOB_LOG_ENTRIES = 2000
MAX_JOB_LOG_LINE = 4096
MIHOMO_SUBSCRIPTION_FORMATS = {"clash", "mihomo", "yaml"}
BASE64_SUBSCRIPTION_FORMATS = {"base64", "v2ray"}


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
        _mihomo_proxy_from_vless(link, index, used_names)
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


def _redact_native_install_log(line: str, panel_password: str) -> str:
    """Remove credentials emitted by both plain and colorized 3x-ui output."""
    clean = str(line)
    if panel_password:
        clean = clean.replace(panel_password, "[redacted]")
    clean = re.sub(
        r"(?i)(XUI_(?:PASSWORD|API_TOKEN)=)[^\s\x1b]+",
        r"\1[redacted]",
        clean,
    )
    clean = re.sub(
        r"(?i)((?:API\s+Token|Password)\s*:\s*)[^\s\x1b]+",
        r"\1[redacted]",
        clean,
    )
    return clean


def _normalize_client_share_link_host(link: str, host: str) -> str:
    """Replace 3x-ui's loopback link host with the managed server address."""
    parsed = urlparse(link)
    if parsed.scheme.lower() != "vless" or not parsed.hostname:
        return link
    userinfo, separator, _ = parsed.netloc.rpartition("@")
    prefix = f"{userinfo}@" if separator else ""
    try:
        port = parsed.port
    except ValueError:
        return link
    suffix = f":{port}" if port else ""
    return parsed._replace(netloc=f"{prefix}{url_host(host)}{suffix}").geturl()


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


def traffic_reset_days_field(payload: dict[str, Any], default: int = 0) -> int:
    raw = payload.get("trafficResetDays", default)
    if raw is None or (isinstance(raw, str) and not raw.strip()):
        raw = default
    if isinstance(raw, bool) or (isinstance(raw, float) and not raw.is_integer()):
        raise ValueError("trafficResetDays must be a whole number")
    try:
        days = int(raw)
    except (TypeError, ValueError) as exc:
        raise ValueError("trafficResetDays must be a whole number") from exc
    if not 0 <= days <= 3650:
        raise ValueError("trafficResetDays must be between 0 and 3650")
    return days


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
