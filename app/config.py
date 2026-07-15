import os
from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import Path
from urllib.parse import urlparse

DEV_SECRET = "development-only-secret"
MIN_SECRET_LENGTH = 16
MIN_PASSWORD_LENGTH = 12
MAX_BODY_BYTES = 1024 * 1024  # 1 MiB cap for request bodies


class ConfigError(RuntimeError):
    """Raised when the runtime configuration is unsafe for the selected mode."""


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    db_path: Path
    static_dir: Path
    host: str
    port: int
    app_secret: str
    admin_username: str
    admin_password: str
    session_seconds: int
    cookie_secure: bool
    allow_insecure: bool
    public_access_warning: bool
    max_body_bytes: int
    trust_x_forwarded_for: bool
    trusted_proxy_ips: str
    public_origin: str
    allowed_hosts: tuple[str, ...]
    subscription_requests_per_minute: int


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def _has_public_domain(hostname: str | None) -> bool:
    if not hostname or hostname == "localhost" or "." not in hostname:
        return False
    try:
        ip_address(hostname)
    except ValueError:
        return True
    return False


def _secret_value(name: str, default: str | None = None) -> str | None:
    """Read a secret from NAME_FILE first, then NAME.

    File-backed secrets work with Docker/Podman secrets and systemd credentials
    without exposing the value in the container environment.
    """
    file_name = os.getenv(f"{name}_FILE", "").strip()
    if file_name:
        try:
            return Path(file_name).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ConfigError(f"Could not read {name}_FILE: {exc}") from exc
    return os.getenv(name, default)


def _normalize_origin(value: str) -> str:
    origin = value.strip().rstrip("/")
    parsed = urlparse(origin)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.netloc
        or parsed.path
        or parsed.params
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
    ):
        raise ConfigError("PUBLIC_ORIGIN must be an origin such as https://nodes.example.com")
    hostname = parsed.hostname
    if not hostname:
        raise ConfigError("PUBLIC_ORIGIN must be an origin such as https://nodes.example.com")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ConfigError("PUBLIC_ORIGIN contains an invalid port") from exc

    try:
        normalized_host = str(ip_address(hostname))
    except ValueError:
        try:
            normalized_host = hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ConfigError("PUBLIC_ORIGIN contains an invalid hostname") from exc
        labels = normalized_host.split(".")
        if any(
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not all(char.isalnum() or char == "-" for char in label)
            for label in labels
        ):
            raise ConfigError("PUBLIC_ORIGIN contains an invalid hostname")

    rendered_host = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    rendered_port = f":{port}" if port is not None and port != default_port else ""
    return f"{parsed.scheme.lower()}://{rendered_host}{rendered_port}"


def load_settings() -> Settings:
    base_dir = Path(__file__).resolve().parent
    data_dir = Path(os.getenv("APP_DATA_DIR", "data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)

    host = os.getenv("HOST", "127.0.0.1")
    app_secret = _secret_value("APP_SECRET", DEV_SECRET) or DEV_SECRET
    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password_env = _secret_value("ADMIN_PASSWORD")

    # Local development may use built-in credentials. Public binding always
    # keeps the production secret checks, even when domain/TLS setup is deferred.
    allow_insecure = _env_bool("APP_ALLOW_INSECURE", _is_loopback(host))

    if allow_insecure and not _is_loopback(host):
        raise ConfigError(
            "APP_ALLOW_INSECURE may only be used while binding to a loopback address."
        )

    if not allow_insecure:
        _require_production_secrets(app_secret, admin_password_env)

    admin_password = admin_password_env or app_secret

    origin_env = os.getenv("PUBLIC_ORIGIN", "").strip()
    fallback_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    public_origin = (
        _normalize_origin(origin_env)
        if origin_env
        else f"http://{fallback_host}:{os.getenv('PORT', '8787')}"
    )
    parsed_origin = urlparse(public_origin)
    public_access_warning = not _is_loopback(host) and not (
        parsed_origin.scheme == "https" and _has_public_domain(parsed_origin.hostname)
    )

    cookie_secure = _env_bool(
        "SESSION_COOKIE_SECURE",
        parsed_origin.scheme == "https" and not allow_insecure,
    )
    if not allow_insecure and parsed_origin.scheme == "https" and not cookie_secure:
        raise ConfigError("SESSION_COOKIE_SECURE cannot be disabled when PUBLIC_ORIGIN uses HTTPS.")
    if cookie_secure and parsed_origin.scheme != "https":
        raise ConfigError("SESSION_COOKIE_SECURE requires an HTTPS PUBLIC_ORIGIN.")

    # Only honor X-Forwarded-For when explicitly enabled (i.e. behind a
    # stripping reverse proxy). Otherwise clients can spoof the header and
    # bypass login lockout.
    trust_x_forwarded_for = _env_bool("TRUST_X_FORWARDED_FOR", False)
    trusted_proxy_ips = os.getenv("TRUSTED_PROXY_IPS", "127.0.0.1,::1").strip()

    origin_host = urlparse(public_origin).hostname or host
    configured_hosts = [
        item.strip()
        for item in os.getenv("ALLOWED_HOSTS", "").split(",")
        if item.strip()
    ]
    if not configured_hosts and public_access_warning:
        configured_hosts = ["*"]
    if "*" in configured_hosts and not allow_insecure and not public_access_warning:
        raise ConfigError(
            "ALLOWED_HOSTS cannot contain '*' when a secure public domain is configured."
        )
    allowed_hosts = tuple(
        dict.fromkeys([origin_host, "127.0.0.1", "localhost", "[::1]", *configured_hosts])
    )

    try:
        port = int(os.getenv("PORT", "8787"))
        session_seconds = int(float(os.getenv("SESSION_HOURS", "12")) * 60 * 60)
        max_body_bytes = int(os.getenv("MAX_BODY_BYTES", str(MAX_BODY_BYTES)))
        subscription_requests_per_minute = int(os.getenv("SUBSCRIPTION_RATE_LIMIT", "120"))
    except ValueError as exc:
        raise ConfigError(
            "PORT, SESSION_HOURS, MAX_BODY_BYTES, and SUBSCRIPTION_RATE_LIMIT must be numeric."
        ) from exc
    if not 1 <= port <= 65535:
        raise ConfigError("PORT must be between 1 and 65535.")
    if not 300 <= session_seconds <= 7 * 24 * 60 * 60:
        raise ConfigError("SESSION_HOURS must be between 5 minutes and 7 days.")
    if not 1024 <= max_body_bytes <= 16 * 1024 * 1024:
        raise ConfigError("MAX_BODY_BYTES must be between 1 KiB and 16 MiB.")
    if not 10 <= subscription_requests_per_minute <= 10_000:
        raise ConfigError("SUBSCRIPTION_RATE_LIMIT must be between 10 and 10000.")

    return Settings(
        data_dir=data_dir,
        db_path=data_dir / "manage_node.db",
        static_dir=base_dir / "static",
        host=host,
        port=port,
        app_secret=app_secret,
        admin_username=admin_username,
        admin_password=admin_password,
        session_seconds=session_seconds,
        cookie_secure=cookie_secure,
        allow_insecure=allow_insecure,
        public_access_warning=public_access_warning,
        max_body_bytes=max_body_bytes,
        trust_x_forwarded_for=trust_x_forwarded_for,
        trusted_proxy_ips=trusted_proxy_ips,
        public_origin=public_origin,
        allowed_hosts=allowed_hosts,
        subscription_requests_per_minute=subscription_requests_per_minute,
    )


def _require_production_secrets(app_secret: str, admin_password_env: str | None) -> None:
    problems: list[str] = []
    if not app_secret or app_secret == DEV_SECRET:
        problems.append("APP_SECRET must be set to a strong, non-default value.")
    elif len(app_secret) < MIN_SECRET_LENGTH:
        problems.append(f"APP_SECRET must be at least {MIN_SECRET_LENGTH} characters.")
    if not admin_password_env:
        problems.append(
            "ADMIN_PASSWORD must be set explicitly (it no longer falls back to APP_SECRET)."
        )
    elif len(admin_password_env) < MIN_PASSWORD_LENGTH:
        problems.append(f"ADMIN_PASSWORD must be at least {MIN_PASSWORD_LENGTH} characters.")
    elif admin_password_env == app_secret:
        problems.append("ADMIN_PASSWORD must be different from APP_SECRET.")
    if problems:
        details = "\n  - ".join(problems)
        raise ConfigError(
            "Refusing to start with an insecure configuration:\n  - "
            + details
            + "\n\nSet the variables above, or export APP_ALLOW_INSECURE=1 for local development only."
        )
