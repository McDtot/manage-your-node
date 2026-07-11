import os
from dataclasses import dataclass
from pathlib import Path

DEV_SECRET = "development-only-secret"
MIN_SECRET_LENGTH = 16
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
    max_body_bytes: int
    trust_x_forwarded_for: bool


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _is_loopback(host: str) -> bool:
    return host in {"127.0.0.1", "::1", "localhost"}


def load_settings() -> Settings:
    base_dir = Path(__file__).resolve().parent
    data_dir = Path(os.getenv("APP_DATA_DIR", "data")).resolve()
    data_dir.mkdir(parents=True, exist_ok=True)

    host = os.getenv("HOST", "127.0.0.1")
    app_secret = os.getenv("APP_SECRET", DEV_SECRET)
    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_password_env = os.getenv("ADMIN_PASSWORD")

    # Insecure mode is only meant for local development. It is auto-enabled when
    # binding to loopback, and can be forced with APP_ALLOW_INSECURE=1.
    allow_insecure = _env_bool("APP_ALLOW_INSECURE", _is_loopback(host))

    if not allow_insecure:
        _require_production_secrets(app_secret, admin_password_env)

    admin_password = admin_password_env or app_secret

    cookie_secure = _env_bool("SESSION_COOKIE_SECURE", not _is_loopback(host))
    # Only honor X-Forwarded-For when explicitly enabled (i.e. behind a
    # stripping reverse proxy). Otherwise clients can spoof the header and
    # bypass login lockout.
    trust_x_forwarded_for = _env_bool("TRUST_X_FORWARDED_FOR", False)

    return Settings(
        data_dir=data_dir,
        db_path=data_dir / "manage_node.db",
        static_dir=base_dir / "static",
        host=host,
        port=int(os.getenv("PORT", "8787")),
        app_secret=app_secret,
        admin_username=admin_username,
        admin_password=admin_password,
        session_seconds=int(float(os.getenv("SESSION_HOURS", "12")) * 60 * 60),
        cookie_secure=cookie_secure,
        allow_insecure=allow_insecure,
        max_body_bytes=int(os.getenv("MAX_BODY_BYTES", str(MAX_BODY_BYTES))),
        trust_x_forwarded_for=trust_x_forwarded_for,
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
    if problems:
        details = "\n  - ".join(problems)
        raise ConfigError(
            "Refusing to start with an insecure configuration:\n  - "
            + details
            + "\n\nSet the variables above, or export APP_ALLOW_INSECURE=1 for local development only."
        )
