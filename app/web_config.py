import threading
from urllib.parse import urlparse

from .config import (
    ConfigError,
    Settings,
    _has_public_domain,
    _is_loopback,
    _normalize_origin,
)
from .database import Database


PUBLIC_ORIGIN_KEY = "public_origin"


class WebConfig:
    """Runtime Web configuration persisted in the application database."""

    def __init__(self, settings: Settings, db: Database):
        self.settings = settings
        self.db = db
        self._lock = threading.RLock()
        self._temporary_origins: set[str] = set()
        row = db.query_one(
            "SELECT value FROM app_metadata WHERE key = ?",
            (PUBLIC_ORIGIN_KEY,),
        )
        self._public_origin_override = row["value"] if row else ""

    @property
    def public_origin(self) -> str:
        with self._lock:
            return self._public_origin_override or self.settings.public_origin

    @property
    def public_access_warning(self) -> bool:
        parsed = urlparse(self.public_origin)
        return not _is_loopback(self.settings.host) and not (
            parsed.scheme == "https" and _has_public_domain(parsed.hostname)
        )

    @property
    def cookie_secure(self) -> bool:
        if not self._public_origin_override:
            return self.settings.cookie_secure
        return not self.settings.allow_insecure and urlparse(self.public_origin).scheme == "https"

    def allowed_hosts(self) -> tuple[str, ...]:
        if self.public_access_warning:
            return self.settings.allowed_hosts
        configured = [host for host in self.settings.allowed_hosts if host != "*"]
        origins = [self.public_origin, *self.temporary_origins()]
        origin_hosts = [
            hostname
            for origin in origins
            if (hostname := urlparse(origin).hostname)
        ]
        return tuple(
            dict.fromkeys(
                [
                    *origin_hosts,
                    "127.0.0.1",
                    "localhost",
                    "::1",
                    "[::1]",
                    *configured,
                ]
            )
        )

    def temporary_origins(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._temporary_origins)

    def origin_is_allowed(self, origin: str, request_origin: str) -> bool:
        if self.public_access_warning:
            return origin == request_origin
        with self._lock:
            return origin in {self.public_origin, *self._temporary_origins}

    def as_dict(self) -> dict[str, object]:
        with self._lock:
            override = self._public_origin_override
        host = self.settings.host
        rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
        automatic = f"http://{rendered_host}:{self.settings.port}"
        source = "webui" if override else (
            "automatic" if self.settings.public_origin == automatic else "environment"
        )
        return {
            "publicOrigin": self.public_origin,
            "configuredPublicOrigin": override,
            "source": source,
            "publicAccessWarning": self.public_access_warning,
            "cookieSecure": self.cookie_secure,
        }

    def update_public_origin(self, value: object, current_origin: str = "") -> dict[str, object]:
        raw = str(value or "").strip()
        normalized = ""
        if raw:
            if self.settings.allow_insecure:
                raise ValueError(
                    "当前处于本地开发模式；请先设置 APP_ALLOW_INSECURE=0 和生产密钥"
                )
            try:
                normalized = _normalize_origin(raw)
            except ConfigError as exc:
                raise ValueError(str(exc)) from exc
            parsed = urlparse(normalized)
            if parsed.scheme != "https" or not _has_public_domain(parsed.hostname):
                raise ValueError("外部访问地址必须是使用 HTTPS 的完整公网域名")

        with self._lock:
            previous_origin = self.public_origin
            if normalized:
                self.db.execute(
                    """
                    INSERT INTO app_metadata (key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                    ON CONFLICT(key) DO UPDATE SET
                        value = excluded.value,
                        updated_at = excluded.updated_at
                    """,
                    (PUBLIC_ORIGIN_KEY, normalized),
                )
            else:
                self.db.execute(
                    "DELETE FROM app_metadata WHERE key = ?",
                    (PUBLIC_ORIGIN_KEY,),
                )
            self._public_origin_override = normalized
            for fallback in (previous_origin, current_origin.rstrip("/")):
                if fallback and fallback != self.public_origin:
                    self._temporary_origins.add(fallback)
        return self.as_dict()
