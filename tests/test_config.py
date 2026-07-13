import pytest

from app.config import ConfigError, load_settings

SECRET_VARS = [
    "APP_SECRET",
    "ADMIN_PASSWORD",
    "ADMIN_USERNAME",
    "APP_ALLOW_INSECURE",
    "SESSION_COOKIE_SECURE",
    "TRUST_X_FORWARDED_FOR",
    "TRUSTED_PROXY_IPS",
    "PUBLIC_ORIGIN",
    "ALLOWED_HOSTS",
    "APP_SECRET_FILE",
    "ADMIN_PASSWORD_FILE",
    "HOST",
    "PORT",
    "SESSION_HOURS",
    "MAX_BODY_BYTES",
    "SUBSCRIPTION_RATE_LIMIT",
]


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    for var in SECRET_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))


def test_production_requires_secrets(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    with pytest.raises(ConfigError):
        load_settings()


def test_production_with_good_secrets(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("APP_SECRET", "a-sufficiently-long-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-password")
    monkeypatch.setenv("PUBLIC_ORIGIN", "https://panel.example.com")
    settings = load_settings()
    assert settings.allow_insecure is False
    assert settings.cookie_secure is True
    assert settings.public_access_warning is False
    assert settings.admin_password == "a-strong-password"
    assert "panel.example.com" in settings.allowed_hosts


def test_short_secret_rejected(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("APP_SECRET", "short")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-password")
    with pytest.raises(ConfigError):
        load_settings()


def test_local_dev_is_lenient(monkeypatch):
    monkeypatch.setenv("HOST", "127.0.0.1")
    settings = load_settings()
    assert settings.allow_insecure is True
    assert settings.cookie_secure is False
    # Falls back to APP_SECRET when ADMIN_PASSWORD is unset in dev mode.
    assert settings.admin_password == settings.app_secret
    # X-Forwarded-For is ignored unless explicitly enabled.
    assert settings.trust_x_forwarded_for is False


def test_trust_x_forwarded_for_opt_in(monkeypatch):
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setenv("TRUST_X_FORWARDED_FOR", "1")
    settings = load_settings()
    assert settings.trust_x_forwarded_for is True


def test_insecure_mode_cannot_bind_publicly(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("APP_ALLOW_INSECURE", "1")
    with pytest.raises(ConfigError):
        load_settings()


def test_public_http_still_requires_strong_secrets(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    with pytest.raises(ConfigError):
        load_settings()


def test_public_http_is_allowed_by_default_and_shows_warning(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("APP_SECRET", "a-sufficiently-long-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-password")
    settings = load_settings()
    assert settings.allow_insecure is False
    assert settings.public_access_warning is True
    assert settings.cookie_secure is False
    assert "*" in settings.allowed_hosts


def test_http_origin_and_explicit_host_allowlist_still_show_warning(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("APP_SECRET", "a-sufficiently-long-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-password")
    monkeypatch.setenv("PUBLIC_ORIGIN", "http://203.0.113.10:8787")
    monkeypatch.setenv("ALLOWED_HOSTS", "203.0.113.10")
    settings = load_settings()
    assert settings.public_access_warning is True
    assert settings.cookie_secure is False
    assert "203.0.113.10" in settings.allowed_hosts


def test_https_ip_still_shows_missing_domain_warning(monkeypatch):
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("APP_SECRET", "a-sufficiently-long-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-password")
    monkeypatch.setenv("PUBLIC_ORIGIN", "https://203.0.113.10")
    settings = load_settings()
    assert settings.public_access_warning is True
    assert settings.cookie_secure is True


def test_file_backed_secrets(monkeypatch, tmp_path):
    secret_file = tmp_path / "app-secret"
    password_file = tmp_path / "admin-password"
    secret_file.write_text("a-file-backed-application-secret", encoding="utf-8")
    password_file.write_text("a-file-backed-password", encoding="utf-8")
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PUBLIC_ORIGIN", "https://panel.example.com")
    monkeypatch.setenv("APP_SECRET_FILE", str(secret_file))
    monkeypatch.setenv("ADMIN_PASSWORD_FILE", str(password_file))
    settings = load_settings()
    assert settings.app_secret == "a-file-backed-application-secret"
    assert settings.admin_password == "a-file-backed-password"
