import pytest

from app.config import ConfigError, load_settings

SECRET_VARS = [
    "APP_SECRET",
    "ADMIN_PASSWORD",
    "ADMIN_USERNAME",
    "APP_ALLOW_INSECURE",
    "SESSION_COOKIE_SECURE",
    "TRUST_X_FORWARDED_FOR",
    "HOST",
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
    settings = load_settings()
    assert settings.allow_insecure is False
    assert settings.cookie_secure is True
    assert settings.admin_password == "a-strong-password"


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
