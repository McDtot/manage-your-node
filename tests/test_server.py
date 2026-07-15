import base64

import yaml
from starlette.testclient import TestClient

from app.config import load_settings
from app.database import Database
from app.security import SecretBox
from app.server import create_app
from app.services import AppServices


def _client(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HOST", "127.0.0.1")
    monkeypatch.setenv("PORT", "8787")
    monkeypatch.setenv("APP_SECRET", "local-test-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "test-password")
    settings = load_settings()
    db = Database(settings.db_path)
    services = AppServices(db, SecretBox(settings.app_secret))
    app = create_app(settings=settings, db=db, services=services)
    return TestClient(app, base_url="http://127.0.0.1:8787"), db


def _login(client: TestClient) -> str:
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "test-password"},
        headers={"Origin": "http://127.0.0.1:8787"},
    )
    assert response.status_code == 200
    token = client.cookies.get("myn_csrf")
    assert token
    return token


def test_health_and_security_headers(monkeypatch, tmp_path):
    client, _db = _client(monkeypatch, tmp_path)
    response = client.get("/api/health/ready")
    assert response.status_code == 200
    assert response.json() == {"ok": True}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert "default-src 'self'" in response.headers["content-security-policy"]


def test_api_authentication_and_csrf(monkeypatch, tmp_path):
    client, db = _client(monkeypatch, tmp_path)
    assert client.get("/api/summary").status_code == 401
    csrf = _login(client)
    assert client.get("/api/summary").status_code == 200

    payload = {
        "name": "test-vps",
        "host": "192.0.2.10",
        "sshPort": 22,
        "sshUser": "deploy",
        "authType": "agent",
    }
    assert client.post("/api/servers", json=payload).status_code == 403
    response = client.post(
        "/api/servers",
        json=payload,
        headers={"X-CSRF-Token": csrf, "Origin": "http://127.0.0.1:8787"},
    )
    assert response.status_code == 201
    assert response.json()["host"] == "192.0.2.10"
    audit = db.query_one("SELECT method, path, status FROM audit_events ORDER BY id DESC LIMIT 1")
    assert audit == {"method": "POST", "path": "/api/servers", "status": 201}


def test_cross_origin_write_is_rejected(monkeypatch, tmp_path):
    client, _db = _client(monkeypatch, tmp_path)
    csrf = _login(client)
    response = client.post(
        "/api/subscriptions",
        json={"name": "bad"},
        headers={"X-CSRF-Token": csrf, "Origin": "https://attacker.example"},
    )
    assert response.status_code == 403


def test_request_body_limit(monkeypatch, tmp_path):
    client, _db = _client(monkeypatch, tmp_path)
    csrf = _login(client)
    response = client.post(
        "/api/subscriptions",
        content=b"x" * (1024 * 1024 + 1),
        headers={
            "Content-Type": "application/json",
            "X-CSRF-Token": csrf,
            "Origin": "http://127.0.0.1:8787",
        },
    )
    assert response.status_code == 400
    assert response.json()["error"] == "request body too large"


def test_public_http_warning_is_returned_to_web_ui(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("APP_SECRET", "a-sufficiently-long-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-password")
    settings = load_settings()
    db = Database(settings.db_path)
    services = AppServices(db, SecretBox(settings.app_secret))
    app = create_app(settings=settings, db=db, services=services)
    client = TestClient(app, base_url="http://203.0.113.10:8787")
    response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a-strong-password"},
        headers={"Origin": "http://203.0.113.10:8787"},
    )
    assert response.status_code == 200
    session = client.get("/api/auth/session").json()
    assert "HTTPS 域名" in session["securityWarning"]


def test_webui_can_persist_and_apply_public_origin(monkeypatch, tmp_path):
    monkeypatch.setenv("APP_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("HOST", "0.0.0.0")
    monkeypatch.setenv("PORT", "8787")
    monkeypatch.setenv("APP_SECRET", "a-sufficiently-long-secret")
    monkeypatch.setenv("ADMIN_PASSWORD", "a-strong-password")
    monkeypatch.delenv("PUBLIC_ORIGIN", raising=False)
    monkeypatch.delenv("ALLOWED_HOSTS", raising=False)
    settings = load_settings()
    db = Database(settings.db_path)
    services = AppServices(db, SecretBox(settings.app_secret))
    app = create_app(settings=settings, db=db, services=services)
    client = TestClient(app, base_url="http://203.0.113.10:8787")
    login_response = client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a-strong-password"},
        headers={"Origin": "http://203.0.113.10:8787"},
    )
    assert login_response.status_code == 200
    csrf = client.cookies.get("myn_csrf")
    assert csrf

    initial = client.get("/api/settings").json()
    assert initial["source"] == "automatic"
    assert initial["publicAccessWarning"] is True

    headers = {
        "X-CSRF-Token": csrf,
        "Origin": "http://203.0.113.10:8787",
    }
    invalid = client.patch(
        "/api/settings",
        json={"publicOrigin": "http://panel.example.com"},
        headers=headers,
    )
    assert invalid.status_code == 400
    assert "HTTPS" in invalid.json()["error"]

    updated = client.patch(
        "/api/settings",
        json={"publicOrigin": "https://panel.example.com/"},
        headers=headers,
    )
    assert updated.status_code == 200
    assert updated.json() == {
        "publicOrigin": "https://panel.example.com",
        "configuredPublicOrigin": "https://panel.example.com",
        "source": "webui",
        "publicAccessWarning": False,
        "cookieSecure": True,
    }
    assert db.query_one(
        "SELECT value FROM app_metadata WHERE key = 'public_origin'"
    )["value"] == "https://panel.example.com"

    # The address used for the update remains temporarily valid so a bad proxy
    # configuration can be reverted before the process restarts.
    assert client.get("/api/settings").status_code == 200
    assert client.post(
        "/api/subscriptions",
        json={"name": "fallback-still-works"},
        headers=headers,
    ).status_code == 201

    restarted_db = Database(settings.db_path)
    restarted_app = create_app(
        settings=settings,
        db=restarted_db,
        services=AppServices(restarted_db, SecretBox(settings.app_secret)),
    )
    domain_client = TestClient(restarted_app, base_url="https://panel.example.com")
    login_response = domain_client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a-strong-password"},
        headers={"Origin": "https://panel.example.com"},
    )
    assert login_response.status_code == 200
    assert domain_client.cookies.get("__Host-myn_csrf")
    assert domain_client.get("/api/settings").json()["source"] == "webui"
    assert domain_client.get(
        "/api/health/ready",
        headers={"Host": "attacker.example"},
    ).status_code == 400

    # Loopback stays available as a recovery path after a bad DNS/proxy change.
    recovery_client = TestClient(restarted_app, base_url="http://127.0.0.1:8787")
    recovery_login = recovery_client.post(
        "/api/auth/login",
        json={"username": "admin", "password": "a-strong-password"},
        headers={"Origin": "http://127.0.0.1:8787"},
    )
    assert recovery_login.status_code == 200
    recovery_csrf = recovery_client.cookies.get("myn_csrf")
    assert recovery_csrf
    assert recovery_client.get("/api/settings").status_code == 200
    restored = recovery_client.patch(
        "/api/settings",
        json={"publicOrigin": ""},
        headers={
            "Origin": "http://127.0.0.1:8787",
            "X-CSRF-Token": recovery_csrf,
        },
    )
    assert restored.status_code == 200
    assert restored.json()["source"] == "automatic"
    assert db.query_one(
        "SELECT value FROM app_metadata WHERE key = 'public_origin'"
    ) is None


def test_chain_subscription_supports_mihomo_and_base64_formats(monkeypatch, tmp_path):
    client, db = _client(monkeypatch, tmp_path)
    share_link = (
        "vless://11111111-2222-3333-4444-555555555555@203.0.113.41:443"
        "?security=reality&type=tcp&flow=xtls-rprx-vision"
        "&pbk=dE8nfT3BBGpvTndPFXrdC3bSRHHQf5veZBKF31ZbWeo"
        "&fp=chrome&sni=cover.example&sid=01020304#chain"
    )
    db.execute(
        """
        INSERT INTO proxy_chains (
            id, name, token, client_uuid, status, share_link, created_at, updated_at
        ) VALUES ('chain-yaml', 'chain', 'yaml-token', 'client-id', 'ready', ?, 'now', 'now')
        """,
        (share_link,),
    )

    mihomo = client.get("/sub/chains/yaml-token?format=mihomo")
    assert mihomo.status_code == 200
    assert mihomo.headers["content-type"].startswith("application/yaml")
    assert yaml.safe_load(mihomo.text)["proxies"][0]["type"] == "vless"

    detected = client.get(
        "/sub/chains/yaml-token",
        headers={"User-Agent": "mihomo/1.19.0"},
    )
    assert detected.headers["content-type"].startswith("application/yaml")
    assert yaml.safe_load(detected.text)["proxy-groups"][0]["name"] == "PROXY"

    legacy = client.get("/sub/chains/yaml-token?format=base64")
    assert legacy.headers["content-type"].startswith("text/plain")
    assert base64.b64decode(legacy.text).decode("utf-8") == share_link
