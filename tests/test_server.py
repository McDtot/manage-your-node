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
