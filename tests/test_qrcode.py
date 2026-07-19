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
    monkeypatch.setenv("TRAFFIC_SYNC_SECONDS", "0")
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


def test_qrcode_requires_authentication(monkeypatch, tmp_path):
    client, _db = _client(monkeypatch, tmp_path)
    response = client.get("/api/qrcode?data=abc")
    assert response.status_code == 401


def test_qrcode_returns_svg(monkeypatch, tmp_path):
    client, _db = _client(monkeypatch, tmp_path)
    _login(client)
    response = client.get("/api/qrcode?data=ss://example")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("image/svg+xml")
    assert b"<svg" in response.content
    assert response.headers["cache-control"] == "no-store"


def test_qrcode_validates_data_parameter(monkeypatch, tmp_path):
    client, _db = _client(monkeypatch, tmp_path)
    _login(client)

    missing = client.get("/api/qrcode")
    assert missing.status_code == 400
    assert missing.json() == {"error": "data is required"}

    too_long = client.get("/api/qrcode", params={"data": "x" * 4097})
    assert too_long.status_code == 400
    assert too_long.json() == {"error": "data is too long"}


def test_traffic_refresh_endpoint_empty(monkeypatch, tmp_path):
    client, _db = _client(monkeypatch, tmp_path)
    csrf = _login(client)
    response = client.post(
        "/api/traffic/refresh",
        json={},
        headers={"X-CSRF-Token": csrf, "Origin": "http://127.0.0.1:8787"},
    )
    assert response.status_code == 200
    assert response.json() == {"deployments": 0, "updatedClients": 0, "errors": []}
