import contextlib

import pytest

from app.database import Database
from app.security import SecretBox
from app.services import AppServices


@pytest.fixture
def services(tmp_path):
    db = Database(tmp_path / "test.db")
    return AppServices(db, SecretBox("a-long-test-secret-value"))


def _create_server(services, name: str, host: str):
    return services.create_server(
        {
            "name": name,
            "host": host,
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )


def test_reachable_records_latency(services, monkeypatch):
    server = _create_server(services, "edge", "203.0.113.10")
    monkeypatch.setattr(
        "app.services.servers.socket.create_connection",
        lambda *a, **k: contextlib.nullcontext(),
    )
    monkeypatch.setattr(
        services.ssh,
        "probe",
        lambda _server: (True, "os=Linux arch=x86_64"),
    )

    result = services.test_server(server["id"])
    assert result["status"] == "reachable"
    assert result["error"] == ""
    assert isinstance(result["latencyMs"], int)
    assert result["latencyMs"] >= 0

    stored = services.get_server(server["id"])
    assert stored["status"] == "reachable"
    assert stored["last_latency_ms"] is not None
    assert stored["last_check_at"]


def test_auth_failed(services, monkeypatch):
    server = _create_server(services, "edge", "203.0.113.10")
    monkeypatch.setattr(
        "app.services.servers.socket.create_connection",
        lambda *a, **k: contextlib.nullcontext(),
    )
    monkeypatch.setattr(
        services.ssh,
        "probe",
        lambda _server: (False, "auth failed"),
    )

    result = services.test_server(server["id"])
    assert result["status"] == "auth_failed"
    assert result["error"] == "auth failed"


def test_unreachable(services, monkeypatch):
    server = _create_server(services, "edge", "203.0.113.10")

    def refuse(*_args, **_kwargs):
        raise OSError("refused")

    monkeypatch.setattr(
        "app.services.servers.socket.create_connection",
        refuse,
    )

    result = services.test_server(server["id"])
    assert result["status"] == "unreachable"
    assert result["latencyMs"] is None

    stored = services.get_server(server["id"])
    assert "refused" in stored["last_health_error"]
    assert stored["last_latency_ms"] is None


def test_check_all_servers_health_summary(services, monkeypatch):
    _create_server(services, "ok", "203.0.113.10")
    _create_server(services, "auth", "203.0.113.20")
    _create_server(services, "down", "203.0.113.30")

    def fake_create_connection(address, *args, **kwargs):
        host, _port = address
        if host == "203.0.113.30":
            raise OSError("refused")
        return contextlib.nullcontext()

    def fake_probe(server):
        if server["host"] == "203.0.113.20":
            return False, "auth failed"
        return True, "ok"

    monkeypatch.setattr(
        "app.services.servers.socket.create_connection",
        fake_create_connection,
    )
    monkeypatch.setattr(services.ssh, "probe", fake_probe)

    summary = services.check_all_servers_health()
    assert summary["checked"] == 3
    assert summary["reachable"] == 1
    assert summary["authFailed"] == 1
    assert summary["unreachable"] == 1


def test_health_monitor_thread_start_stop(services):
    assert services._health_thread is None
    services.start_health_monitor(0)
    assert services._health_thread is None
    services.start_health_monitor(3600)
    assert services._health_thread is not None
    services.stop_health_monitor()
    assert services._health_thread is None
