import pytest

from app.database import Database
from app.security import SecretBox
from app.services import AppServices


@pytest.fixture
def services(tmp_path):
    db = Database(tmp_path / "test.db")
    return AppServices(db, SecretBox("a-long-test-secret-value"))


def _create_native_deployment(services, *, suffix: str, host: str) -> tuple[str, str]:
    server = services.create_server(
        {
            "name": f"edge-{suffix}",
            "host": host,
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    deployment_id = f"dep-{suffix}"
    services.db.execute(
        """
        INSERT INTO deployments (
            id, server_id, engine, protocol, install_method, proxy_port,
            status, subscription_url, created_at, updated_at
        ) VALUES (?, ?, 'sing-box', 'VLESS + REALITY', 'native', 443,
                  'ready', ?, 'now', 'now')
        """,
        (deployment_id, server["id"], f"/sub/deployments/{deployment_id}"),
    )
    return server["id"], deployment_id


def test_delete_deployment_keeps_going_when_remote_cleanup_fails(services, monkeypatch):
    _server_id, deployment_id = _create_native_deployment(
        services, suffix="offline-dep", host="203.0.113.50"
    )

    def boom(*_args, **_kwargs):
        raise RuntimeError("SSH connection failed: unreachable")

    monkeypatch.setattr(services, "_cleanup_remote_deployment", boom)

    result = services.delete_deployment(deployment_id)

    assert result["deleted"] == deployment_id
    assert result["remoteCleanupOk"] is False
    assert any("Remote cleanup failed" in line for line in result["remoteLogs"])
    assert services.db.query_one("SELECT id FROM deployments WHERE id = ?", (deployment_id,)) is None


def test_delete_server_keeps_going_when_remote_uninstall_fails(services, monkeypatch):
    server_id, deployment_id = _create_native_deployment(
        services, suffix="offline-srv", host="203.0.113.51"
    )

    def boom(*_args, **_kwargs):
        raise RuntimeError("SSH connection failed: unreachable")

    monkeypatch.setattr(services, "_uninstall_server_deployments", boom)

    result = services.delete_server(server_id)

    assert result["deleted"] == server_id
    assert result["remoteCleanupOk"] is False
    assert any("Remote cleanup failed" in line for line in result["remoteLogs"])
    assert services.db.query_one("SELECT id FROM servers WHERE id = ?", (server_id,)) is None
    assert services.db.query_one("SELECT id FROM deployments WHERE id = ?", (deployment_id,)) is None


def test_delete_deployment_reports_success_when_remote_cleanup_works(services, monkeypatch):
    _server_id, deployment_id = _create_native_deployment(
        services, suffix="online-dep", host="203.0.113.52"
    )
    monkeypatch.setattr(
        services,
        "_cleanup_remote_deployment",
        lambda *_args, **_kwargs: ["Removed myn-node-dep-online-dep"],
    )

    result = services.delete_deployment(deployment_id)

    assert result["deleted"] == deployment_id
    assert result["remoteCleanupOk"] is True
    assert "Removed myn-node-dep-online-dep" in result["remoteLogs"]
    assert services.db.query_one("SELECT id FROM deployments WHERE id = ?", (deployment_id,)) is None
