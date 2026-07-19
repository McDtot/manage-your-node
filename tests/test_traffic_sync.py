from contextlib import nullcontext

import pytest

from app.database import Database
from app.security import SecretBox
from app.services import AppServices
from app.xui_api import XuiApiClient


@pytest.fixture
def services(tmp_path):
    db = Database(tmp_path / "test.db")
    return AppServices(db, SecretBox("a-long-test-secret-value"))


def _create_ready_deployment(services, suffix: str, host: str) -> str:
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
            id, server_id, engine, protocol, install_method, panel_port,
            panel_path, panel_username, encrypted_panel_password,
            encrypted_api_token, proxy_port, status, subscription_url,
            created_at, updated_at
        ) VALUES (?, ?, '3x-ui', 'VLESS + REALITY', 'native', 32000,
                  '/panel', 'admin', ?, ?, 443, 'ready', ?, 'now', 'now')
        """,
        (
            deployment_id,
            server["id"],
            services.secret_box.seal("panel-password"),
            services.secret_box.seal("api-token"),
            f"/sub/deployments/{deployment_id}",
        ),
    )
    return deployment_id


class FakeXui:
    def __init__(self, totals=None):
        self.totals = totals or {}

    def wait_ready(self, seconds):
        pass

    def login(self):
        pass

    def create_client(self, **payload):
        return []

    def client_traffic_totals(self, inbound_id):
        return self.totals


def test_client_traffic_totals_sums_up_and_down(monkeypatch):
    client = XuiApiClient(
        base_url="https://127.0.0.1:32000/panel-path/",
        username="admin",
        password="password",
    )
    monkeypatch.setattr(
        client,
        "get_json",
        lambda _path: {
            "success": True,
            "obj": {
                "clientStats": [
                    {"email": "alice", "up": 100, "down": 200},
                    {"email": "bob", "up": 50, "down": 75},
                ]
            },
        },
    )

    assert client.client_traffic_totals(42) == {"alice": 300, "bob": 125}


def test_client_traffic_totals_empty_when_stats_missing_or_invalid(monkeypatch):
    client = XuiApiClient(
        base_url="https://127.0.0.1:32000/panel-path/",
        username="admin",
        password="password",
    )

    monkeypatch.setattr(
        client,
        "get_json",
        lambda _path: {"success": True, "obj": {}},
    )
    assert client.client_traffic_totals(1) == {}

    monkeypatch.setattr(
        client,
        "get_json",
        lambda _path: {"success": True, "obj": {"clientStats": {"email": "alice"}}},
    )
    assert client.client_traffic_totals(1) == {}

    monkeypatch.setattr(
        client,
        "get_json",
        lambda _path: {
            "success": True,
            "obj": {
                "clientStats": [
                    "skip-me",
                    {"up": 1, "down": 2},
                    {"email": "", "up": 10, "down": 20},
                    {"email": "ok", "up": 1, "down": 2},
                ]
            },
        },
    )
    assert client.client_traffic_totals(1) == {"ok": 3}


def test_refresh_deployment_traffic_updates_used_bytes(services, monkeypatch):
    deployment_id = _create_ready_deployment(services, "traffic-sync", "203.0.113.80")
    services.db.execute(
        "UPDATE deployments SET xui_inbound_id = 55 WHERE id = ?",
        (deployment_id,),
    )
    monkeypatch.setattr(services, "_xui_session", lambda _deployment: nullcontext(FakeXui()))

    alice = services.create_client(deployment_id, {"name": "alice"})
    bob = services.create_client(deployment_id, {"name": "bob"})

    monkeypatch.setattr(
        services,
        "_xui_session",
        lambda _deployment: nullcontext(FakeXui({"alice": 1000, "bob": 2000})),
    )

    updated = services.refresh_deployment_traffic(services.get_deployment(deployment_id))
    assert updated == 2
    assert services.get_client(alice["id"])["used_bytes"] == 1000
    assert services.get_client(bob["id"])["used_bytes"] == 2000


def test_refresh_deployment_traffic_skips_ineligible_deployments(services, monkeypatch):
    calls = []

    def tracking_session(_deployment):
        calls.append(_deployment)
        return nullcontext(FakeXui())

    monkeypatch.setattr(services, "_xui_session", tracking_session)

    deployment_id = _create_ready_deployment(services, "no-inbound", "203.0.113.81")
    assert services.refresh_deployment_traffic(services.get_deployment(deployment_id)) == 0
    assert calls == []

    services.db.execute(
        "UPDATE deployments SET xui_inbound_id = 55, status = 'failed' WHERE id = ?",
        (deployment_id,),
    )
    assert services.refresh_deployment_traffic(services.get_deployment(deployment_id)) == 0
    assert calls == []


def test_refresh_all_traffic_collects_errors(services, monkeypatch):
    deployment_id = _create_ready_deployment(services, "traffic-error", "203.0.113.82")
    services.db.execute(
        "UPDATE deployments SET xui_inbound_id = 55 WHERE id = ?",
        (deployment_id,),
    )

    def boom(_deployment):
        raise RuntimeError("xui unreachable")

    monkeypatch.setattr(services, "refresh_deployment_traffic", boom)

    result = services.refresh_all_traffic()
    assert result["deployments"] == 0
    assert result["updatedClients"] == 0
    assert result["errors"] == [
        {"deploymentId": deployment_id, "error": "xui unreachable"},
    ]


def test_traffic_sync_thread_lifecycle(services):
    assert services._traffic_thread is None
    services.start_traffic_sync(0)
    assert services._traffic_thread is None

    services.start_traffic_sync(3600)
    assert services._traffic_thread is not None
    services.stop_traffic_sync()
    assert services._traffic_thread is None
