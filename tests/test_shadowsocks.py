import base64
from urllib.parse import unquote, urlparse

import pytest
import yaml

from app.database import Database
from app.security import SecretBox
from app.services import (
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
    DEPLOYMENT_SS_METHOD,
    AppServices,
    _mihomo_proxy_from_ss,
    _render_subscription_links,
    new_ss2022_password,
    ss_share_link,
)


@pytest.fixture
def services(tmp_path):
    db = Database(tmp_path / "test.db")
    return AppServices(db, SecretBox("a-long-test-secret-value"))


def _trust_server_for_native_deployment(services, server_id: str) -> None:
    services.db.execute(
        "UPDATE servers SET status = 'reachable' WHERE id = ?",
        (server_id,),
    )
    services.db.execute(
        """
        INSERT INTO ssh_host_keys (
            server_id, key_type, key_base64, fingerprint, trusted, created_at
        ) VALUES (?, 'ssh-ed25519', 'test-key', 'SHA256:test', 1, 'now')
        """,
        (server_id,),
    )


def _create_ready_ss_deployment(services, suffix: str, host: str) -> str:
    server = services.create_server(
        {
            "name": f"ss-{suffix}",
            "host": host,
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    deployment_id = f"dep-ss-{suffix}"
    services.db.execute(
        """
        INSERT INTO deployments (
            id, server_id, engine, protocol, install_method, proxy_port,
            ss_method, encrypted_ss_password, status, subscription_url,
            created_at, updated_at
        ) VALUES (?, ?, 'sing-box', ?, 'native', 8388, ?, ?, 'ready', ?, 'now', 'now')
        """,
        (
            deployment_id,
            server["id"],
            DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
            DEPLOYMENT_SS_METHOD,
            services.secret_box.seal("server-psk-value"),
            f"/sub/deployments/{deployment_id}",
        ),
    )
    return deployment_id


def test_new_ss2022_password_is_32_bytes_base64():
    password = new_ss2022_password()
    assert len(base64.b64decode(password)) == 32


def test_ss_share_link_encodes_method_and_keys():
    link = ss_share_link(
        method=DEPLOYMENT_SS_METHOD,
        server_password="server-psk",
        user_password="user-psk",
        host="203.0.113.10",
        port=8388,
        name="节点 A",
    )
    parsed = urlparse(link)
    assert parsed.scheme == "ss"
    assert parsed.hostname == "203.0.113.10"
    assert parsed.port == 8388
    assert unquote(parsed.fragment) == "节点 A"
    decoded = base64.b64decode(parsed.username).decode("utf-8")
    assert decoded == f"{DEPLOYMENT_SS_METHOD}:server-psk:user-psk"


def test_ss_share_link_round_trips_to_mihomo_proxy():
    link = ss_share_link(
        method=DEPLOYMENT_SS_METHOD,
        server_password="server-psk",
        user_password="user-psk",
        host="203.0.113.20",
        port=8388,
        name="tokyo",
    )
    proxy = _mihomo_proxy_from_ss(link, 1, set())
    assert proxy["type"] == "ss"
    assert proxy["cipher"] == DEPLOYMENT_SS_METHOD
    assert proxy["password"] == "server-psk:user-psk"
    assert proxy["server"] == "203.0.113.20"
    assert proxy["port"] == 8388
    assert proxy["udp"] is True


def test_ss_deployment_persists_engine_and_server_psk(services, monkeypatch):
    server = services.create_server(
        {
            "name": "edge-ss",
            "host": "203.0.113.80",
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    _trust_server_for_native_deployment(services, server["id"])

    def finish_without_worker(job_id, deployment_id, _server):
        services.db.execute(
            "UPDATE deployments SET status = 'ready' WHERE id = ?",
            (deployment_id,),
        )
        services._finish_job(job_id, "success", None)
        services._release_operation_locks(job_id)

    monkeypatch.setattr(services, "_run_deployment", finish_without_worker)

    deployment = services.start_deployment(
        server["id"],
        {"protocol": DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022, "proxyPort": 8388},
    )["deployment"]
    assert services.wait_for_workers()

    row = services.get_deployment(deployment["id"])
    assert row["engine"] == "sing-box"
    assert row["protocol"] == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022
    assert len(base64.b64decode(row["ss_password"])) == 32


def test_create_ss_client_pushes_config_and_builds_link(services, monkeypatch):
    deployment_id = _create_ready_ss_deployment(services, "user", "203.0.113.81")
    captured: dict = {}

    def fake_push(deployment, config):
        captured["config"] = config

    monkeypatch.setattr(services, "_push_node_config", fake_push)

    client = services.create_client(deployment_id, {"name": "alice"})

    inbound = captured["config"]["inbounds"][0]
    assert inbound["type"] == "shadowsocks"
    assert inbound["password"] == "server-psk-value"
    alice = next(user for user in inbound["users"] if user["name"] == "alice")
    assert len(base64.b64decode(alice["password"])) == 32

    parsed = urlparse(client["share_link"])
    assert parsed.scheme == "ss"
    assert parsed.port == 8388
    decoded = base64.b64decode(parsed.username).decode("utf-8")
    assert decoded.startswith(f"{DEPLOYMENT_SS_METHOD}:server-psk-value:")


def test_create_ss_client_skips_push_when_not_ready(services, monkeypatch):
    deployment_id = _create_ready_ss_deployment(services, "pending", "203.0.113.82")
    services.db.execute(
        "UPDATE deployments SET status = 'provisioning' WHERE id = ?",
        (deployment_id,),
    )
    monkeypatch.setattr(
        services,
        "_push_node_config",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(
            AssertionError("no push when not ready")
        ),
    )
    client = services.create_client(deployment_id, {"name": "bob"})
    assert client["share_link"].startswith("ss://")


def test_ss_subscription_renders_base64_and_mihomo(services, monkeypatch):
    deployment_id = _create_ready_ss_deployment(services, "sub", "203.0.113.83")
    monkeypatch.setattr(services, "_push_node_config", lambda deployment, config: None)

    client = services.create_client(deployment_id, {"name": "carol"})
    services.update_subscription_config(deployment_id, {"nodeIds": [client["id"]]})

    base64_out = services.render_deployment_subscription(deployment_id, "base64")
    decoded = base64.b64decode(base64_out).decode("utf-8")
    assert decoded.startswith("ss://")

    mihomo_out = services.render_deployment_subscription(deployment_id, "mihomo")
    config = yaml.safe_load(mihomo_out)
    assert config["proxies"][0]["type"] == "ss"


def test_render_subscription_links_accepts_ss():
    link = ss_share_link(
        method=DEPLOYMENT_SS_METHOD,
        server_password="s",
        user_password="u",
        host="203.0.113.90",
        port=8388,
        name="ss-node",
    )
    rendered = _render_subscription_links([link], "mihomo")
    assert "type: ss" in rendered
