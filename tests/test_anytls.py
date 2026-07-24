import base64
from urllib.parse import unquote, urlparse

import pytest
import yaml

from app.database import Database
from app.security import SecretBox
from app.services import (
    DEPLOYMENT_PROTOCOL_ANYTLS,
    AppServices,
    _mihomo_proxy_from_anytls,
    anytls_share_link,
    new_anytls_password,
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


def _create_ready_anytls_deployment(
    services,
    suffix: str,
    host: str,
    domain: str = "",
) -> str:
    server = services.create_server(
        {
            "name": f"anytls-{suffix}",
            "host": host,
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    deployment_id = f"dep-anytls-{suffix}"
    services.db.execute(
        """
        INSERT INTO deployments (
            id, server_id, engine, protocol, install_method, panel_port,
            panel_path, panel_username, encrypted_panel_password,
            encrypted_api_token, proxy_port, anytls_domain,
            status, subscription_url, created_at, updated_at
        ) VALUES (?, ?, 'sing-box', ?, 'native', 32000,
                  '/panel', 'admin', ?, ?, 443, ?, 'ready', ?, 'now', 'now')
        """,
        (
            deployment_id,
            server["id"],
            DEPLOYMENT_PROTOCOL_ANYTLS,
            services.secret_box.seal("panel-password"),
            services.secret_box.seal(""),
            domain,
            f"/sub/deployments/{deployment_id}",
        ),
    )
    return deployment_id


def test_new_anytls_password_is_32_bytes_base64():
    password = new_anytls_password()
    assert len(base64.b64decode(password)) == 32


def test_anytls_share_link_carries_insecure_and_sni():
    link = anytls_share_link(
        password="secret-pass",
        host="203.0.113.10",
        port=443,
        name="节点 A",
        sni="",
        insecure=True,
    )
    parsed = urlparse(link)
    assert parsed.scheme == "anytls"
    assert parsed.hostname == "203.0.113.10"
    assert parsed.port == 443
    assert unquote(parsed.username) == "secret-pass"
    assert "insecure=1" in parsed.query
    assert unquote(parsed.fragment) == "节点 A"


def test_anytls_share_link_round_trips_to_mihomo_proxy():
    link = anytls_share_link(
        password="pw",
        host="203.0.113.20",
        port=8443,
        name="tokyo",
        sni="example.com",
        insecure=False,
    )
    proxy = _mihomo_proxy_from_anytls(link, 1, set())
    assert proxy["type"] == "anytls"
    assert proxy["password"] == "pw"
    assert proxy["server"] == "203.0.113.20"
    assert proxy["port"] == 8443
    assert proxy["sni"] == "example.com"
    assert proxy["udp"] is True
    assert "skip-cert-verify" not in proxy


def test_anytls_self_signed_link_sets_skip_cert_verify():
    link = anytls_share_link(
        password="pw",
        host="203.0.113.30",
        port=443,
        name="edge",
        insecure=True,
    )
    proxy = _mihomo_proxy_from_anytls(link, 1, set())
    assert proxy["skip-cert-verify"] is True


def test_anytls_deployment_persists_engine_protocol_and_domain(services, monkeypatch):
    server = services.create_server(
        {
            "name": "edge-anytls",
            "host": "203.0.113.70",
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
        {"protocol": DEPLOYMENT_PROTOCOL_ANYTLS, "proxyPort": 443, "anytlsDomain": "vpn.example.com"},
    )["deployment"]
    assert services.wait_for_workers()

    row = services.db.query_one(
        "SELECT engine, protocol, anytls_domain FROM deployments WHERE id = ?",
        (deployment["id"],),
    )
    assert row["engine"] == "sing-box"
    assert row["protocol"] == DEPLOYMENT_PROTOCOL_ANYTLS
    assert row["anytls_domain"] == "vpn.example.com"


def test_build_anytls_config_self_signed_structure(services):
    deployment_id = _create_ready_anytls_deployment(services, "cfg", "203.0.113.71")
    services.db.execute(
        """
        INSERT INTO clients (
            id, deployment_id, name, uuid, quota_bytes, used_bytes,
            traffic_reset_days, expires_at, enabled, encrypted_ss_password,
            encrypted_anytls_password, share_link, subscription_url,
            created_at, updated_at
        ) VALUES ('cli-1', ?, 'alice', 'uuid-1', 0, 0, 0, '', 1, '', ?, '', '', 'now', 'now')
        """,
        (deployment_id, services.secret_box.seal("user-pass")),
    )
    deployment = services.get_deployment(deployment_id)
    config = services._build_anytls_config(deployment)
    inbound = config["inbounds"][0]
    assert inbound["type"] == "anytls"
    assert inbound["listen_port"] == 443
    assert inbound["users"] == [{"name": "alice", "password": "user-pass"}]
    assert inbound["tls"]["enabled"] is True
    assert inbound["tls"]["certificate_path"].endswith("cert.pem")
    assert "acme" not in inbound["tls"]


def test_build_anytls_config_uses_acme_when_domain_set(services):
    deployment_id = _create_ready_anytls_deployment(
        services, "acme", "203.0.113.72", domain="vpn.example.com"
    )
    deployment = services.get_deployment(deployment_id)
    config = services._build_anytls_config(deployment)
    tls = config["inbounds"][0]["tls"]
    assert tls["server_name"] == "vpn.example.com"
    assert tls["acme"]["domain"] == ["vpn.example.com"]
    assert "certificate_path" not in tls


def test_create_anytls_client_pushes_config_and_builds_link(services, monkeypatch):
    deployment_id = _create_ready_anytls_deployment(services, "user", "203.0.113.73")
    captured: dict = {}

    def fake_push(deployment, config):
        captured["config"] = config

    monkeypatch.setattr(services, "_push_anytls_config", fake_push)

    client = services.create_client(deployment_id, {"name": "alice"})

    inbound = captured["config"]["inbounds"][0]
    assert inbound["type"] == "anytls"
    alice = next(user for user in inbound["users"] if user["name"] == "alice")
    assert len(base64.b64decode(alice["password"])) == 32

    parsed = urlparse(client["share_link"])
    assert parsed.scheme == "anytls"
    assert parsed.port == 443
    assert "insecure=1" in parsed.query

    stored = services.secret_box.open(
        services.db.query_one(
            "SELECT encrypted_anytls_password FROM clients WHERE id = ?",
            (client["id"],),
        )["encrypted_anytls_password"]
    )
    assert stored == alice["password"]


def test_anytls_subscription_renders_base64_and_mihomo(services, monkeypatch):
    deployment_id = _create_ready_anytls_deployment(services, "sub", "203.0.113.74")
    monkeypatch.setattr(services, "_push_anytls_config", lambda deployment, config: None)

    client = services.create_client(deployment_id, {"name": "bob"})
    services.update_subscription_config(deployment_id, {"nodeIds": [client["id"]]})

    base64_out = services.render_deployment_subscription(deployment_id, "base64")
    decoded = base64.b64decode(base64_out).decode("utf-8")
    assert decoded.startswith("anytls://")

    mihomo_out = services.render_deployment_subscription(deployment_id, "mihomo")
    config = yaml.safe_load(mihomo_out)
    assert config["proxies"][0]["type"] == "anytls"
