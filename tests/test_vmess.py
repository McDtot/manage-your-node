import base64
import json
from urllib.parse import urlparse

import pytest
import yaml

from app.database import Database
from app.security import SecretBox
from app.services import (
    DEPLOYMENT_PROTOCOL_VMESS,
    AppServices,
    _mihomo_proxy_from_vmess,
    _share_link_with_display_name,
    vmess_share_link,
)

CERT_SHA256 = ":".join(["BB"] * 32)


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


def _create_ready_vmess_deployment(
    services,
    suffix: str,
    host: str,
    domain: str = "",
) -> str:
    server = services.create_server(
        {
            "name": f"vmess-{suffix}",
            "host": host,
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    deployment_id = f"dep-vmess-{suffix}"
    services.db.execute(
        """
        INSERT INTO deployments (
            id, server_id, engine, protocol, install_method, proxy_port,
            anytls_domain, tls_cert_sha256, status, subscription_url,
            created_at, updated_at
        ) VALUES (?, ?, 'sing-box', ?, 'native', 443, ?, ?, 'ready', ?, 'now', 'now')
        """,
        (
            deployment_id,
            server["id"],
            DEPLOYMENT_PROTOCOL_VMESS,
            domain,
            "" if domain else CERT_SHA256,
            f"/sub/deployments/{deployment_id}",
        ),
    )
    return deployment_id


def _decode_vmess(link: str) -> dict:
    parsed = urlparse(link)
    raw = (parsed.netloc or "") + (parsed.path or "")
    padded = raw + "=" * (-len(raw) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))


def test_vmess_share_link_encodes_standard_payload():
    link = vmess_share_link(
        client_uuid="bf000d23-0752-40b4-affe-68f7707a9661",
        host="203.0.113.10",
        port=443,
        name="节点 A",
        sni="",
        tls=True,
        insecure=True,
        cert_sha256=CERT_SHA256,
    )
    assert link.startswith("vmess://")
    payload = _decode_vmess(link)
    assert payload["add"] == "203.0.113.10"
    assert payload["port"] == "443"
    assert payload["id"] == "bf000d23-0752-40b4-affe-68f7707a9661"
    assert payload["aid"] == "0"
    assert payload["tls"] == "tls"
    assert payload["insecure"] == "1"
    assert payload["pcs"] == CERT_SHA256
    assert "allowInsecure" not in payload
    assert payload["ps"] == "节点 A"


def test_vmess_share_link_rejects_unpinned_self_signed_tls():
    with pytest.raises(ValueError, match="certificate fingerprint"):
        vmess_share_link(
            client_uuid="bf000d23-0752-40b4-affe-68f7707a9661",
            host="203.0.113.10",
            port=443,
            name="unsafe",
            insecure=True,
        )


def test_vmess_share_link_round_trips_to_mihomo_proxy():
    link = vmess_share_link(
        client_uuid="bf000d23-0752-40b4-affe-68f7707a9661",
        host="203.0.113.20",
        port=8443,
        name="tokyo",
        sni="example.com",
        tls=True,
        insecure=False,
    )
    proxy = _mihomo_proxy_from_vmess(link, 1, set())
    assert proxy["type"] == "vmess"
    assert proxy["uuid"] == "bf000d23-0752-40b4-affe-68f7707a9661"
    assert proxy["server"] == "203.0.113.20"
    assert proxy["port"] == 8443
    assert proxy["tls"] is True
    assert proxy["servername"] == "example.com"
    assert "skip-cert-verify" not in proxy

    pinned = vmess_share_link(
        client_uuid="bf000d23-0752-40b4-affe-68f7707a9661",
        host="203.0.113.20",
        port=8443,
        name="pinned",
        tls=True,
        insecure=True,
        cert_sha256=CERT_SHA256,
    )
    pinned_proxy = _mihomo_proxy_from_vmess(pinned, 2, set())
    assert pinned_proxy["skip-cert-verify"] is True
    assert pinned_proxy["fingerprint"] == CERT_SHA256


def test_vmess_display_name_updates_ps_field():
    link = vmess_share_link(
        client_uuid="bf000d23-0752-40b4-affe-68f7707a9661",
        host="203.0.113.30",
        port=443,
        name="old",
        cert_sha256=CERT_SHA256,
    )
    renamed = _share_link_with_display_name(link, "订阅名")
    assert _decode_vmess(renamed)["ps"] == "订阅名"


def test_vmess_deployment_persists_engine_protocol_and_domain(services, monkeypatch):
    server = services.create_server(
        {
            "name": "edge-vmess",
            "host": "203.0.113.90",
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
        {
            "protocol": DEPLOYMENT_PROTOCOL_VMESS,
            "proxyPort": 443,
            "anytlsDomain": "vmess.example.com",
        },
    )["deployment"]
    assert services.wait_for_workers()

    row = services.db.query_one(
        "SELECT engine, protocol, anytls_domain FROM deployments WHERE id = ?",
        (deployment["id"],),
    )
    assert row["engine"] == "sing-box"
    assert row["protocol"] == DEPLOYMENT_PROTOCOL_VMESS
    assert row["anytls_domain"] == "vmess.example.com"


def test_create_vmess_client_pushes_config_and_builds_link(services, monkeypatch):
    deployment_id = _create_ready_vmess_deployment(services, "user", "203.0.113.91")
    captured: dict = {}

    def fake_push(deployment, config):
        captured["config"] = config

    monkeypatch.setattr(services, "_push_node_config", fake_push)

    client = services.create_client(deployment_id, {"name": "alice"})

    inbound = captured["config"]["inbounds"][0]
    assert inbound["type"] == "vmess"
    alice = next(user for user in inbound["users"] if user["name"] == "alice")
    assert alice["uuid"] == client["uuid"]
    assert alice["alterId"] == 0

    payload = _decode_vmess(client["share_link"])
    assert payload["id"] == client["uuid"]
    assert payload["tls"] == "tls"
    assert payload["insecure"] == "1"
    assert payload["pcs"] == CERT_SHA256


def test_vmess_subscription_renders_base64_and_mihomo(services, monkeypatch):
    deployment_id = _create_ready_vmess_deployment(services, "sub", "203.0.113.92")
    monkeypatch.setattr(services, "_push_node_config", lambda deployment, config: None)

    client = services.create_client(deployment_id, {"name": "bob"})
    services.update_subscription_config(deployment_id, {"nodeIds": [client["id"]]})

    base64_out = services.render_deployment_subscription(deployment_id, "base64")
    decoded = base64.b64decode(base64_out).decode("utf-8")
    assert decoded.startswith("vmess://")

    mihomo_out = services.render_deployment_subscription(deployment_id, "mihomo")
    config = yaml.safe_load(mihomo_out)
    assert config["proxies"][0]["type"] == "vmess"
