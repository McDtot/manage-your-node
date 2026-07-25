import base64
from urllib.parse import unquote, urlparse

import pytest
import yaml

from app.database import Database
from app.security import SecretBox
from app.services import (
    DEPLOYMENT_PROTOCOL_HYSTERIA2,
    AppServices,
    _mihomo_proxy_from_hy2,
    hy2_share_link,
    new_hy2_password,
)

CERT_SHA256 = ":".join(["AA"] * 32)


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


def _create_ready_hy2_deployment(
    services,
    suffix: str,
    host: str,
    domain: str = "",
    obfs_password: str = "obfs-secret",
) -> str:
    server = services.create_server(
        {
            "name": f"hy2-{suffix}",
            "host": host,
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    deployment_id = f"dep-hy2-{suffix}"
    services.db.execute(
        """
        INSERT INTO deployments (
            id, server_id, engine, protocol, install_method, proxy_port,
            anytls_domain, tls_cert_sha256, encrypted_hy2_obfs_password,
            status, subscription_url, created_at, updated_at
        ) VALUES (?, ?, 'sing-box', ?, 'native', 443, ?, ?, ?, 'ready', ?, 'now', 'now')
        """,
        (
            deployment_id,
            server["id"],
            DEPLOYMENT_PROTOCOL_HYSTERIA2,
            domain,
            "" if domain else CERT_SHA256,
            services.secret_box.seal(obfs_password),
            f"/sub/deployments/{deployment_id}",
        ),
    )
    return deployment_id


def test_new_hy2_password_is_32_bytes_base64():
    password = new_hy2_password()
    assert len(base64.b64decode(password)) == 32


def test_hy2_share_link_carries_obfs_and_insecure():
    link = hy2_share_link(
        password="secret-pass",
        host="203.0.113.10",
        port=443,
        name="节点 A",
        sni="",
        insecure=True,
        obfs_password="obfs-pw",
        cert_sha256=CERT_SHA256,
    )
    parsed = urlparse(link)
    assert parsed.scheme == "hy2"
    assert parsed.hostname == "203.0.113.10"
    assert parsed.port == 443
    assert unquote(parsed.username) == "secret-pass"
    assert "insecure=1" in parsed.query
    assert f"pinSHA256={CERT_SHA256.replace(':', '%3A')}" in parsed.query
    assert "obfs=salamander" in parsed.query
    assert "obfs-password=obfs-pw" in parsed.query
    assert unquote(parsed.fragment) == "节点 A"


def test_hy2_share_link_rejects_unpinned_self_signed_tls():
    with pytest.raises(ValueError, match="certificate fingerprint"):
        hy2_share_link(
            password="secret-pass",
            host="203.0.113.10",
            port=443,
            name="unsafe",
            insecure=True,
        )


def test_hy2_share_link_round_trips_to_mihomo_proxy():
    link = hy2_share_link(
        password="pw",
        host="203.0.113.20",
        port=8443,
        name="tokyo",
        sni="example.com",
        insecure=False,
        obfs_password="obfs",
    )
    proxy = _mihomo_proxy_from_hy2(link, 1, set())
    assert proxy["type"] == "hysteria2"
    assert proxy["password"] == "pw"
    assert proxy["server"] == "203.0.113.20"
    assert proxy["port"] == 8443
    assert proxy["sni"] == "example.com"
    assert proxy["obfs"] == "salamander"
    assert proxy["obfs-password"] == "obfs"
    assert "skip-cert-verify" not in proxy

    pinned = hy2_share_link(
        password="pw",
        host="203.0.113.20",
        port=8443,
        name="pinned",
        insecure=True,
        cert_sha256=CERT_SHA256,
    )
    pinned_proxy = _mihomo_proxy_from_hy2(pinned, 2, set())
    assert pinned_proxy["skip-cert-verify"] is True
    assert pinned_proxy["fingerprint"] == CERT_SHA256


def test_hy2_deployment_persists_obfs_password(services, monkeypatch):
    server = services.create_server(
        {
            "name": "edge-hy2",
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
        {
            "protocol": DEPLOYMENT_PROTOCOL_HYSTERIA2,
            "proxyPort": 443,
            "anytlsDomain": "hy2.example.com",
        },
    )["deployment"]
    assert services.wait_for_workers()

    row = services.db.query_one(
        "SELECT engine, protocol, anytls_domain, encrypted_hy2_obfs_password "
        "FROM deployments WHERE id = ?",
        (deployment["id"],),
    )
    assert row["engine"] == "sing-box"
    assert row["protocol"] == DEPLOYMENT_PROTOCOL_HYSTERIA2
    assert row["anytls_domain"] == "hy2.example.com"
    assert services.secret_box.open(row["encrypted_hy2_obfs_password"])


def test_self_signed_hy2_deployment_persists_certificate_fingerprint(
    services, monkeypatch
):
    server = services.create_server(
        {
            "name": "edge-hy2-pinned",
            "host": "203.0.113.83",
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    _trust_server_for_native_deployment(services, server["id"])

    def fake_run_script(_server, _script, log, timeout):
        line = f"__MYN_TLS_CERT_SHA256__={CERT_SHA256}"
        log(line)
        return [line]

    monkeypatch.setattr(services.ssh, "run_script", fake_run_script)

    result = services.start_deployment(
        server["id"],
        {
            "protocol": DEPLOYMENT_PROTOCOL_HYSTERIA2,
            "proxyPort": 443,
        },
    )
    assert services.wait_for_workers()

    row = services.db.query_one(
        "SELECT status, tls_cert_sha256 FROM deployments WHERE id = ?",
        (result["deployment"]["id"],),
    )
    assert row == {"status": "ready", "tls_cert_sha256": CERT_SHA256}


def test_create_hy2_client_pushes_config_and_builds_link(services, monkeypatch):
    deployment_id = _create_ready_hy2_deployment(services, "user", "203.0.113.81")
    captured: dict = {}

    def fake_push(deployment, config):
        captured["config"] = config

    monkeypatch.setattr(services, "_push_node_config", fake_push)

    client = services.create_client(deployment_id, {"name": "alice"})

    inbound = captured["config"]["inbounds"][0]
    assert inbound["type"] == "hysteria2"
    alice = next(user for user in inbound["users"] if user["name"] == "alice")
    assert len(base64.b64decode(alice["password"])) == 32
    assert inbound["obfs"]["type"] == "salamander"

    parsed = urlparse(client["share_link"])
    assert parsed.scheme == "hy2"
    assert parsed.port == 443
    assert "insecure=1" in parsed.query
    assert "pinSHA256=" in parsed.query
    assert "obfs=salamander" in parsed.query


def test_hy2_subscription_renders_base64_and_mihomo(services, monkeypatch):
    deployment_id = _create_ready_hy2_deployment(services, "sub", "203.0.113.82")
    monkeypatch.setattr(services, "_push_node_config", lambda deployment, config: None)

    client = services.create_client(deployment_id, {"name": "bob"})
    services.update_subscription_config(deployment_id, {"nodeIds": [client["id"]]})

    base64_out = services.render_deployment_subscription(deployment_id, "base64")
    decoded = base64.b64decode(base64_out).decode("utf-8")
    assert decoded.startswith("hy2://")

    mihomo_out = services.render_deployment_subscription(deployment_id, "mihomo")
    config = yaml.safe_load(mihomo_out)
    assert config["proxies"][0]["type"] == "hysteria2"
