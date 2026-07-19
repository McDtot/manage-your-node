import base64
from contextlib import nullcontext
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
from app.xui_api import XuiApiClient


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
            id, server_id, engine, protocol, install_method, panel_port,
            panel_path, panel_username, encrypted_panel_password,
            encrypted_api_token, proxy_port, ss_method, encrypted_ss_password,
            status, subscription_url, created_at, updated_at
        ) VALUES (?, ?, '3x-ui', ?, 'native', 32000,
                  '/panel', 'admin', ?, ?, 8388, ?, ?, 'ready', ?, 'now', 'now')
        """,
        (
            deployment_id,
            server["id"],
            DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
            services.secret_box.seal("panel-password"),
            services.secret_box.seal("api-token"),
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
        host="203.0.113.10",
        port=8388,
        name="tokyo",
    )
    proxy = _mihomo_proxy_from_ss(link, 1, set())
    assert proxy["type"] == "ss"
    assert proxy["cipher"] == DEPLOYMENT_SS_METHOD
    assert proxy["password"] == "server-psk:user-psk"
    assert proxy["server"] == "203.0.113.10"
    assert proxy["port"] == 8388
    assert proxy["udp"] is True


def test_render_subscription_mixes_ss_and_vless_in_mihomo():
    ss_link = ss_share_link(
        method=DEPLOYMENT_SS_METHOD,
        server_password="s",
        user_password="u",
        host="203.0.113.10",
        port=8388,
        name="ss-node",
    )
    vless_link = (
        "vless://11111111-1111-1111-1111-111111111111@203.0.113.20:443"
        "?security=reality&type=tcp&flow=xtls-rprx-vision&pbk=key&sid=ab#vless-node"
    )
    rendered = _render_subscription_links([ss_link, vless_link], "mihomo")
    config = yaml.safe_load(rendered)
    kinds = {proxy["type"] for proxy in config["proxies"]}
    assert kinds == {"ss", "vless"}


def test_create_shadowsocks_inbound_payload(monkeypatch):
    client = XuiApiClient(
        base_url="https://127.0.0.1:32000/panel-path/",
        username="admin",
        password="password",
    )
    calls = []

    def fake_post_json(path, payload, use_auth=True):
        calls.append((path, payload))
        return {"success": True, "obj": {"id": 7}}

    monkeypatch.setattr(client, "post_json", fake_post_json)

    inbound = client.create_shadowsocks_inbound(
        port=8388,
        remark="myn-edge-8388",
        method=DEPLOYMENT_SS_METHOD,
        server_password="server-psk",
    )

    assert inbound["id"] == 7
    path, payload = calls[0]
    assert path == "panel/api/inbounds/add"
    assert payload["protocol"] == "shadowsocks"
    assert payload["settings"]["method"] == DEPLOYMENT_SS_METHOD
    assert payload["settings"]["password"] == "server-psk"
    assert payload["settings"]["network"] == "tcp,udp"
    assert payload["settings"]["clients"] == []


def test_create_ss_client_sends_password_not_uuid(monkeypatch):
    client = XuiApiClient(
        base_url="https://127.0.0.1:32000/panel-path/",
        username="admin",
        password="password",
    )
    payloads = []

    def fake_post_json(path, payload, use_auth=True):
        payloads.append((path, payload))
        return {"success": True}

    monkeypatch.setattr(client, "post_json", fake_post_json)
    monkeypatch.setattr(client, "get_json", lambda _path: {"success": True, "obj": []})

    client.create_ss_client(
        inbound_id=7,
        email="alice",
        password="user-psk",
        sub_id="sub-id",
        quota_bytes=100 * 1024**3,
        expires_ms=0,
        reset_days=30,
    )

    path, payload = payloads[0]
    assert path == "panel/api/clients/add"
    assert payload["client"]["password"] == "user-psk"
    assert payload["client"]["reset"] == 30
    assert "id" not in payload["client"]
    assert "flow" not in payload["client"]


def test_shadowsocks_deployment_persists_protocol_and_secret(services, monkeypatch):
    server = services.create_server(
        {
            "name": "edge-ss-deploy",
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
        {"protocol": DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022, "proxyPort": 8388},
    )["deployment"]
    assert services.wait_for_workers()

    assert deployment["protocol"] == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022
    row = services.db.query_one(
        "SELECT ss_method, encrypted_ss_password FROM deployments WHERE id = ?",
        (deployment["id"],),
    )
    assert row["ss_method"] == DEPLOYMENT_SS_METHOD
    assert len(base64.b64decode(services.secret_box.open(row["encrypted_ss_password"]))) == 32


def test_create_ss_client_builds_local_ss_link_and_calls_xui(services, monkeypatch):
    deployment_id = _create_ready_ss_deployment(services, "user", "203.0.113.71")
    services.db.execute(
        "UPDATE deployments SET xui_inbound_id = 7 WHERE id = ?",
        (deployment_id,),
    )
    created = []

    class FakeXui:
        def wait_ready(self, seconds):
            pass

        def login(self):
            pass

        def create_ss_client(self, **payload):
            created.append(payload)
            return []

    monkeypatch.setattr(services, "_xui_session", lambda _deployment: nullcontext(FakeXui()))

    client = services.create_client(deployment_id, {"name": "alice"})

    assert created[0]["email"] == "alice"
    assert len(base64.b64decode(created[0]["password"])) == 32
    parsed = urlparse(client["share_link"])
    assert parsed.scheme == "ss"
    assert parsed.port == 8388
    userinfo = base64.b64decode(parsed.username).decode("utf-8")
    assert userinfo == f"{DEPLOYMENT_SS_METHOD}:server-psk-value:{created[0]['password']}"


def test_shadowsocks_subscription_renders_base64_and_mihomo(services, monkeypatch):
    deployment_id = _create_ready_ss_deployment(services, "sub", "203.0.113.72")
    monkeypatch.setattr(
        services,
        "_xui_session",
        lambda _deployment: (_ for _ in ()).throw(AssertionError("no xui when not ready")),
    )
    services.db.execute(
        "UPDATE deployments SET xui_inbound_id = NULL WHERE id = ?",
        (deployment_id,),
    )
    client = services.create_client(deployment_id, {"name": "bob"})
    services.update_subscription_config(deployment_id, {"nodeIds": [client["id"]]})

    base64_out = services.render_deployment_subscription(deployment_id, "base64")
    decoded = base64.b64decode(base64_out).decode("utf-8")
    assert decoded.startswith("ss://")

    mihomo_out = services.render_deployment_subscription(deployment_id, "mihomo")
    config = yaml.safe_load(mihomo_out)
    assert config["proxies"][0]["type"] == "ss"
