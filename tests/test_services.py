import base64

import pytest
import yaml

from app.database import Database
from app.security import SecretBox
from app.services import (
    CHAIN_PROTOCOL_SHADOWSOCKS_2022,
    CHAIN_PROTOCOL_VLESS_REALITY,
    CHAIN_SS_METHOD,
    DEFAULT_REALITY_CANDIDATES,
    AppServices,
    _normalize_client_share_link_host,
    _redact_native_install_log,
    parse_reality_destination,
    reality_candidates,
    reality_dest,
    reality_server_name,
)


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
        ) VALUES (?, ?, '3x-ui', 'VLESS + REALITY', 'dry-run', 32000,
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


def test_summary_empty(services):
    summary = services.summary()
    assert summary["servers"] == 0
    assert summary["clients"] == 0


def test_wrong_master_secret_is_rejected(tmp_path):
    db = Database(tmp_path / "keys.db")
    AppServices(db, SecretBox("first-long-secret"))
    with pytest.raises(RuntimeError, match="APP_SECRET does not match"):
        AppServices(db, SecretBox("different-long-secret"))


def test_create_and_list_server(services):
    server = services.create_server(
        {
            "name": "edge-1",
            "host": "203.0.113.10",
            "sshPort": 22,
            "sshUser": "root",
            "authType": "key",
            "secret": "dummy-key-material",
        }
    )
    assert server["name"] == "edge-1"
    assert server["secret_label"] == "saved"
    listed = services.list_servers()
    assert len(listed) == 1
    # Secret material must never be returned to callers.
    assert "encrypted_secret" not in listed[0]
    assert "secret" not in listed[0]


def test_host_key_requires_explicit_approval(services):
    server = services.create_server(
        {
            "name": "edge",
            "host": "203.0.113.10",
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    services.db.execute(
        """
        INSERT INTO ssh_host_keys (server_id, key_type, key_base64, fingerprint, trusted, created_at)
        VALUES (?, 'ssh-ed25519', 'AA==', 'SHA256:example', 0, 'now')
        """,
        (server["id"],),
    )
    pending = services.get_server(server["id"])
    assert pending["host_key_trusted"] == 0
    approved = services.approve_server_host_key(server["id"])
    assert approved["host_key_trusted"] == 1


def test_deployment_list_does_not_expose_control_credentials(services):
    server = services.create_server(
        {
            "name": "edge",
            "host": "203.0.113.10",
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )
    services.db.execute(
        """
        INSERT INTO deployments (
            id, server_id, engine, protocol, panel_port, panel_path, panel_username,
            encrypted_panel_password, encrypted_api_token, proxy_port, status,
            subscription_url, created_at, updated_at
        ) VALUES ('dep', ?, '3x-ui', 'VLESS + REALITY', 32000, '/panel', 'admin',
                  ?, ?, 443, 'ready', '/sub/deployments/dep', 'now', 'now')
        """,
        (
            server["id"],
            services.secret_box.seal("panel-password"),
            services.secret_box.seal("api-token"),
        ),
    )
    deployment = services.list_deployments()[0]
    assert "panel_password" not in deployment
    assert "api_token" not in deployment
    assert "encrypted_panel_password" not in deployment
    assert "encrypted_api_token" not in deployment


def test_one_node_supports_multiple_users(services):
    deployment_id = _create_ready_deployment(
        services,
        "multi-user",
        "203.0.113.25",
    )
    services._ensure_deployment_subscription(deployment_id, "edge-multi-user")

    first = services.create_client(
        deployment_id,
        {"name": "alice", "quotaGb": 100, "expiresAt": "2030-01-01"},
    )
    second = services.create_client(
        deployment_id,
        {"name": "bob", "quotaGb": 200, "expiresAt": "2030-02-01"},
    )

    users = [
        item for item in services.list_clients()
        if item["deployment_id"] == deployment_id
    ]
    assert {item["name"] for item in users} == {"alice", "bob"}
    assert first["uuid"] != second["uuid"]
    assert services.list_deployments()[0]["client_count"] == 2


def test_user_names_are_unique_within_a_node(services):
    deployment_id = _create_ready_deployment(
        services,
        "unique-user",
        "203.0.113.26",
    )
    services._ensure_deployment_subscription(deployment_id, "edge-unique-user")
    services.create_client(deployment_id, {"name": "Alice"})

    with pytest.raises(ValueError, match="该节点已存在同名用户"):
        services.create_client(deployment_id, {"name": "alice"})

    second = services.create_client(deployment_id, {"name": "Bob"})
    with pytest.raises(ValueError, match="该节点已存在同名用户"):
        services.update_client(second["id"], {"name": "ALICE"})


def test_subscription_lifecycle(services):
    sub = services.create_subscription({"name": "my-sub"})
    assert sub["name"] == "my-sub"
    assert sub["subscription_url"].startswith("/sub/links/")
    assert any(s["id"] == sub["id"] for s in services.list_subscriptions())
    services.delete_subscription(sub["id"])
    assert all(s["id"] != sub["id"] for s in services.list_subscriptions())


def test_subscription_token_rotation_invalidates_old_url(services):
    subscription = services.create_subscription({"name": "private"})
    old_token = subscription["token"]
    rotated = services.rotate_subscription_token(subscription["id"])
    assert rotated["token"] != old_token
    with pytest.raises(ValueError, match="subscription not found"):
        services.render_managed_subscription(old_token)


def test_recover_orphaned_jobs(services):
    db = services.db
    db.execute(
        "INSERT INTO servers (id,name,host,ssh_port,ssh_user,auth_type,status,created_at,updated_at)"
        " VALUES ('srv1','n','h',22,'u','key','new','t','t')"
    )
    db.execute(
        "INSERT INTO deployments (id,server_id,engine,protocol,panel_port,panel_path,panel_username,"
        "encrypted_panel_password,encrypted_api_token,proxy_port,status,subscription_url,created_at,updated_at)"
        " VALUES ('dep1','srv1','3x-ui','v',1,'/p','u','','',443,'provisioning','/x','t','t')"
    )
    db.execute(
        "INSERT INTO jobs (id,type,status,logs,created_at,updated_at)"
        " VALUES ('job1','deploy_3xui','running','[]','t','t')"
    )
    db.execute(
        "INSERT INTO operation_locks (resource_type,resource_id,job_id,acquired_at)"
        " VALUES ('server','srv1','job1','t')"
    )
    assert services.recover_orphaned_jobs() == 1
    assert db.query_one("SELECT status FROM jobs WHERE id='job1'")["status"] == "failed"
    assert db.query_one("SELECT status FROM deployments WHERE id='dep1'")["status"] == "failed"
    assert db.query_one("SELECT job_id FROM operation_locks WHERE job_id='job1'") is None


def test_reality_defaults(monkeypatch):
    monkeypatch.delenv("REALITY_DEST", raising=False)
    monkeypatch.delenv("REALITY_SNI", raising=False)
    assert reality_dest() == "www.yahoo.com:443"
    assert reality_server_name() == reality_dest().split(":", 1)[0]


def test_reality_overrides(monkeypatch):
    monkeypatch.setenv("REALITY_DEST", "example.org:8443")
    monkeypatch.delenv("REALITY_SNI", raising=False)
    assert reality_dest() == "example.org:8443"
    assert reality_server_name() == "example.org"
    monkeypatch.setenv("REALITY_SNI", "cdn.example.org")
    assert reality_server_name() == "cdn.example.org"


def test_reality_auto_candidates_and_validation(monkeypatch):
    monkeypatch.delenv("REALITY_CANDIDATES", raising=False)
    monkeypatch.delenv("REALITY_DEST", raising=False)
    monkeypatch.delenv("REALITY_SNI", raising=False)
    assert [target for target, _ in reality_candidates()] == list(
        DEFAULT_REALITY_CANDIDATES
    )

    monkeypatch.setenv(
        "REALITY_CANDIDATES",
        "Example.org:443, www.example.net:8443,example.org:443",
    )
    assert reality_candidates() == [
        ("example.org:443", "example.org"),
        ("www.example.net:8443", "www.example.net"),
    ]
    assert parse_reality_destination("[2001:db8::1]:443") == (
        "[2001:db8::1]:443",
        "2001:db8::1",
    )
    with pytest.raises(ValueError, match="host:port"):
        parse_reality_destination("https://example.org")


def test_deployment_persists_auto_and_manual_reality_settings(services, monkeypatch):
    server = services.create_server(
        {
            "name": "edge",
            "host": "203.0.113.50",
            "sshPort": 22,
            "sshUser": "deploy",
            "authType": "agent",
        }
    )

    def finish_without_worker(job_id, deployment_id, _server, _payload):
        services.db.execute(
            "UPDATE deployments SET status = 'ready' WHERE id = ?",
            (deployment_id,),
        )
        services._finish_job(job_id, "success", None)
        services._release_operation_locks(job_id)

    monkeypatch.setattr(services, "_run_deployment", finish_without_worker)
    monkeypatch.setenv("REALITY_CANDIDATES", "auto.example:443,backup.example:443")

    automatic = services.start_deployment(
        server["id"],
        {
            "installMethod": "dry-run",
            "panelPort": "",
            "realityMode": "auto",
        },
    )["deployment"]
    assert automatic["reality_mode"] == "auto"
    assert automatic["reality_dest"] == "auto.example:443"
    assert automatic["reality_sni"] == "auto.example"
    assert services.wait_for_workers()

    manual = services.start_deployment(
        server["id"],
        {
            "installMethod": "dry-run",
            "realityMode": "manual",
            "realityDest": "Manual.Example:8443",
            "realitySni": "Cover.Example",
        },
    )["deployment"]
    assert manual["reality_mode"] == "manual"
    assert manual["reality_dest"] == "manual.example:8443"
    assert manual["reality_sni"] == "cover.example"
    assert services.wait_for_workers()


def test_native_reality_target_probe_is_persisted(services, monkeypatch):
    deployment_id = _create_ready_deployment(services, "probe", "203.0.113.60")
    services.db.execute(
        "UPDATE deployments SET reality_mode = 'auto', reality_dest = '', reality_sni = '' "
        "WHERE id = ?",
        (deployment_id,),
    )
    services.db.execute(
        "INSERT INTO jobs (id,type,status,logs,created_at,updated_at) "
        "VALUES ('probe-job','deploy_3xui','running','[]','now','now')"
    )
    monkeypatch.setenv("REALITY_CANDIDATES", "first.example:443,second.example:443")

    def choose_second(_server, script, log, timeout):
        assert "-tls1_3" in script
        assert "-verify_hostname" in script
        assert timeout >= 90
        log("Rejected REALITY target first.example:443")
        log("__MYN_REALITY_SELECTED__=1")
        return ["Rejected REALITY target first.example:443", "__MYN_REALITY_SELECTED__=1"]

    monkeypatch.setattr(services.ssh, "run_script", choose_second)
    deployment = services.get_deployment(deployment_id)
    selected = services._resolve_reality_target(
        "probe-job",
        deployment_id,
        {"host": "203.0.113.60"},
        deployment,
    )
    assert selected == ("second.example:443", "second.example")
    stored = services.get_deployment(deployment_id)
    assert stored["reality_dest"] == "second.example:443"
    assert stored["reality_sni"] == "second.example"


def test_native_installer_logs_redact_colorized_credentials():
    api_line = "\x1b[0;32mAPI Token: leaked-token\x1b[0m"
    password_line = "\x1b[0;32mPassword: leaked-password\x1b[0m"
    result_line = "XUI_API_TOKEN=leaked-result-token"

    assert "leaked-token" not in _redact_native_install_log(api_line, "panel-password")
    assert "leaked-password" not in _redact_native_install_log(password_line, "panel-password")
    assert "leaked-result-token" not in _redact_native_install_log(
        result_line,
        "panel-password",
    )


def test_native_client_link_uses_managed_server_host():
    link = (
        "vless://client-id@127.0.0.1:443"
        "?security=reality&pbk=example#client"
    )
    normalized = _normalize_client_share_link_host(link, "2001:db8::10")

    assert normalized.startswith("vless://client-id@[2001:db8::10]:443?")
    assert normalized.endswith("#client")


@pytest.mark.parametrize(
    ("lines", "expected"),
    [
        (
            ["Private key: old-private", "Public key: old-public"],
            ("old-private", "old-public"),
        ),
        (
            [
                "PrivateKey: new-private",
                "Password (PublicKey): new-public",
                "Hash32: ignored",
            ],
            ("new-private", "new-public"),
        ),
    ],
)
def test_x25519_keypair_accepts_old_and_new_xray_output(
    services,
    monkeypatch,
    lines,
    expected,
):
    monkeypatch.setattr(
        services.ssh,
        "run_script",
        lambda server, script, log, timeout: lines,
    )

    assert services._remote_x25519_keypair({"server_name": "edge"}) == expected


def test_proxy_chain_failure_triggers_cleanup(services, monkeypatch):
    cleaned: list[str] = []
    monkeypatch.setattr(
        services,
        "_cleanup_proxy_chain_services",
        lambda chain_id: cleaned.append(chain_id) or ["cleaned"],
    )
    db = services.db
    db.execute(
        "INSERT INTO proxy_chains (id,name,token,client_uuid,status,share_link,created_at,updated_at)"
        " VALUES ('chain1','c','tok','uuid','deploying','','t','t')"
    )
    db.execute(
        "INSERT INTO jobs (id,type,chain_id,status,logs,created_at,updated_at)"
        " VALUES ('job1','deploy_proxy_chain','chain1','running','[]','t','t')"
    )
    # Fewer than two nodes → deployment fails and should roll back.
    services._run_proxy_chain_deployment("job1", "chain1")
    assert cleaned == ["chain1"]
    chain = db.query_one("SELECT status, last_error FROM proxy_chains WHERE id='chain1'")
    assert chain["status"] == "failed"
    assert "at least two" in (chain["last_error"] or "")
    job = db.query_one("SELECT status, logs FROM jobs WHERE id='job1'")
    assert job["status"] == "failed"
    assert "Rolling back" in job["logs"]


def test_mixed_proxy_chain_uses_ss2022_between_overseas_nodes(services):
    deployment_ids = [
        _create_ready_deployment(services, "hk", "198.51.100.10"),
        _create_ready_deployment(services, "jp", "198.51.100.20"),
        _create_ready_deployment(services, "us", "198.51.100.30"),
    ]
    services.db.execute(
        "UPDATE deployments SET reality_dest = 'entry.example:443', "
        "reality_sni = 'entry.example' WHERE id = ?",
        (deployment_ids[0],),
    )
    services.db.execute(
        "UPDATE deployments SET reality_dest = 'exit.example:8443', "
        "reality_sni = 'cover.exit.example' WHERE id = ?",
        (deployment_ids[2],),
    )
    chain = services.create_proxy_chain(
        {
            "name": "mixed-chain",
            "deploymentIds": deployment_ids,
            "linkProtocols": [
                CHAIN_PROTOCOL_SHADOWSOCKS_2022,
                CHAIN_PROTOCOL_VLESS_REALITY,
            ],
        }
    )

    assert [node["inbound_protocol"] for node in chain["nodes"]] == [
        CHAIN_PROTOCOL_VLESS_REALITY,
        CHAIN_PROTOCOL_SHADOWSOCKS_2022,
        CHAIN_PROTOCOL_VLESS_REALITY,
    ]
    assert [hop["protocol"] for hop in chain["hops"]] == [
        CHAIN_PROTOCOL_SHADOWSOCKS_2022,
        CHAIN_PROTOCOL_VLESS_REALITY,
    ]
    assert all("encrypted_ss_password" not in node for node in chain["nodes"])

    started = services.start_proxy_chain_deployment(chain["id"])
    assert services.wait_for_workers()
    assert services.get_job(started["job"]["id"])["status"] == "success"

    nodes = services._proxy_chain_full_nodes(chain["id"])
    assert nodes[0]["encrypted_private_key"]
    assert nodes[1]["encrypted_ss_password"]
    assert nodes[1]["ss_method"] == CHAIN_SS_METHOD
    assert len(services.secret_box.open(nodes[1]["encrypted_ss_password"])) == 44
    assert not nodes[1]["encrypted_private_key"]
    assert nodes[2]["encrypted_private_key"]

    entry_config = services._chain_xray_config(nodes[0], nodes[1])
    assert entry_config["inbounds"][0]["protocol"] == "vless"
    assert "listen" not in entry_config["inbounds"][0]
    assert entry_config["inbounds"][0]["streamSettings"]["network"] == "raw"
    assert (
        entry_config["inbounds"][0]["streamSettings"]["realitySettings"]["target"]
        == "entry.example:443"
    )
    assert entry_config["outbounds"][0]["protocol"] == "shadowsocks"
    assert entry_config["outbounds"][0]["settings"]["servers"] == [
        {
            "address": "198.51.100.20",
            "port": nodes[1]["inbound_port"],
            "method": CHAIN_SS_METHOD,
            "password": services.secret_box.open(nodes[1]["encrypted_ss_password"]),
        }
    ]

    relay_config = services._chain_xray_config(nodes[1], nodes[2])
    assert relay_config["inbounds"][0]["protocol"] == "shadowsocks"
    assert "listen" not in relay_config["inbounds"][0]
    assert relay_config["inbounds"][0]["settings"]["network"] == "tcp,udp"
    assert relay_config["outbounds"][0]["protocol"] == "vless"
    assert relay_config["outbounds"][0]["streamSettings"]["network"] == "raw"
    reality = relay_config["outbounds"][0]["streamSettings"]["realitySettings"]
    assert reality["password"] == nodes[2]["public_key"]
    assert reality["serverName"] == "cover.exit.example"
    assert "publicKey" not in reality

    exit_config = services._chain_xray_config(nodes[2], None)
    assert exit_config["inbounds"][0]["protocol"] == "vless"
    assert exit_config["outbounds"][0]["protocol"] == "freedom"
    share_link = services.get_proxy_chain(chain["id"])["share_link"]
    assert share_link.startswith("vless://")
    assert "sni=entry.example" in share_link


def test_proxy_chain_protocol_validation_and_legacy_default(services):
    deployment_ids = [
        _create_ready_deployment(services, "one", "203.0.113.11"),
        _create_ready_deployment(services, "two", "203.0.113.12"),
    ]
    with pytest.raises(ValueError, match="one protocol per server-to-server hop"):
        services.create_proxy_chain(
            {
                "deploymentIds": deployment_ids,
                "linkProtocols": [],
            }
        )
    with pytest.raises(ValueError, match="unsupported chain protocol"):
        services.create_proxy_chain(
            {
                "deploymentIds": deployment_ids,
                "linkProtocols": ["plain-text"],
            }
        )

    legacy_chain = services.create_proxy_chain({"deploymentIds": deployment_ids})
    assert [node["inbound_protocol"] for node in legacy_chain["nodes"]] == [
        CHAIN_PROTOCOL_VLESS_REALITY,
        CHAIN_PROTOCOL_VLESS_REALITY,
    ]


def test_proxy_chain_subscription_is_unavailable_until_deployed(services):
    deployment_ids = [
        _create_ready_deployment(services, "entry", "203.0.113.21"),
        _create_ready_deployment(services, "exit", "203.0.113.22"),
    ]
    chain = services.create_proxy_chain({"deploymentIds": deployment_ids})

    with pytest.raises(ValueError, match="proxy chain is not ready"):
        services.render_proxy_chain_subscription(chain["token"])

    services.db.execute(
        "UPDATE proxy_chains SET share_link = ? WHERE id = ?",
        ("vless://ready-chain", chain["id"]),
    )
    rendered = services.render_proxy_chain_subscription(chain["token"])
    assert base64.b64decode(rendered).decode("utf-8") == "vless://ready-chain"


def test_proxy_chain_subscription_renders_mihomo_yaml(services):
    deployment_ids = [
        _create_ready_deployment(services, "entry-yaml", "203.0.113.31"),
        _create_ready_deployment(services, "exit-yaml", "203.0.113.32"),
    ]
    chain = services.create_proxy_chain({"deploymentIds": deployment_ids})
    share_link = (
        "vless://11111111-2222-3333-4444-555555555555@203.0.113.31:443"
        "?security=reality&type=tcp&flow=xtls-rprx-vision"
        "&pbk=dE8nfT3BBGpvTndPFXrdC3bSRHHQf5veZBKF31ZbWeo"
        "&fp=chrome&sni=cover.example&sid=a1b2c3d4#测试代理链"
    )
    services.db.execute(
        "UPDATE proxy_chains SET share_link = ? WHERE id = ?",
        (share_link, chain["id"]),
    )

    config = yaml.safe_load(services.render_proxy_chain_subscription(chain["token"], "mihomo"))
    proxy = config["proxies"][0]
    assert proxy == {
        "name": "测试代理链",
        "type": "vless",
        "server": "203.0.113.31",
        "port": 443,
        "uuid": "11111111-2222-3333-4444-555555555555",
        "udp": True,
        "flow": "xtls-rprx-vision",
        "packet-encoding": "xudp",
        "tls": True,
        "servername": "cover.example",
        "client-fingerprint": "chrome",
        "reality-opts": {
            "public-key": "dE8nfT3BBGpvTndPFXrdC3bSRHHQf5veZBKF31ZbWeo",
            "short-id": "a1b2c3d4",
        },
        "encryption": "",
        "network": "tcp",
    }
    assert config["proxy-groups"][0]["proxies"] == [
        "AUTO",
        "DIRECT",
        "测试代理链",
    ]
    assert config["rules"] == ["MATCH,PROXY"]

    with pytest.raises(ValueError, match="unsupported subscription format"):
        services.render_proxy_chain_subscription(chain["token"], "sing-box")


def test_ss2022_chain_install_script_opens_udp_firewall_rules(services):
    install_script = services._chain_install_script(
        "myn-chain-test",
        45000,
        {"inbounds": [], "outbounds": []},
        allow_udp=True,
    )
    # Xray 26.5.9 infers the config format from the final extension.
    assert 'TMP_CONFIG="$INSTALL_DIR/config.tmp.json"' in install_script
    assert 'run -test -config "$TMP_CONFIG"' in install_script
    assert "ufw allow 45000/udp" in install_script
    assert "--add-port=45000/udp" in install_script
