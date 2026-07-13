import pytest

from app.database import Database
from app.security import SecretBox
from app.services import AppServices, reality_dest, reality_server_name


@pytest.fixture
def services(tmp_path):
    db = Database(tmp_path / "test.db")
    return AppServices(db, SecretBox("a-long-test-secret-value"))


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
    assert ":" in reality_dest()
    assert reality_server_name() == reality_dest().split(":", 1)[0]


def test_reality_overrides(monkeypatch):
    monkeypatch.setenv("REALITY_DEST", "example.org:8443")
    monkeypatch.delenv("REALITY_SNI", raising=False)
    assert reality_dest() == "example.org:8443"
    assert reality_server_name() == "example.org"
    monkeypatch.setenv("REALITY_SNI", "cdn.example.org")
    assert reality_server_name() == "cdn.example.org"


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
