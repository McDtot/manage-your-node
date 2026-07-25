import sqlite3
from pathlib import Path

import pytest

from app.database import Database


def test_transaction_rolls_back(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    with pytest.raises(RuntimeError), db.transaction():
        db.execute(
            "INSERT INTO subscriptions (id, name, token, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("sub", "name", "token", "now", "now"),
        )
        raise RuntimeError("abort")
    assert db.query_one("SELECT id FROM subscriptions WHERE id = 'sub'") is None


def test_online_backup(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    db.execute(
        "INSERT INTO subscriptions (id, name, token, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        ("sub", "name", "token", "now", "now"),
    )
    target = tmp_path / "backup.sqlite"
    db.backup_to(target)
    backup = Database(Path(target))
    assert backup.query_one("SELECT name FROM subscriptions WHERE id = 'sub'")["name"] == "name"


def test_legacy_json_job_logs_are_migrated(tmp_path):
    path = tmp_path / "legacy-job-logs.sqlite"
    db = Database(path)
    db.execute(
        """
        INSERT INTO jobs (id, type, status, logs, created_at, updated_at)
        VALUES ('job', 'legacy', 'success',
                '[{"at":"2026-01-01T00:00:00+00:00","line":"done"}]',
                'now', 'now')
        """
    )
    db.close()

    upgraded = Database(path)

    assert upgraded.query_one("SELECT logs FROM jobs WHERE id = 'job'")["logs"] == "[]"
    assert upgraded.query_all(
        "SELECT seq, at, line FROM job_logs WHERE job_id = 'job' ORDER BY seq"
    ) == [
        {"seq": 1, "at": "2026-01-01T00:00:00+00:00", "line": "done"}
    ]


def test_deployments_default_to_native_and_retire_legacy_simulations(tmp_path):
    path = tmp_path / "deployment-migration.sqlite"
    db = Database(path)
    db.execute(
        """
        INSERT INTO servers (
            id, name, host, ssh_port, ssh_user, auth_type, secret_label,
            status, created_at, updated_at
        ) VALUES ('server', 'edge', '203.0.113.10', 22, 'root', 'agent',
                  'not_saved', 'reachable', 'now', 'now')
        """
    )
    db.execute(
        """
        INSERT INTO deployments (
            id, server_id, engine, protocol, install_method, proxy_port,
            status, subscription_url, created_at, updated_at
        ) VALUES ('deployment', 'server', 'sing-box', 'VLESS + REALITY',
                  'simulated', 443, 'ready', '/sub/deployments/deployment',
                  'now', 'now')
        """
    )

    upgraded = Database(path)
    row = upgraded.query_one(
        "SELECT install_method, status, last_error FROM deployments WHERE id = 'deployment'"
    )
    columns = {row["name"]: row for row in upgraded.query_all("PRAGMA table_info(deployments)")}

    assert columns["install_method"]["dflt_value"] == "'native'"
    assert row["install_method"] == "legacy"
    assert row["status"] == "failed"
    assert "no longer supported" in row["last_error"]


def test_legacy_3xui_deployments_block_startup(tmp_path, monkeypatch):
    path = tmp_path / "legacy-3xui.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE servers (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            host TEXT NOT NULL,
            ssh_port INTEGER NOT NULL,
            ssh_user TEXT NOT NULL,
            auth_type TEXT NOT NULL,
            encrypted_secret TEXT,
            secret_label TEXT NOT NULL DEFAULT 'not_saved',
            os TEXT,
            arch TEXT,
            status TEXT NOT NULL,
            last_check_at TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE deployments (
            id TEXT PRIMARY KEY,
            server_id TEXT NOT NULL,
            engine TEXT NOT NULL,
            protocol TEXT NOT NULL,
            install_method TEXT NOT NULL DEFAULT 'native',
            panel_port INTEGER NOT NULL,
            panel_path TEXT NOT NULL,
            panel_username TEXT NOT NULL,
            encrypted_panel_password TEXT NOT NULL,
            encrypted_api_token TEXT NOT NULL,
            proxy_port INTEGER NOT NULL,
            status TEXT NOT NULL,
            subscription_url TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        INSERT INTO servers (
            id, name, host, ssh_port, ssh_user, auth_type, status, created_at, updated_at
        ) VALUES ('server', 'edge', '203.0.113.10', 22, 'root', 'agent',
                  'reachable', 'now', 'now');
        INSERT INTO deployments (
            id, server_id, engine, protocol, install_method, panel_port,
            panel_path, panel_username, encrypted_panel_password,
            encrypted_api_token, proxy_port, status, subscription_url,
            created_at, updated_at
        ) VALUES ('deployment', 'server', '3x-ui', 'VLESS + REALITY',
                  'native', 32000, '/panel', 'admin', '', '', 443,
                  'ready', '/sub/x', 'now', 'now');
        """
    )
    connection.commit()
    connection.close()

    monkeypatch.delenv("MYN_FORCE_SINGBOX_MIGRATION", raising=False)
    with pytest.raises(RuntimeError, match="3x-ui deployment"):
        Database(path)

    monkeypatch.setenv("MYN_FORCE_SINGBOX_MIGRATION", "1")
    upgraded = Database(path)
    assert upgraded.query_all("SELECT id FROM deployments") == []


def test_proxy_chain_protocol_columns_migrate_existing_rows(tmp_path):
    path = tmp_path / "legacy.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE proxy_chain_nodes (
            chain_id TEXT NOT NULL,
            deployment_id TEXT NOT NULL,
            position INTEGER NOT NULL,
            inbound_port INTEGER,
            client_uuid TEXT,
            encrypted_private_key TEXT,
            public_key TEXT,
            short_id TEXT,
            remote_service_name TEXT,
            status TEXT NOT NULL DEFAULT 'planned',
            created_at TEXT NOT NULL,
            updated_at TEXT,
            PRIMARY KEY(chain_id, position),
            UNIQUE(chain_id, deployment_id)
        );
        INSERT INTO proxy_chain_nodes (
            chain_id, deployment_id, position, created_at
        ) VALUES ('legacy-chain', 'legacy-deployment', 0, 'now');
        """
    )
    connection.commit()
    connection.close()

    db = Database(path)
    row = db.query_one(
        """
        SELECT inbound_protocol, ss_method, encrypted_ss_password
        FROM proxy_chain_nodes
        WHERE chain_id = 'legacy-chain'
        """
    )
    assert row == {
        "inbound_protocol": "vless_reality",
        "ss_method": "2022-blake3-aes-256-gcm",
        "encrypted_ss_password": None,
    }


def test_reality_and_config_hash_columns_migrate(tmp_path):
    path = tmp_path / "legacy-reality.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE deployments (
            id TEXT PRIMARY KEY,
            server_id TEXT NOT NULL,
            engine TEXT NOT NULL,
            protocol TEXT NOT NULL,
            install_method TEXT NOT NULL DEFAULT 'native',
            proxy_port INTEGER NOT NULL,
            status TEXT NOT NULL,
            subscription_url TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    connection.commit()
    connection.close()

    db = Database(path)
    columns = {row["name"]: row for row in db.query_all("PRAGMA table_info(deployments)")}
    for name in (
        "encrypted_reality_private_key",
        "reality_public_key",
        "reality_short_id",
        "tls_cert_sha256",
        "last_config_hash",
    ):
        assert columns[name]["notnull"] == 1


def test_unpinned_self_signed_tls_deployments_are_invalidated(tmp_path):
    path = tmp_path / "unpinned-tls.sqlite"
    db = Database(path)
    db.execute(
        """
        INSERT INTO servers (
            id, name, host, ssh_port, ssh_user, auth_type, secret_label,
            status, created_at, updated_at
        ) VALUES ('server', 'edge', '203.0.113.10', 22, 'root', 'agent',
                  'not_saved', 'reachable', 'now', 'now')
        """
    )
    for protocol in ("AnyTLS", "Hysteria2", "VMess"):
        deployment_id = f"deployment-{protocol.lower()}"
        client_id = f"client-{protocol.lower()}"
        db.execute(
            """
            INSERT INTO deployments (
                id, server_id, engine, protocol, install_method, proxy_port,
                anytls_domain, tls_cert_sha256, status, subscription_url,
                created_at, updated_at
            ) VALUES (?, 'server', 'sing-box', ?, 'native', 443, '', '',
                      'ready', ?, 'now', 'now')
            """,
            (deployment_id, protocol, f"/sub/deployments/{deployment_id}"),
        )
        db.execute(
            """
            INSERT INTO clients (
                id, deployment_id, name, uuid, expires_at, enabled,
                share_link, subscription_url, created_at, updated_at
            ) VALUES (?, ?, 'alice', 'bf000d23-0752-40b4-affe-68f7707a9661',
                      '', 1, 'unsafe-link', '', 'now', 'now')
            """,
            (client_id, deployment_id),
        )
    db.execute(
        """
        INSERT INTO deployments (
            id, server_id, engine, protocol, install_method, proxy_port,
            anytls_domain, tls_cert_sha256, status, subscription_url,
            created_at, updated_at
        ) VALUES ('deployment-pinned', 'server', 'sing-box', 'Hysteria2',
                  'native', 8443, '', ?, 'ready', '', 'now', 'now')
        """,
        (":".join(["AA"] * 32),),
    )
    db.close()

    upgraded = Database(path)
    invalidated = upgraded.query_all(
        """
        SELECT d.protocol, d.status, d.last_error, c.share_link
        FROM deployments d
        JOIN clients c ON c.deployment_id = d.id
        WHERE d.id != 'deployment-pinned'
        ORDER BY d.protocol
        """
    )
    assert invalidated == [
        {
            "protocol": "AnyTLS",
            "status": "failed",
            "last_error": (
                "Self-signed TLS certificate is not pinned; "
                "delete and redeploy this node."
            ),
            "share_link": "",
        },
        {
            "protocol": "Hysteria2",
            "status": "failed",
            "last_error": (
                "Self-signed TLS certificate is not pinned; "
                "delete and redeploy this node."
            ),
            "share_link": "",
        },
        {
            "protocol": "VMess",
            "status": "failed",
            "last_error": (
                "Self-signed TLS certificate is not pinned; "
                "delete and redeploy this node."
            ),
            "share_link": "",
        },
    ]
    assert upgraded.query_one(
        "SELECT status FROM deployments WHERE id = 'deployment-pinned'"
    )["status"] == "ready"


def test_subscription_display_names_migrate_existing_tables(tmp_path):
    path = tmp_path / "legacy-subscription-names.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE subscription_nodes (
            subscription_id TEXT NOT NULL,
            node_client_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(subscription_id, node_client_id)
        );
        CREATE TABLE subscription_entries (
            subscription_id TEXT NOT NULL,
            node_client_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL,
            PRIMARY KEY(subscription_id, node_client_id)
        );
        CREATE TABLE subscription_chain_entries (
            subscription_id TEXT NOT NULL,
            chain_id TEXT NOT NULL,
            created_at TEXT NOT NULL,
            PRIMARY KEY(subscription_id, chain_id)
        );
        """
    )
    connection.commit()
    connection.close()

    db = Database(path)
    node_columns = {
        row["name"]: row for row in db.query_all("PRAGMA table_info(subscription_nodes)")
    }
    entry_columns = {
        row["name"]: row for row in db.query_all("PRAGMA table_info(subscription_entries)")
    }
    chain_columns = {
        row["name"]: row
        for row in db.query_all("PRAGMA table_info(subscription_chain_entries)")
    }
    assert node_columns["display_name"]["dflt_value"] == "''"
    assert entry_columns["display_name"]["dflt_value"] == "''"
    assert "quota_bytes" not in entry_columns
    assert chain_columns["display_name"]["dflt_value"] == "''"
