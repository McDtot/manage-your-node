import sqlite3
from pathlib import Path

import pytest

from app.database import Database


def test_transaction_rolls_back(tmp_path):
    db = Database(tmp_path / "db.sqlite")
    with pytest.raises(RuntimeError):
        with db.transaction():
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


def test_client_traffic_reset_period_migrates_existing_table(tmp_path):
    path = tmp_path / "legacy-clients.sqlite"
    connection = sqlite3.connect(path)
    connection.executescript(
        """
        CREATE TABLE clients (
            id TEXT PRIMARY KEY,
            deployment_id TEXT NOT NULL,
            name TEXT NOT NULL,
            uuid TEXT NOT NULL,
            quota_bytes INTEGER NOT NULL,
            used_bytes INTEGER NOT NULL,
            expires_at TEXT NOT NULL,
            enabled INTEGER NOT NULL,
            share_link TEXT NOT NULL,
            subscription_url TEXT NOT NULL,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )
    connection.commit()
    connection.close()

    db = Database(path)
    columns = {row["name"]: row for row in db.query_all("PRAGMA table_info(clients)")}

    assert columns["traffic_reset_days"]["notnull"] == 1
    assert columns["traffic_reset_days"]["dflt_value"] == "0"
