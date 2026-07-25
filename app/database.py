import json
import os
import sqlite3
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any


class Database:
    def __init__(self, db_path: Path):
        self._lock = threading.RLock()
        self._state = threading.local()
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._conn.execute("PRAGMA synchronous = NORMAL")
        self._conn.execute("PRAGMA busy_timeout = 5000")
        self._migrate()

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS servers (
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
                    last_latency_ms INTEGER,
                    last_health_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS ssh_host_keys (
                    server_id TEXT PRIMARY KEY,
                    key_type TEXT NOT NULL,
                    key_base64 TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS deployments (
                    id TEXT PRIMARY KEY,
                    server_id TEXT NOT NULL,
                    engine TEXT NOT NULL,
                    protocol TEXT NOT NULL,
                    install_method TEXT NOT NULL DEFAULT 'native',
                    proxy_port INTEGER NOT NULL,
                    reality_mode TEXT NOT NULL DEFAULT 'manual',
                    reality_dest TEXT NOT NULL DEFAULT '',
                    reality_sni TEXT NOT NULL DEFAULT '',
                    encrypted_reality_private_key TEXT NOT NULL DEFAULT '',
                    reality_public_key TEXT NOT NULL DEFAULT '',
                    reality_short_id TEXT NOT NULL DEFAULT '',
                    ss_method TEXT NOT NULL DEFAULT '2022-blake3-aes-256-gcm',
                    encrypted_ss_password TEXT NOT NULL DEFAULT '',
                    encrypted_hy2_obfs_password TEXT NOT NULL DEFAULT '',
                    anytls_domain TEXT NOT NULL DEFAULT '',
                    last_config_hash TEXT NOT NULL DEFAULT '',
                    subscription_configured INTEGER NOT NULL DEFAULT 0,
                    status TEXT NOT NULL,
                    subscription_url TEXT NOT NULL,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS clients (
                    id TEXT PRIMARY KEY,
                    deployment_id TEXT NOT NULL,
                    name TEXT NOT NULL,
                    uuid TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
                    encrypted_ss_password TEXT NOT NULL DEFAULT '',
                    encrypted_anytls_password TEXT NOT NULL DEFAULT '',
                    share_link TEXT NOT NULL,
                    subscription_url TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS subscription_nodes (
                    subscription_id TEXT NOT NULL,
                    node_client_id TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(subscription_id, node_client_id),
                    FOREIGN KEY(subscription_id) REFERENCES deployments(id) ON DELETE CASCADE,
                    FOREIGN KEY(node_client_id) REFERENCES clients(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS subscriptions (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS subscription_entries (
                    subscription_id TEXT NOT NULL,
                    node_client_id TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY(subscription_id, node_client_id),
                    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
                    FOREIGN KEY(node_client_id) REFERENCES clients(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS jobs (
                    id TEXT PRIMARY KEY,
                    type TEXT NOT NULL,
                    server_id TEXT,
                    deployment_id TEXT,
                    status TEXT NOT NULL,
                    logs TEXT NOT NULL,
                    error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    finished_at TEXT,
                    FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE SET NULL,
                    FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE SET NULL
                );

                CREATE TABLE IF NOT EXISTS job_logs (
                    job_id TEXT NOT NULL,
                    seq INTEGER NOT NULL,
                    at TEXT NOT NULL,
                    line TEXT NOT NULL,
                    PRIMARY KEY(job_id, seq),
                    FOREIGN KEY(job_id) REFERENCES jobs(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS proxy_chains (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    token TEXT NOT NULL UNIQUE,
                    client_uuid TEXT NOT NULL,
                    status TEXT NOT NULL,
                    share_link TEXT NOT NULL,
                    last_error TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS proxy_chain_nodes (
                    chain_id TEXT NOT NULL,
                    deployment_id TEXT NOT NULL,
                    position INTEGER NOT NULL,
                    inbound_protocol TEXT NOT NULL DEFAULT 'vless_reality',
                    inbound_port INTEGER,
                    client_uuid TEXT,
                    encrypted_private_key TEXT,
                    public_key TEXT,
                    short_id TEXT,
                    ss_method TEXT NOT NULL DEFAULT '2022-blake3-aes-256-gcm',
                    encrypted_ss_password TEXT,
                    encrypted_hy2_password TEXT,
                    remote_service_name TEXT,
                    status TEXT NOT NULL DEFAULT 'planned',
                    created_at TEXT NOT NULL,
                    updated_at TEXT,
                    PRIMARY KEY(chain_id, position),
                    UNIQUE(chain_id, deployment_id),
                    FOREIGN KEY(chain_id) REFERENCES proxy_chains(id) ON DELETE CASCADE,
                    FOREIGN KEY(deployment_id) REFERENCES deployments(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS subscription_chain_entries (
                    subscription_id TEXT NOT NULL,
                    chain_id TEXT NOT NULL,
                    display_name TEXT NOT NULL DEFAULT '',
                    created_at TEXT NOT NULL,
                    PRIMARY KEY(subscription_id, chain_id),
                    FOREIGN KEY(subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE,
                    FOREIGN KEY(chain_id) REFERENCES proxy_chains(id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS login_rate_limits (
                    client_key TEXT PRIMARY KEY,
                    failures TEXT NOT NULL,
                    locked_until REAL NOT NULL DEFAULT 0,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    client_ip TEXT NOT NULL,
                    method TEXT NOT NULL,
                    path TEXT NOT NULL,
                    status INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS operation_locks (
                    resource_type TEXT NOT NULL,
                    resource_id TEXT NOT NULL,
                    job_id TEXT NOT NULL,
                    acquired_at TEXT NOT NULL,
                    PRIMARY KEY(resource_type, resource_id)
                );

                CREATE TABLE IF NOT EXISTS app_metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TRIGGER IF NOT EXISTS trg_proxy_chain_node_delete
                AFTER DELETE ON proxy_chain_nodes
                BEGIN
                    DELETE FROM proxy_chains WHERE id = OLD.chain_id;
                END;

                CREATE INDEX IF NOT EXISTS idx_deployments_server
                    ON deployments(server_id);
                CREATE INDEX IF NOT EXISTS idx_clients_deployment
                    ON clients(deployment_id);
                CREATE INDEX IF NOT EXISTS idx_subscription_nodes_client
                    ON subscription_nodes(node_client_id);
                CREATE INDEX IF NOT EXISTS idx_subscription_entries_client
                    ON subscription_entries(node_client_id);
                CREATE INDEX IF NOT EXISTS idx_jobs_server
                    ON jobs(server_id);
                CREATE INDEX IF NOT EXISTS idx_proxy_chain_nodes_deployment
                    ON proxy_chain_nodes(deployment_id);
                CREATE INDEX IF NOT EXISTS idx_subscription_chain_entries_chain
                    ON subscription_chain_entries(chain_id);
                CREATE INDEX IF NOT EXISTS idx_audit_events_at
                    ON audit_events(at);
                CREATE INDEX IF NOT EXISTS idx_operation_locks_job
                    ON operation_locks(job_id);
                """
            )
            self._assert_no_legacy_engine()
            self._ensure_column("deployments", "install_method", "TEXT NOT NULL DEFAULT 'native'")
            self._ensure_column("servers", "last_latency_ms", "INTEGER")
            self._ensure_column("servers", "last_health_error", "TEXT")
            self._ensure_column("ssh_host_keys", "trusted", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column("deployments", "subscription_configured", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(
                "deployments",
                "reality_mode",
                "TEXT NOT NULL DEFAULT 'manual'",
            )
            self._ensure_column("deployments", "reality_dest", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("deployments", "reality_sni", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(
                "deployments",
                "ss_method",
                "TEXT NOT NULL DEFAULT '2022-blake3-aes-256-gcm'",
            )
            self._ensure_column(
                "deployments",
                "encrypted_ss_password",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "deployments",
                "anytls_domain",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "deployments",
                "encrypted_hy2_obfs_password",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "deployments",
                "encrypted_reality_private_key",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "deployments",
                "reality_public_key",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "deployments",
                "reality_short_id",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "deployments",
                "last_config_hash",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "clients",
                "encrypted_ss_password",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "clients",
                "encrypted_anytls_password",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "subscription_nodes",
                "display_name",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "subscription_entries",
                "display_name",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column("jobs", "chain_id", "TEXT")
            self._ensure_column("proxy_chains", "last_error", "TEXT")
            self._ensure_column(
                "subscription_chain_entries",
                "display_name",
                "TEXT NOT NULL DEFAULT ''",
            )
            self._ensure_column(
                "proxy_chain_nodes",
                "inbound_protocol",
                "TEXT NOT NULL DEFAULT 'vless_reality'",
            )
            self._ensure_column("proxy_chain_nodes", "inbound_port", "INTEGER")
            self._ensure_column("proxy_chain_nodes", "client_uuid", "TEXT")
            self._ensure_column("proxy_chain_nodes", "encrypted_private_key", "TEXT")
            self._ensure_column("proxy_chain_nodes", "public_key", "TEXT")
            self._ensure_column("proxy_chain_nodes", "short_id", "TEXT")
            self._ensure_column(
                "proxy_chain_nodes",
                "ss_method",
                "TEXT NOT NULL DEFAULT '2022-blake3-aes-256-gcm'",
            )
            self._ensure_column("proxy_chain_nodes", "encrypted_ss_password", "TEXT")
            self._ensure_column("proxy_chain_nodes", "encrypted_hy2_password", "TEXT")
            self._ensure_column("proxy_chain_nodes", "remote_service_name", "TEXT")
            self._ensure_column("proxy_chain_nodes", "status", "TEXT NOT NULL DEFAULT 'planned'")
            self._ensure_column("proxy_chain_nodes", "updated_at", "TEXT")
            self._ensure_column("deployments", "last_error", "TEXT")
            self._drop_legacy_columns()
            self._migrate_legacy_job_logs()
            self._conn.execute(
                """
                UPDATE deployments
                SET install_method = 'legacy',
                    status = 'failed',
                    last_error = CASE
                        WHEN last_error IS NULL OR last_error = ''
                        THEN 'Legacy simulated deployments are no longer supported; delete and redeploy.'
                        ELSE last_error
                    END
                WHERE install_method <> 'native'
                """
            )
            self._conn.commit()

    def _migrate_legacy_job_logs(self) -> None:
        """Move pre-normalization JSON logs into the append-only log table."""
        rows = self._conn.execute(
            "SELECT id, logs FROM jobs WHERE logs <> '[]' AND logs <> ''"
        ).fetchall()
        for row in rows:
            try:
                legacy_logs = json.loads(row["logs"])
            except (TypeError, ValueError, json.JSONDecodeError):
                continue
            if not isinstance(legacy_logs, list):
                continue

            entries: list[tuple[Any, ...]] = []
            for seq, entry in enumerate(legacy_logs, start=1):
                if isinstance(entry, dict):
                    at = str(entry.get("at") or "")
                    line = str(entry.get("line") or "")
                else:
                    at = ""
                    line = str(entry)
                entries.append((row["id"], seq, at, line))
            if entries:
                self._conn.executemany(
                    """
                    INSERT OR IGNORE INTO job_logs (job_id, seq, at, line)
                    VALUES (?, ?, ?, ?)
                    """,
                    entries,
                )
            self._conn.execute("UPDATE jobs SET logs = '[]' WHERE id = ?", (row["id"],))

    def _assert_no_legacy_engine(self) -> None:
        """Refuse to migrate a database that still tracks 3x-ui deployments.

        Those records point at panels this release can no longer uninstall, so
        the safe order is to delete them from the previous release first.
        """
        rows = self._conn.execute("PRAGMA table_info(deployments)").fetchall()
        if not any(row["name"] == "engine" for row in rows):
            return
        legacy = self._conn.execute(
            "SELECT COUNT(*) AS count FROM deployments WHERE engine <> 'sing-box'"
        ).fetchone()["count"]
        if not legacy:
            return
        if os.getenv("MYN_FORCE_SINGBOX_MIGRATION") == "1":
            self._conn.execute("DELETE FROM deployments WHERE engine <> 'sing-box'")
            return
        raise RuntimeError(
            f"{legacy} 3x-ui deployment(s) are still recorded in this database. "
            "Delete them from the previous release first so it can uninstall "
            "3x-ui on the target hosts, or set MYN_FORCE_SINGBOX_MIGRATION=1 to "
            "drop the records and clean those hosts by hand."
        )

    def _drop_legacy_columns(self) -> None:
        """Remove 3x-ui panel columns and the retired traffic accounting."""
        for column in (
            "panel_scheme",
            "panel_port",
            "panel_path",
            "panel_username",
            "encrypted_panel_password",
            "encrypted_api_token",
            "xui_inbound_id",
        ):
            self._drop_column("deployments", column)
        for column in ("quota_bytes", "used_bytes", "traffic_reset_days"):
            self._drop_column("clients", column)
        self._drop_column("subscription_entries", "quota_bytes")

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        if any(row["name"] == column for row in rows):
            return
        self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def _drop_column(self, table: str, column: str) -> None:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        if not any(row["name"] == column for row in rows):
            return
        # SQLite older than 3.35 cannot drop columns. Leaving the column
        # behind is harmless because nothing reads or writes it any more.
        with suppress(sqlite3.OperationalError):
            self._conn.execute(f"ALTER TABLE {table} DROP COLUMN {column}")

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row else None

    def query_row(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any]:
        """Like query_one, for queries guaranteed to return a row (e.g. aggregates)."""
        row = self.query_one(sql, params)
        if row is None:
            raise RuntimeError("query unexpectedly returned no rows")
        return row

    def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
        with self._lock:
            self._conn.execute(sql, params)
            if not self._in_transaction():
                self._conn.commit()

    def executemany(self, sql: str, params: list[tuple[Any, ...]]) -> None:
        with self._lock:
            self._conn.executemany(sql, params)
            if not self._in_transaction():
                self._conn.commit()

    def executescript(self, sql: str) -> None:
        with self._lock:
            self._conn.executescript(sql)
            if not self._in_transaction():
                self._conn.commit()

    def _in_transaction(self) -> bool:
        return bool(getattr(self._state, "transaction_depth", 0))

    @contextmanager
    def transaction(self) -> Iterator[None]:
        """Serialize and atomically commit a group of local database changes."""
        with self._lock:
            depth = int(getattr(self._state, "transaction_depth", 0))
            if depth == 0:
                self._conn.execute("BEGIN IMMEDIATE")
            self._state.transaction_depth = depth + 1
            try:
                yield
                if depth == 0:
                    self._conn.commit()
            except Exception:
                if depth == 0:
                    self._conn.rollback()
                raise
            finally:
                self._state.transaction_depth = depth

    def ping(self) -> bool:
        with self._lock:
            return self._conn.execute("SELECT 1").fetchone()[0] == 1

    def backup_to(self, target: Path) -> None:
        """Create a consistent online SQLite backup, including WAL contents."""
        target.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, sqlite3.connect(target) as destination:
            self._conn.backup(destination)

    def close(self) -> None:
        with self._lock:
            self._conn.close()
