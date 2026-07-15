import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator


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
                    panel_scheme TEXT NOT NULL DEFAULT 'http',
                    panel_port INTEGER NOT NULL,
                    panel_path TEXT NOT NULL,
                    panel_username TEXT NOT NULL,
                    encrypted_panel_password TEXT NOT NULL,
                    encrypted_api_token TEXT NOT NULL,
                    proxy_port INTEGER NOT NULL,
                    reality_mode TEXT NOT NULL DEFAULT 'manual',
                    reality_dest TEXT NOT NULL DEFAULT '',
                    reality_sni TEXT NOT NULL DEFAULT '',
                    xui_inbound_id INTEGER,
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
                    quota_bytes INTEGER NOT NULL,
                    used_bytes INTEGER NOT NULL,
                    traffic_reset_days INTEGER NOT NULL DEFAULT 0,
                    expires_at TEXT NOT NULL,
                    enabled INTEGER NOT NULL,
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
                    quota_bytes INTEGER NOT NULL,
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
            self._ensure_column("deployments", "install_method", "TEXT NOT NULL DEFAULT 'native'")
            self._ensure_column("ssh_host_keys", "trusted", "INTEGER NOT NULL DEFAULT 1")
            self._ensure_column("deployments", "panel_scheme", "TEXT NOT NULL DEFAULT 'http'")
            self._ensure_column("deployments", "xui_inbound_id", "INTEGER")
            self._ensure_column("deployments", "subscription_configured", "INTEGER NOT NULL DEFAULT 0")
            self._ensure_column(
                "deployments",
                "reality_mode",
                "TEXT NOT NULL DEFAULT 'manual'",
            )
            self._ensure_column("deployments", "reality_dest", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column("deployments", "reality_sni", "TEXT NOT NULL DEFAULT ''")
            self._ensure_column(
                "clients",
                "traffic_reset_days",
                "INTEGER NOT NULL DEFAULT 0",
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
            self._ensure_column("proxy_chain_nodes", "remote_service_name", "TEXT")
            self._ensure_column("proxy_chain_nodes", "status", "TEXT NOT NULL DEFAULT 'planned'")
            self._ensure_column("proxy_chain_nodes", "updated_at", "TEXT")
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

    def _ensure_column(self, table: str, column: str, definition: str) -> None:
        rows = self._conn.execute(f"PRAGMA table_info({table})").fetchall()
        if any(row["name"] == column for row in rows):
            return
        self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")

    def query_all(self, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(sql, params).fetchall()
            return [dict(row) for row in rows]

    def query_one(self, sql: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(sql, params).fetchone()
            return dict(row) if row else None

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
