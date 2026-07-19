import json
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from typing import Any

from ..database import Database
from ..security import SecretBox
from ..ssh_runner import SshRunner
from ..ssh_tunnel import SshTunnel
from ..xui_api import XuiApiClient
from .helpers import (
    MAX_JOB_LOG_ENTRIES,
    MAX_JOB_LOG_LINE,
    _deployment_reality_settings,
    now_iso,
    url_host,
)


class ServicesBase:
    def __init__(self, db: Database, secret_box: SecretBox):
        self.db = db
        self.secret_box = secret_box
        self._verify_master_secret()
        self.ssh = SshRunner(secret_box, db)
        self._workers: set[threading.Thread] = set()
        self._workers_lock = threading.Lock()

    def _track_worker(self, worker: threading.Thread) -> None:
        with self._workers_lock:
            self._workers.add(worker)

    def _forget_current_worker(self) -> None:
        with self._workers_lock:
            self._workers.discard(threading.current_thread())

    def wait_for_workers(self, timeout: float = 25.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self._workers_lock:
                workers = [worker for worker in self._workers if worker.is_alive()]
            if not workers:
                return True
            remaining = max(0.0, deadline - time.monotonic())
            workers[0].join(min(0.25, remaining))
        return False

    def _verify_master_secret(self) -> None:
        marker = self.db.query_one(
            "SELECT value FROM app_metadata WHERE key = 'master_secret_check'"
        )
        expected = "manage-your-node/master-secret-check/v1"
        if marker:
            try:
                if self.secret_box.open(marker["value"]) != expected:
                    raise ValueError("marker mismatch")
            except ValueError as exc:
                raise RuntimeError(
                    "APP_SECRET does not match this database; refusing to mix encryption keys"
                ) from exc
            return

        encrypted_columns = [
            ("servers", "encrypted_secret"),
            ("deployments", "encrypted_panel_password"),
            ("deployments", "encrypted_api_token"),
            ("deployments", "encrypted_ss_password"),
            ("clients", "encrypted_ss_password"),
            ("proxy_chain_nodes", "encrypted_private_key"),
            ("proxy_chain_nodes", "encrypted_ss_password"),
        ]
        try:
            for table, column in encrypted_columns:
                rows = self.db.query_all(
                    f"SELECT {column} AS value FROM {table} WHERE {column} <> ''"
                )
                for row in rows:
                    self.secret_box.open(row["value"])
        except ValueError as exc:
            raise RuntimeError(
                "APP_SECRET cannot decrypt existing data; refusing to write with a different key"
            ) from exc

        self.db.execute(
            """
            INSERT INTO app_metadata (key, value, updated_at)
            VALUES ('master_secret_check', ?, ?)
            """,
            (self.secret_box.seal(expected), now_iso()),
        )

    def _acquire_operation_locks(
        self,
        job_id: str,
        resources: list[tuple[str, str]],
    ) -> None:
        for resource_type, resource_id in resources:
            existing = self.db.query_one(
                "SELECT job_id FROM operation_locks WHERE resource_type = ? AND resource_id = ?",
                (resource_type, resource_id),
            )
            if existing:
                raise ValueError(
                    f"{resource_type} is busy with job {existing['job_id']}; wait for it to finish"
                )
        self.db.executemany(
            """
            INSERT INTO operation_locks (resource_type, resource_id, job_id, acquired_at)
            VALUES (?, ?, ?, ?)
            """,
            [
                (resource_type, resource_id, job_id, now_iso())
                for resource_type, resource_id in resources
            ],
        )

    def _release_operation_locks(self, job_id: str) -> None:
        self.db.execute("DELETE FROM operation_locks WHERE job_id = ?", (job_id,))

    def _assert_not_busy(self, resource_type: str, resource_id: str) -> None:
        lock = self.db.query_one(
            "SELECT job_id FROM operation_locks WHERE resource_type = ? AND resource_id = ?",
            (resource_type, resource_id),
        )
        if lock:
            raise ValueError(f"resource is busy with job {lock['job_id']}")

    def recover_orphaned_jobs(self) -> int:
        """Fail jobs/records left ``running`` by a previous process.

        Background deployment work runs in daemon threads, so a restart mid-run
        would otherwise leave jobs stuck as ``running`` and deployments/chains
        stuck as ``provisioning``/``deploying`` forever.
        """
        stamp = now_iso()
        orphaned = self.db.query_all("SELECT id FROM jobs WHERE status = 'running'")
        message = "Process restarted before this job finished; marked as failed."
        with self.db.transaction():
            for row in orphaned:
                self._append_job_log(row["id"], message)
            self.db.execute(
                """
                UPDATE jobs
                SET status = 'failed', error = ?, updated_at = ?, finished_at = ?
                WHERE status = 'running'
                """,
                (message, stamp, stamp),
            )
            self.db.execute(
                """
                UPDATE deployments
                SET status = 'failed', last_error = ?, updated_at = ?
                WHERE status = 'provisioning'
                """,
                ("Deployment interrupted by a process restart.", stamp),
            )
            self.db.execute(
                """
                UPDATE proxy_chains
                SET status = 'failed', last_error = ?, updated_at = ?
                WHERE status = 'deploying'
                """,
                ("Proxy chain deployment interrupted by a process restart.", stamp),
            )
            self.db.execute("DELETE FROM operation_locks")
        return len(orphaned)

    def summary(self) -> dict[str, Any]:
        servers = self.db.query_row("SELECT COUNT(*) AS count FROM servers")["count"]
        ready = self.db.query_row(
            "SELECT COUNT(*) AS count FROM deployments WHERE status = 'ready'"
        )["count"]
        clients = self.db.query_row("SELECT COUNT(*) AS count FROM clients")["count"]
        chains = self.db.query_row("SELECT COUNT(*) AS count FROM proxy_chains")["count"]
        traffic = self.db.query_row(
            "SELECT COALESCE(SUM(used_bytes), 0) AS used, "
            "COALESCE(SUM(quota_bytes), 0) AS quota FROM clients"
        )
        soon = (datetime.now(UTC) + timedelta(days=7)).date().isoformat()
        expiring = self.db.query_row(
            "SELECT COUNT(*) AS count FROM clients "
            "WHERE enabled = 1 AND expires_at <> '' AND expires_at <= ?",
            (soon,),
        )["count"]
        return {
            "servers": servers,
            "readyDeployments": ready,
            "clients": clients,
            "proxyChains": chains,
            "usedBytes": traffic["used"],
            "quotaBytes": traffic["quota"],
            "expiringClients": expiring,
        }

    def list_audit_events(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 500))
        return self.db.query_all(
            """
            SELECT id, at, actor, client_ip, method, path, status
            FROM audit_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (safe_limit,),
        )

    def _append_job_log(self, job_id: str, line: str) -> None:
        clean = str(line).replace("\x00", "")[:MAX_JOB_LOG_LINE]
        stamp = now_iso()
        with self.db.transaction():
            job = self.db.query_one("SELECT id FROM jobs WHERE id = ?", (job_id,))
            if not job:
                return
            next_seq = self.db.query_row(
                "SELECT COALESCE(MAX(seq), 0) + 1 AS value FROM job_logs WHERE job_id = ?",
                (job_id,),
            )["value"]
            self.db.execute(
                "INSERT INTO job_logs (job_id, seq, at, line) VALUES (?, ?, ?, ?)",
                (job_id, next_seq, stamp, clean),
            )
            self.db.execute(
                "DELETE FROM job_logs WHERE job_id = ? AND seq <= ?",
                (job_id, next_seq - MAX_JOB_LOG_ENTRIES),
            )
            self.db.execute(
                "UPDATE jobs SET updated_at = ? WHERE id = ?",
                (stamp, job_id),
            )

    def _finish_job(self, job_id: str, status: str, error: str | None) -> None:
        self.db.execute(
            """
            UPDATE jobs
            SET status = ?, error = ?, updated_at = ?, finished_at = ?
            WHERE id = ?
            """,
            (status, error, now_iso(), now_iso(), job_id),
        )

    def get_job(self, job_id: str, after_seq: int | None = None) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise ValueError("job not found")
        legacy_raw = row.pop("logs", "[]")
        safe_after = max(0, int(after_seq or 0))
        logs = self.db.query_all(
            """
            SELECT seq, at, line
            FROM job_logs
            WHERE job_id = ? AND seq > ?
            ORDER BY seq ASC
            """,
            (job_id, safe_after),
        )
        if not logs:
            try:
                legacy_logs = json.loads(legacy_raw)
            except (TypeError, ValueError, json.JSONDecodeError):
                legacy_logs = []
            if isinstance(legacy_logs, list):
                logs = [
                    {
                        "seq": seq,
                        "at": str(entry.get("at") or "") if isinstance(entry, dict) else "",
                        "line": str(entry.get("line") or "") if isinstance(entry, dict) else str(entry),
                    }
                    for seq, entry in enumerate(legacy_logs, start=1)
                    if seq > safe_after
                ]
        row["logs"] = logs
        row["last_log_seq"] = logs[-1]["seq"] if logs else safe_after
        return row

    def _subscription_url(self, token: str) -> str:
        return f"/sub/links/{token}"

    def _chain_subscription_url(self, token: str) -> str:
        return f"/sub/chains/{token}"

    def _deployment_subscription_url(self, deployment_id: str) -> str:
        return f"/sub/deployments/{deployment_id}"

    @contextmanager
    def _xui_session(self, deployment: dict[str, Any]) -> Iterator[XuiApiClient]:
        """Yield a 3x-ui API client reachable through an SSH tunnel.

        The panel is only exposed over plaintext HTTP on the remote host, so we
        forward it through SSH and talk to it via ``127.0.0.1`` locally. This
        keeps the panel password, API token and inbound secrets off the public
        network.
        """
        server = self._get_server_row(deployment["server_id"])
        scheme = deployment.get("panel_scheme") or "http"
        panel_path = deployment.get("panel_path") or ""
        with SshTunnel(self.ssh, server, "127.0.0.1", int(deployment["panel_port"])) as local_port:
            base_url = f"{scheme}://127.0.0.1:{local_port}{panel_path}/"
            yield XuiApiClient(
                base_url=base_url,
                username=deployment["panel_username"],
                password=deployment["panel_password"],
                api_token=deployment.get("api_token") or "",
                verify_tls=False,  # endpoint is authenticated by the pinned SSH tunnel
            )

    def _get_server_row(self, server_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        if not row:
            raise ValueError("server not found")
        return row

    def _get_deployment_row(self, deployment_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM deployments WHERE id = ?", (deployment_id,))
        if not row:
            raise ValueError("deployment not found")
        return row

    def _attach_deployment_secrets(self, row: dict[str, Any], reveal: bool = True) -> None:
        auto_selection_pending = (
            row.get("reality_mode") == "auto" and not row.get("reality_dest")
        )
        if not auto_selection_pending:
            row["reality_dest"], row["reality_sni"] = _deployment_reality_settings(row)
        row["panel_url"] = f"{row['panel_scheme']}://{url_host(row['host'])}:{row['panel_port']}{row['panel_path']}/"
        if row.get("subscription_url"):
            row["subscription_url"] = self._deployment_subscription_url(row["id"])
        encrypted_password = row.pop("encrypted_panel_password", "")
        encrypted_token = row.pop("encrypted_api_token", "")
        encrypted_ss_password = row.pop("encrypted_ss_password", "")
        if reveal:
            row["panel_password"] = self.secret_box.open(encrypted_password)
            row["api_token"] = self.secret_box.open(encrypted_token)
            row["ss_password"] = self.secret_box.open(encrypted_ss_password)

    def _client_rows(self, client_id: str | None = None) -> list[dict[str, Any]]:
        where = "WHERE c.id = ?" if client_id else ""
        params = (client_id,) if client_id else ()
        return self.db.query_all(
            f"""
            SELECT c.id, c.deployment_id, d.server_id, s.name AS server_name,
                   s.host, c.name, c.uuid, c.quota_bytes, c.used_bytes,
                   c.traffic_reset_days, c.expires_at, c.enabled,
                   c.share_link, c.subscription_url,
                   c.created_at, c.updated_at
            FROM clients c
            JOIN deployments d ON d.id = c.deployment_id
            JOIN servers s ON s.id = d.server_id
            {where}
            ORDER BY c.created_at DESC
            """,
            params,
        )
