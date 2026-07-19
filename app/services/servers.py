import socket
import threading
import time
from contextlib import suppress
from typing import Any

from .base import ServicesBase
from .helpers import (
    host_field,
    new_id,
    now_iso,
    port_field,
    require_text,
)


class ServersService(ServicesBase):
    def list_servers(self) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            """
            SELECT s.id, s.name, s.host, s.ssh_port, s.ssh_user, s.auth_type,
                   s.secret_label, s.os, s.arch, s.status, s.last_check_at,
                   s.last_latency_ms, s.last_health_error,
                   s.created_at, s.updated_at, hk.fingerprint AS host_key_fingerprint,
                   COALESCE(hk.trusted, 0) AS host_key_trusted
            FROM servers s
            LEFT JOIN ssh_host_keys hk ON hk.server_id = s.id
            ORDER BY s.created_at DESC
            """
        )
        return rows

    def create_server(self, payload: dict[str, Any]) -> dict[str, Any]:
        server_id = new_id("srv")
        stamp = now_iso()
        secret = str(payload.get("secret", ""))
        auth_type = require_text(payload, "authType")
        if auth_type not in {"key", "password", "agent"}:
            raise ValueError("authType must be key, password, or agent")
        self.db.execute(
            """
            INSERT INTO servers (
                id, name, host, ssh_port, ssh_user, auth_type, encrypted_secret,
                secret_label, status, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                require_text(payload, "name"),
                host_field(payload),
                port_field(payload, "sshPort", 22),
                require_text(payload, "sshUser"),
                auth_type,
                self.secret_box.seal(secret),
                "saved" if secret else "not_saved",
                "new",
                stamp,
                stamp,
            ),
        )
        return self.get_server(server_id)

    def get_server(self, server_id: str) -> dict[str, Any]:
        row = self.db.query_one(
            """
            SELECT s.id, s.name, s.host, s.ssh_port, s.ssh_user, s.auth_type,
                   s.secret_label, s.os, s.arch, s.status, s.last_check_at,
                   s.last_latency_ms, s.last_health_error,
                   s.created_at, s.updated_at, hk.fingerprint AS host_key_fingerprint,
                   COALESCE(hk.trusted, 0) AS host_key_trusted
            FROM servers s
            LEFT JOIN ssh_host_keys hk ON hk.server_id = s.id
            WHERE s.id = ?
            """,
            (server_id,),
        )
        if not row:
            raise ValueError("server not found")
        return row

    def approve_server_host_key(self, server_id: str) -> dict[str, Any]:
        self.get_server(server_id)
        row = self.db.query_one(
            "SELECT fingerprint, trusted FROM ssh_host_keys WHERE server_id = ?",
            (server_id,),
        )
        if not row:
            raise ValueError("test SSH once to capture the host key before approving it")
        if not row["fingerprint"]:
            raise ValueError("captured SSH host key is invalid")
        self.db.execute(
            "UPDATE ssh_host_keys SET trusted = 1 WHERE server_id = ?",
            (server_id,),
        )
        return self.get_server(server_id)

    def reset_server_host_key(self, server_id: str) -> dict[str, Any]:
        self.get_server(server_id)
        self._assert_not_busy("server", server_id)
        self.db.execute("DELETE FROM ssh_host_keys WHERE server_id = ?", (server_id,))
        self.db.execute(
            "UPDATE servers SET status = 'new', updated_at = ? WHERE id = ?",
            (now_iso(), server_id),
        )
        return self.get_server(server_id)

    def _check_server_health(self, server: dict[str, Any]) -> dict[str, Any]:
        """Probe a server's SSH reachability and persist the result.

        Returns ``{status, checkedAt, error, latencyMs}``. Latency is the TCP
        connect time to the SSH port in milliseconds, or ``None`` when the host
        is unreachable.
        """
        stamp = now_iso()
        latency_ms: int | None = None
        try:
            started = time.monotonic()
            with socket.create_connection(
                (server["host"], int(server["ssh_port"])),
                timeout=4,
            ):
                latency_ms = int((time.monotonic() - started) * 1000)
            ok, detail = self.ssh.probe(server)
            status = "reachable" if ok else "auth_failed"
            error = "" if ok else detail
        except OSError as exc:
            status = "unreachable"
            error = str(exc)
        self.db.execute(
            """
            UPDATE servers
            SET status = ?, last_check_at = ?, last_latency_ms = ?,
                last_health_error = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, stamp, latency_ms, error, stamp, server["id"]),
        )
        return {
            "status": status,
            "checkedAt": stamp,
            "error": error,
            "latencyMs": latency_ms,
        }

    def test_server(self, server_id: str) -> dict[str, Any]:
        server = self._get_server_row(server_id)
        return self._check_server_health(server)

    def check_all_servers_health(self) -> dict[str, Any]:
        """Probe every registered server and summarize the fleet's health."""
        servers = self.db.query_all("SELECT * FROM servers")
        checked = 0
        counts = {"reachable": 0, "auth_failed": 0, "unreachable": 0}
        for server in servers:
            try:
                result = self._check_server_health(server)
                checked += 1
                status = result["status"]
                if status in counts:
                    counts[status] += 1
            except Exception:  # noqa: BLE001
                counts["unreachable"] += 1
        return {
            "checked": checked,
            "reachable": counts["reachable"],
            "authFailed": counts["auth_failed"],
            "unreachable": counts["unreachable"],
        }

    def start_health_monitor(self, interval_seconds: int) -> None:
        """Start a background loop that periodically checks server health."""
        if interval_seconds <= 0 or self._health_thread is not None:
            return
        self._health_stop.clear()

        def loop() -> None:
            while not self._health_stop.wait(interval_seconds):
                with suppress(Exception):
                    self.check_all_servers_health()

        thread = threading.Thread(target=loop, name="health-monitor", daemon=True)
        self._health_thread = thread
        thread.start()

    def stop_health_monitor(self) -> None:
        self._health_stop.set()
        thread = self._health_thread
        if thread is not None:
            thread.join(timeout=5)
            self._health_thread = None
