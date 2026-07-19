import socket
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

    def test_server(self, server_id: str) -> dict[str, Any]:
        server = self._get_server_row(server_id)
        stamp = now_iso()
        try:
            with socket.create_connection(
                (server["host"], int(server["ssh_port"])),
                timeout=4,
            ):
                pass
            status = "reachable"
            error = ""
            ok, detail = self.ssh.probe(server)
            status = "reachable" if ok else "auth_failed"
            error = "" if ok else detail
        except OSError as exc:
            status = "unreachable"
            error = str(exc)
        self.db.execute(
            """
            UPDATE servers
            SET status = ?, last_check_at = ?, updated_at = ?
            WHERE id = ?
            """,
            (status, stamp, stamp, server_id),
        )
        return {"status": status, "checkedAt": stamp, "error": error}
