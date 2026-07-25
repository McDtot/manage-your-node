import hashlib
import json
import threading
import uuid
from contextlib import suppress
from datetime import UTC, date, datetime, timedelta
from typing import Any

from ..provisioning import node_service_name, singbox_config_push_script
from .deployments import DeploymentsService
from .helpers import (
    ACTIVE_CLIENT_CONDITION,
    DEPLOYMENT_PROTOCOL_ANYTLS,
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
    boolean_field,
    new_anytls_password,
    new_id,
    new_ss2022_password,
    now_iso,
    require_text,
)
from .singbox import build_node_config


class ClientsService(DeploymentsService):
    def list_clients(self) -> list[dict[str, Any]]:
        return self._client_rows()

    def _assert_user_name_available(
        self,
        deployment_id: str,
        name: str,
        exclude_client_id: str | None = None,
    ) -> None:
        sql = (
            "SELECT id FROM clients "
            "WHERE deployment_id = ? AND name = ? COLLATE NOCASE"
        )
        params: list[Any] = [deployment_id, name]
        if exclude_client_id:
            sql += " AND id != ?"
            params.append(exclude_client_id)
        if self.db.query_one(sql, tuple(params)):
            raise ValueError("该节点已存在同名用户")

    def _active_client_users(
        self,
        deployment: dict[str, Any],
        extra_users: list[dict[str, str]] | None = None,
    ) -> list[dict[str, str]]:
        """Return the users a node should currently accept.

        Disabled and expired users are dropped here. Rendering is the only
        place either is enforced now that nodes run a bare sing-box with no
        panel of their own.
        """
        rows = self.db.query_all(
            f"""
            SELECT c.name, c.uuid, c.encrypted_ss_password, c.encrypted_anytls_password
            FROM clients c
            WHERE c.deployment_id = ? AND {ACTIVE_CLIENT_CONDITION}
            ORDER BY c.created_at ASC
            """,
            (deployment["id"],),
        )
        protocol = deployment.get("protocol")
        users: list[dict[str, str]] = []
        for row in rows:
            password = ""
            if protocol == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022:
                password = self.secret_box.open(row["encrypted_ss_password"] or "")
            elif protocol == DEPLOYMENT_PROTOCOL_ANYTLS:
                password = self.secret_box.open(row["encrypted_anytls_password"] or "")
                if not password:
                    continue
            users.append(
                {"name": row["name"], "uuid": row["uuid"], "password": password}
            )
        return [*users, *(extra_users or [])]

    def _render_node_config(
        self,
        deployment: dict[str, Any],
        extra_users: list[dict[str, str]] | None = None,
    ) -> dict[str, Any]:
        return build_node_config(
            deployment,
            self._active_client_users(deployment, extra_users),
        )

    @staticmethod
    def _config_hash(config: dict[str, Any]) -> str:
        payload = json.dumps(
            config, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _push_node_config(
        self,
        deployment: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        server = self._get_server_row(deployment["server_id"])
        self.ssh.run_script(
            server,
            singbox_config_push_script(node_service_name(deployment["id"]), config),
            lambda _: None,
            timeout=180,
        )

    def _record_config_hash(self, deployment_id: str, config_hash: str) -> None:
        self.db.execute(
            "UPDATE deployments SET last_config_hash = ?, updated_at = ? WHERE id = ?",
            (config_hash, now_iso(), deployment_id),
        )

    def _apply_node_config(self, deployment: dict[str, Any]) -> bool:
        """Re-render from committed state and reload only on a real change.

        Returns whether the remote service was restarted, so the periodic sweep
        can report how much it actually touched.
        """
        if not self._node_deployment_ready(deployment):
            return False
        config = self._render_node_config(deployment)
        config_hash = self._config_hash(config)
        if config_hash == str(deployment.get("last_config_hash") or ""):
            return False
        self._push_node_config(deployment, config)
        self._record_config_hash(deployment["id"], config_hash)
        return True

    def _node_deployment_ready(self, deployment: dict[str, Any]) -> bool:
        return (
            deployment.get("install_method") == "native"
            and deployment.get("status") == "ready"
        )

    def create_client(self, deployment_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        deployment = self.get_deployment(deployment_id)
        if deployment.get("install_method") != "native":
            raise ValueError("legacy simulated deployments are no longer supported")
        client_id = new_id("cli")
        client_uuid = str(uuid.uuid4())
        never_expires = boolean_field(payload, "neverExpires")
        expires_at = "" if never_expires else str(payload.get("expiresAt", "")).strip()
        if not never_expires and not expires_at:
            expires_at = (datetime.now(UTC) + timedelta(days=30)).date().isoformat()
        if expires_at:
            try:
                date.fromisoformat(expires_at)
            except ValueError as exc:
                raise ValueError("expiresAt must be an ISO date (YYYY-MM-DD)") from exc
        name = require_text(payload, "name")
        if len(name) > 128:
            raise ValueError("name must be 128 characters or fewer")
        self._assert_user_name_available(deployment_id, name)
        is_shadowsocks = deployment.get("protocol") == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022
        is_anytls = deployment.get("protocol") == DEPLOYMENT_PROTOCOL_ANYTLS
        ss_password = new_ss2022_password() if is_shadowsocks else ""
        anytls_password = new_anytls_password() if is_anytls else ""
        share_link = self._default_share_link(
            deployment,
            client_uuid,
            name,
            ss_password=ss_password,
            anytls_password=anytls_password,
        )
        # Push before the insert so a failing node leaves no orphaned user.
        config_hash = ""
        if self._node_deployment_ready(deployment) and self._client_is_active(expires_at):
            config = self._render_node_config(
                deployment,
                extra_users=[
                    {
                        "name": name,
                        "uuid": client_uuid,
                        "password": anytls_password or ss_password,
                    }
                ],
            )
            self._push_node_config(deployment, config)
            config_hash = self._config_hash(config)
        stamp = now_iso()
        with self.db.transaction():
            self.db.execute(
                """
                INSERT INTO clients (
                    id, deployment_id, name, uuid, expires_at, enabled,
                    encrypted_ss_password, encrypted_anytls_password,
                    share_link, subscription_url, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    deployment_id,
                    name,
                    client_uuid,
                    expires_at,
                    1,
                    self.secret_box.seal(ss_password),
                    self.secret_box.seal(anytls_password),
                    share_link,
                    deployment["subscription_url"],
                    stamp,
                    stamp,
                ),
            )
            if config_hash:
                self._record_config_hash(deployment_id, config_hash)
            if deployment.get("subscription_url"):
                self.db.execute(
                    """
                    INSERT OR IGNORE INTO subscription_nodes (
                        subscription_id, node_client_id, created_at
                    ) VALUES (?, ?, ?)
                    """,
                    (deployment_id, client_id, stamp),
                )
            self.db.execute(
                """
                INSERT OR IGNORE INTO subscription_entries (
                    subscription_id, node_client_id, created_at, updated_at
                )
                SELECT ?, ?, ?, ?
                WHERE EXISTS (
                    SELECT 1 FROM subscriptions WHERE id = ?
                )
                """,
                (
                    f"sub_{deployment_id}",
                    client_id,
                    stamp,
                    stamp,
                    f"sub_{deployment_id}",
                ),
            )
        return self.get_client(client_id)

    @staticmethod
    def _client_is_active(expires_at: str, enabled: int = 1) -> bool:
        if not enabled:
            return False
        if not expires_at:
            return True
        return date.fromisoformat(expires_at) >= datetime.now(UTC).date()

    def get_client(self, client_id: str) -> dict[str, Any]:
        rows = self._client_rows(client_id)
        if not rows:
            raise ValueError("用户不存在")
        return rows[0]

    def _client_ss_password(self, client_id: str) -> str:
        row = self.db.query_one(
            "SELECT encrypted_ss_password FROM clients WHERE id = ?",
            (client_id,),
        )
        if not row:
            return ""
        return self.secret_box.open(row["encrypted_ss_password"])

    def _client_anytls_password(self, client_id: str) -> str:
        row = self.db.query_one(
            "SELECT encrypted_anytls_password FROM clients WHERE id = ?",
            (client_id,),
        )
        if not row:
            return ""
        return self.secret_box.open(row["encrypted_anytls_password"] or "")

    def update_client(self, client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        client = self.get_client(client_id)
        deployment = self.get_deployment(client["deployment_id"])
        if deployment.get("install_method") != "native":
            raise ValueError("legacy simulated deployments are no longer supported")
        name = str(payload.get("name", client["name"])).strip()
        if not name:
            raise ValueError("name is required")
        if len(name) > 128:
            raise ValueError("name must be 128 characters or fewer")
        self._assert_user_name_available(
            client["deployment_id"],
            name,
            exclude_client_id=client_id,
        )
        if "neverExpires" in payload:
            never_expires = boolean_field(payload, "neverExpires")
            expires_at = "" if never_expires else str(payload.get("expiresAt", "")).strip()
            if not never_expires and not expires_at:
                raise ValueError("expiresAt is required when neverExpires is false")
        else:
            expires_at = str(payload.get("expiresAt", client["expires_at"])).strip()
        if expires_at:
            try:
                date.fromisoformat(expires_at)
            except ValueError as exc:
                raise ValueError("expiresAt must be an ISO date (YYYY-MM-DD)") from exc
        enabled = 1 if bool(payload.get("enabled", client["enabled"])) else 0
        is_shadowsocks = deployment.get("protocol") == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022
        is_anytls = deployment.get("protocol") == DEPLOYMENT_PROTOCOL_ANYTLS
        ss_password = self._client_ss_password(client_id) if is_shadowsocks else ""
        anytls_password = self._client_anytls_password(client_id) if is_anytls else ""
        share_link = self._default_share_link(
            deployment,
            client["uuid"],
            name,
            ss_password=ss_password,
            anytls_password=anytls_password,
        )
        stamp = now_iso()
        self.db.execute(
            """
            UPDATE clients
            SET name = ?, expires_at = ?, enabled = ?, share_link = ?, updated_at = ?
            WHERE id = ?
            """,
            (name, expires_at, enabled, share_link, stamp, client_id),
        )
        self._apply_node_config(self.get_deployment(client["deployment_id"]))
        return self.get_client(client_id)

    def refresh_node_configs(self) -> dict[str, Any]:
        """Re-render every ready node so expirations take effect on time.

        Individual failures (an unreachable host, say) are collected instead of
        aborting the sweep.
        """
        target_ids = [
            item["id"]
            for item in self.list_deployments()
            if item.get("status") == "ready" and item.get("install_method") == "native"
        ]
        reloaded = 0
        errors: list[dict[str, str]] = []
        for deployment_id in target_ids:
            try:
                if self._apply_node_config(self.get_deployment(deployment_id)):
                    reloaded += 1
            except Exception as exc:  # noqa: BLE001
                errors.append({"deploymentId": deployment_id, "error": str(exc)})
        return {
            "deployments": len(target_ids),
            "reloadedDeployments": reloaded,
            "errors": errors,
        }

    def start_config_sync(self, interval_seconds: int) -> None:
        """Start the loop that drops expired users from live node configs."""
        if interval_seconds <= 0 or self._config_thread is not None:
            return
        self._config_stop.clear()

        def loop() -> None:
            while not self._config_stop.wait(interval_seconds):
                with suppress(Exception):
                    self.refresh_node_configs()

        thread = threading.Thread(target=loop, name="config-sync", daemon=True)
        self._config_thread = thread
        thread.start()

    def stop_config_sync(self) -> None:
        self._config_stop.set()
        thread = self._config_thread
        if thread is not None:
            thread.join(timeout=5)
            self._config_thread = None

    def get_subscription_config(self, deployment_id: str) -> dict[str, Any]:
        deployment = self.get_deployment(deployment_id)
        selected = self.db.query_all(
            """
            SELECT node_client_id
            FROM subscription_nodes
            WHERE subscription_id = ?
            ORDER BY created_at ASC
            """,
            (deployment_id,),
        )
        return {
            "deployment": {
                "id": deployment["id"],
                "serverName": deployment["server_name"],
                "subscriptionUrl": deployment["subscription_url"],
            },
            "availableNodes": self.list_clients(),
            "selectedNodeIds": [row["node_client_id"] for row in selected],
        }

    def update_subscription_config(self, deployment_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        self.get_deployment(deployment_id)
        node_ids = payload.get("nodeIds", [])
        if not isinstance(node_ids, list):
            raise ValueError("nodeIds must be a list")

        ordered_ids = []
        seen = set()
        for node_id in node_ids:
            text_id = str(node_id).strip()
            if text_id and text_id not in seen:
                ordered_ids.append(text_id)
                seen.add(text_id)

        if ordered_ids:
            placeholders = ",".join("?" for _ in ordered_ids)
            rows = self.db.query_all(
                f"SELECT id FROM clients WHERE id IN ({placeholders})",
                tuple(ordered_ids),
            )
            found = {row["id"] for row in rows}
            if len(found) != len(ordered_ids):
                raise ValueError("selected node not found")

        stamp = now_iso()
        with self.db.transaction():
            self.db.execute(
                "DELETE FROM subscription_nodes WHERE subscription_id = ?",
                (deployment_id,),
            )
            self.db.executemany(
                """
                INSERT INTO subscription_nodes (
                    subscription_id, node_client_id, created_at
                ) VALUES (?, ?, ?)
                """,
                [(deployment_id, node_id, stamp) for node_id in ordered_ids],
            )
            self.db.execute(
                """
                UPDATE deployments
                SET subscription_configured = 1, subscription_url = ?, updated_at = ?
                WHERE id = ?
                """,
                (self._deployment_subscription_url(deployment_id), stamp, deployment_id),
            )
        return self.get_subscription_config(deployment_id)
