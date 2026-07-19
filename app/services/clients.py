import math
import threading
import uuid
from contextlib import suppress
from datetime import UTC, date, datetime, timedelta
from typing import Any

from .deployments import DeploymentsService
from .helpers import (
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
    _normalize_client_share_link_host,
    boolean_field,
    new_id,
    new_ss2022_password,
    now_iso,
    require_text,
    traffic_reset_days_field,
)


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

    def create_client(self, deployment_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        deployment = self.get_deployment(deployment_id)
        if deployment.get("install_method") != "native":
            raise ValueError("legacy simulated deployments are no longer supported")
        client_id = new_id("cli")
        client_uuid = str(uuid.uuid4())
        try:
            quota_gb = float(payload.get("quotaGb", 100))
        except (TypeError, ValueError) as exc:
            raise ValueError("quotaGb must be a number") from exc
        if not math.isfinite(quota_gb) or not 0 <= quota_gb <= 1_000_000:
            raise ValueError("quotaGb must be between 0 and 1000000")
        quota_bytes = int(quota_gb * 1024 * 1024 * 1024)
        traffic_reset_days = traffic_reset_days_field(payload)
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
        ss_password = new_ss2022_password() if is_shadowsocks else ""
        share_link = self._default_share_link(
            deployment,
            client_uuid,
            name,
            ss_password=ss_password,
        )
        sub_id = client_id[-12:]
        if (
            deployment.get("install_method") == "native"
            and deployment.get("status") == "ready"
            and deployment.get("xui_inbound_id")
        ):
            with self._xui_session(deployment) as xui:
                xui.wait_ready(seconds=30)
                xui.login()
                if is_shadowsocks:
                    xui.create_ss_client(
                        inbound_id=int(deployment["xui_inbound_id"]),
                        email=name,
                        password=ss_password,
                        sub_id=sub_id,
                        quota_bytes=quota_bytes,
                        expires_ms=self._expires_ms(expires_at),
                        reset_days=traffic_reset_days,
                    )
                    links = []
                else:
                    links = xui.create_client(
                        inbound_id=int(deployment["xui_inbound_id"]),
                        email=name,
                        client_uuid=client_uuid,
                        sub_id=sub_id,
                        quota_bytes=quota_bytes,
                        expires_ms=self._expires_ms(expires_at),
                        reset_days=traffic_reset_days,
                    )
            if links:
                share_link = _normalize_client_share_link_host(
                    links[0],
                    deployment["host"],
                )
        stamp = now_iso()
        with self.db.transaction():
            self.db.execute(
                """
                INSERT INTO clients (
                    id, deployment_id, name, uuid, quota_bytes, used_bytes,
                    traffic_reset_days, expires_at, enabled, encrypted_ss_password,
                    share_link, subscription_url,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    client_id,
                    deployment_id,
                    name,
                    client_uuid,
                    quota_bytes,
                    0,
                    traffic_reset_days,
                    expires_at,
                    1,
                    self.secret_box.seal(ss_password),
                    share_link,
                    deployment["subscription_url"],
                    stamp,
                    stamp,
                ),
            )
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
                    subscription_id, node_client_id, quota_bytes, created_at, updated_at
                )
                SELECT ?, ?, ?, ?, ?
                WHERE EXISTS (
                    SELECT 1 FROM subscriptions WHERE id = ?
                )
                """,
                (
                    f"sub_{deployment_id}",
                    client_id,
                    quota_bytes,
                    stamp,
                    stamp,
                    f"sub_{deployment_id}",
                ),
            )
        return self.get_client(client_id)

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
        try:
            quota_gb = float(
                payload.get("quotaGb", client["quota_bytes"] / 1024 / 1024 / 1024)
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("quotaGb must be a number") from exc
        if not math.isfinite(quota_gb) or not 0 <= quota_gb <= 1_000_000:
            raise ValueError("quotaGb must be between 0 and 1000000")
        quota_bytes = int(quota_gb * 1024 * 1024 * 1024)
        traffic_reset_days = traffic_reset_days_field(
            payload,
            int(client.get("traffic_reset_days") or 0),
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
        ss_password = self._client_ss_password(client_id) if is_shadowsocks else ""
        share_link = client["share_link"]
        if (
            deployment.get("install_method") == "native"
            and deployment.get("status") == "ready"
            and deployment.get("xui_inbound_id")
        ):
            with self._xui_session(deployment) as xui:
                xui.wait_ready(seconds=30)
                xui.login()
                remote = xui.get_client(client["name"])
                remote_client = remote.get("client") if isinstance(remote.get("client"), dict) else remote
                if not isinstance(remote_client, dict):
                    raise ValueError("3x-ui client payload is invalid")
                updated_remote = dict(remote_client)
                if not is_shadowsocks:
                    remote_uuid = str(updated_remote.get("uuid") or client["uuid"])
                    updated_remote["id"] = remote_uuid
                    updated_remote.pop("uuid", None)
                if isinstance(updated_remote.get("allowedIPs"), str):
                    updated_remote["allowedIPs"] = [
                        item.strip()
                        for item in updated_remote["allowedIPs"].split(",")
                        if item.strip()
                    ]
                updated_remote["email"] = name
                updated_remote["totalGB"] = quota_bytes
                updated_remote["expiryTime"] = self._expires_ms(expires_at)
                updated_remote["reset"] = traffic_reset_days
                updated_remote["enable"] = bool(enabled)
                xui.update_client(client["name"], updated_remote)
                if is_shadowsocks:
                    share_link = self._default_share_link(
                        deployment, client["uuid"], name, ss_password=ss_password
                    )
                else:
                    try:
                        links = xui.client_links(name)
                        if links:
                            share_link = _normalize_client_share_link_host(
                                links[0],
                                deployment["host"],
                            )
                    except Exception:  # noqa: BLE001
                        pass
                with suppress(Exception):
                    xui.restart_xray()
        else:
            share_link = self._default_share_link(
                deployment, client["uuid"], name, ss_password=ss_password
            )
        stamp = now_iso()
        self.db.execute(
            """
            UPDATE clients
            SET name = ?, quota_bytes = ?, traffic_reset_days = ?, expires_at = ?,
                enabled = ?, share_link = ?, updated_at = ?
            WHERE id = ?
            """,
            (
                name,
                quota_bytes,
                traffic_reset_days,
                expires_at,
                enabled,
                share_link,
                stamp,
                client_id,
            ),
        )
        return self.get_client(client_id)

    def refresh_deployment_traffic(self, deployment: dict[str, Any]) -> int:
        """Pull real per-client usage from 3x-ui into the local database.

        Returns the number of clients whose ``used_bytes`` were updated.
        """
        if (
            deployment.get("install_method") != "native"
            or deployment.get("status") != "ready"
            or not deployment.get("xui_inbound_id")
        ):
            return 0
        with self._xui_session(deployment) as xui:
            xui.wait_ready(seconds=20)
            xui.login()
            totals = xui.client_traffic_totals(int(deployment["xui_inbound_id"]))
        if not totals:
            return 0
        stamp = now_iso()
        updated = 0
        with self.db.transaction():
            rows = self.db.query_all(
                "SELECT id, name, used_bytes FROM clients WHERE deployment_id = ?",
                (deployment["id"],),
            )
            for row in rows:
                if row["name"] not in totals:
                    continue
                used = totals[row["name"]]
                if used == row["used_bytes"]:
                    continue
                self.db.execute(
                    "UPDATE clients SET used_bytes = ?, updated_at = ? WHERE id = ?",
                    (used, stamp, row["id"]),
                )
                updated += 1
        return updated

    def refresh_all_traffic(self) -> dict[str, Any]:
        """Refresh usage for every ready native deployment.

        Failures on individual deployments (e.g. a temporarily unreachable
        host) are collected instead of aborting the whole sweep.
        """
        summaries = self.list_deployments()
        target_ids = [
            item["id"]
            for item in summaries
            if item.get("status") == "ready"
            and item.get("install_method") == "native"
            and item.get("xui_inbound_id")
        ]
        updated = 0
        synced = 0
        errors: list[dict[str, str]] = []
        for deployment_id in target_ids:
            try:
                deployment = self.get_deployment(deployment_id)
                updated += self.refresh_deployment_traffic(deployment)
                synced += 1
            except Exception as exc:  # noqa: BLE001
                errors.append({"deploymentId": deployment_id, "error": str(exc)})
        return {
            "deployments": synced,
            "updatedClients": updated,
            "errors": errors,
        }

    def start_traffic_sync(self, interval_seconds: int) -> None:
        """Start a background loop that periodically syncs traffic usage."""
        if interval_seconds <= 0 or self._traffic_thread is not None:
            return
        self._traffic_stop.clear()

        def loop() -> None:
            while not self._traffic_stop.wait(interval_seconds):
                with suppress(Exception):
                    self.refresh_all_traffic()

        thread = threading.Thread(target=loop, name="traffic-sync", daemon=True)
        self._traffic_thread = thread
        thread.start()

    def stop_traffic_sync(self) -> None:
        self._traffic_stop.set()
        thread = self._traffic_thread
        if thread is not None:
            thread.join(timeout=5)
            self._traffic_thread = None

    def reset_client(self, client_id: str) -> dict[str, Any]:
        client = self.get_client(client_id)
        deployment = self.get_deployment(client["deployment_id"])
        if deployment.get("install_method") != "native":
            raise ValueError("legacy simulated deployments are no longer supported")
        if (
            deployment.get("install_method") == "native"
            and deployment.get("status") == "ready"
            and deployment.get("xui_inbound_id")
        ):
            with self._xui_session(deployment) as xui:
                xui.wait_ready(seconds=30)
                xui.login()
                xui.reset_client_traffic(
                    int(deployment["xui_inbound_id"]),
                    client["name"],
                )
        self.db.execute(
            "UPDATE clients SET used_bytes = 0, updated_at = ? WHERE id = ?",
            (now_iso(), client_id),
        )
        return self.get_client(client_id)

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
