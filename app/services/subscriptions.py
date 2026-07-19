import secrets
from typing import Any

from .chains import ChainsService
from .helpers import (
    _render_subscription_links,
    _share_link_with_display_name,
    new_id,
    now_iso,
)


class SubscriptionsService(ChainsService):
    def _subscription_rows(
        self,
        subscription_id: str | None = None,
    ) -> list[dict[str, Any]]:
        where = "WHERE s.id = ?" if subscription_id else ""
        node_where = "WHERE se.subscription_id = ?" if subscription_id else ""
        chain_where = "WHERE subscription_id = ?" if subscription_id else ""
        params = (subscription_id, subscription_id, subscription_id) if subscription_id else ()
        return self.db.query_all(
            f"""
            WITH node_stats AS (
                SELECT se.subscription_id,
                       COUNT(*) AS node_count,
                       SUM(se.quota_bytes) AS quota_bytes,
                       SUM(c.used_bytes) AS used_bytes,
                       SUM(
                           CASE
                               WHEN se.quota_bytes > c.used_bytes
                               THEN se.quota_bytes - c.used_bytes
                               ELSE 0
                           END
                       ) AS remaining_bytes
                FROM subscription_entries se
                JOIN clients c ON c.id = se.node_client_id
                {node_where}
                GROUP BY se.subscription_id
            ),
            chain_stats AS (
                SELECT subscription_id, COUNT(*) AS chain_count
                FROM subscription_chain_entries
                {chain_where}
                GROUP BY subscription_id
            )
            SELECT s.id, s.name, s.token, s.created_at, s.updated_at,
                   COALESCE(ns.node_count, 0) AS node_count,
                   COALESCE(cs.chain_count, 0) AS chain_count,
                   COALESCE(ns.quota_bytes, 0) AS quota_bytes,
                   COALESCE(ns.used_bytes, 0) AS used_bytes,
                   COALESCE(ns.remaining_bytes, 0) AS remaining_bytes
            FROM subscriptions s
            LEFT JOIN node_stats ns ON ns.subscription_id = s.id
            LEFT JOIN chain_stats cs ON cs.subscription_id = s.id
            {where}
            ORDER BY s.created_at DESC
            """,
            params,
        )

    def list_subscriptions(self) -> list[dict[str, Any]]:
        rows = self._subscription_rows()
        for row in rows:
            row["subscription_url"] = self._subscription_url(row["token"])
        return rows

    def create_subscription(self, payload: dict[str, Any]) -> dict[str, Any]:
        stamp = now_iso()
        subscription_id = new_id("sub")
        name = str(payload.get("name", "")).strip() or "新订阅"
        token = secrets.token_urlsafe(24)
        self.db.execute(
            """
            INSERT INTO subscriptions (
                id, name, token, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (subscription_id, name, token, stamp, stamp),
        )
        return self.get_subscription(subscription_id)

    def get_subscription(self, subscription_id: str) -> dict[str, Any]:
        rows = self._subscription_rows(subscription_id)
        if not rows:
            raise ValueError("subscription not found")
        row = rows[0]
        row["subscription_url"] = self._subscription_url(row["token"])
        return row

    def get_managed_subscription_config(self, subscription_id: str) -> dict[str, Any]:
        subscription = self.get_subscription(subscription_id)
        selected = self.db.query_all(
            """
            SELECT node_client_id, quota_bytes, display_name
            FROM subscription_entries
            WHERE subscription_id = ?
            ORDER BY created_at ASC
            """,
            (subscription_id,),
        )
        selected_chains = self.db.query_all(
            """
            SELECT chain_id, display_name
            FROM subscription_chain_entries
            WHERE subscription_id = ?
            ORDER BY created_at ASC
            """,
            (subscription_id,),
        )
        available_chains = [
            {
                "id": chain["id"],
                "name": chain["name"],
                "status": chain["status"],
                "share_link": chain["share_link"],
                "path": chain["path"],
            }
            for chain in self.list_proxy_chains()
        ]
        return {
            "subscription": subscription,
            "availableNodes": self.list_clients(),
            "availableChains": available_chains,
            "selectedNodes": [
                {
                    "nodeClientId": row["node_client_id"],
                    "quotaBytes": row["quota_bytes"],
                    "displayName": row["display_name"],
                }
                for row in selected
            ],
            "selectedChains": [
                {
                    "chainId": row["chain_id"],
                    "displayName": row["display_name"],
                }
                for row in selected_chains
            ],
            "selectedChainIds": [row["chain_id"] for row in selected_chains],
        }

    def update_managed_subscription(
        self,
        subscription_id: str,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        self.get_subscription(subscription_id)
        name = str(payload.get("name", "")).strip()
        nodes = payload.get("nodes", [])
        if "nodeIds" in payload and not nodes:
            nodes = [{"nodeId": node_id} for node_id in payload.get("nodeIds", [])]
        if not isinstance(nodes, list):
            raise ValueError("nodes must be a list")
        chain_selection_supplied = "chains" in payload or "chainIds" in payload
        if "chains" in payload:
            chain_items = payload.get("chains", [])
            if not isinstance(chain_items, list):
                raise ValueError("chains must be a list")
        else:
            chain_ids = payload.get("chainIds", [])
            if not isinstance(chain_ids, list):
                raise ValueError("chainIds must be a list")
            chain_items = [{"chainId": chain_id} for chain_id in chain_ids]

        clients = {client["id"]: client for client in self.list_clients()}
        existing_display_names = {
            row["node_client_id"]: row["display_name"]
            for row in self.db.query_all(
                """
                SELECT node_client_id, display_name
                FROM subscription_entries
                WHERE subscription_id = ?
                """,
                (subscription_id,),
            )
        }
        existing_chain_display_names = {
            row["chain_id"]: row["display_name"]
            for row in self.db.query_all(
                """
                SELECT chain_id, display_name
                FROM subscription_chain_entries
                WHERE subscription_id = ?
                """,
                (subscription_id,),
            )
        }
        selected: list[tuple[str, int, str]] = []
        seen = set()
        for item in nodes:
            if not isinstance(item, dict):
                raise ValueError("nodes must contain objects")
            node_id = str(item.get("nodeId", "")).strip()
            if not node_id or node_id in seen:
                continue
            client = clients.get(node_id)
            if not client:
                raise ValueError("selected node not found")
            quota_gb = item.get("quotaGb", client["quota_bytes"] / 1024 / 1024 / 1024)
            try:
                quota_bytes = int(float(quota_gb) * 1024 * 1024 * 1024)
            except (TypeError, ValueError) as exc:
                raise ValueError("quotaGb must be a number") from exc
            if quota_bytes < 0:
                raise ValueError("quotaGb must be zero or greater")
            if "displayName" in item:
                display_name = str(item.get("displayName", "")).strip()
            else:
                display_name = existing_display_names.get(node_id, "")
            if len(display_name) > 128:
                raise ValueError("displayName must be 128 characters or fewer")
            selected.append((node_id, quota_bytes, display_name))
            seen.add(node_id)

        if chain_selection_supplied:
            chains = {chain["id"]: chain for chain in self.list_proxy_chains()}
            selected_chains: list[tuple[str, str]] = []
            seen_chains = set()
            for item in chain_items:
                if not isinstance(item, dict):
                    raise ValueError("chains must contain objects")
                text_id = str(item.get("chainId", "")).strip()
                if not text_id or text_id in seen_chains:
                    continue
                chain = chains.get(text_id)
                if not chain:
                    raise ValueError("selected proxy chain not found")
                if not chain["share_link"]:
                    raise ValueError("proxy chain is not ready")
                if "displayName" in item:
                    display_name = str(item.get("displayName", "")).strip()
                else:
                    display_name = existing_chain_display_names.get(text_id, "")
                if len(display_name) > 128:
                    raise ValueError("displayName must be 128 characters or fewer")
                selected_chains.append((text_id, display_name))
                seen_chains.add(text_id)
        else:
            selected_chains = [
                (row["chain_id"], row["display_name"])
                for row in self.db.query_all(
                    """
                    SELECT chain_id, display_name
                    FROM subscription_chain_entries
                    WHERE subscription_id = ?
                    ORDER BY created_at ASC
                    """,
                    (subscription_id,),
                )
            ]

        for node_id, quota_bytes, _display_name in selected:
            client = clients[node_id]
            if int(client["quota_bytes"]) == quota_bytes:
                continue
            self.update_client(
                node_id,
                {
                    "name": client["name"],
                    "quotaGb": quota_bytes / 1024 / 1024 / 1024,
                    "expiresAt": client["expires_at"],
                    "enabled": bool(client["enabled"]),
                },
            )

        stamp = now_iso()
        with self.db.transaction():
            if name:
                self.db.execute(
                    "UPDATE subscriptions SET name = ?, updated_at = ? WHERE id = ?",
                    (name, stamp, subscription_id),
                )
            else:
                self.db.execute(
                    "UPDATE subscriptions SET updated_at = ? WHERE id = ?",
                    (stamp, subscription_id),
                )
            self.db.execute(
                "DELETE FROM subscription_entries WHERE subscription_id = ?",
                (subscription_id,),
            )
            self.db.executemany(
                """
                INSERT INTO subscription_entries (
                    subscription_id, node_client_id, quota_bytes, display_name,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                [
                    (subscription_id, node_id, quota_bytes, display_name, stamp, stamp)
                    for node_id, quota_bytes, display_name in selected
                ],
            )
            default_deployment = self.db.query_one(
                "SELECT id FROM deployments WHERE ? = 'sub_' || id",
                (subscription_id,),
            )
            if default_deployment:
                default_deployment_id = default_deployment["id"]
                self.db.execute(
                    "DELETE FROM subscription_nodes WHERE subscription_id = ?",
                    (default_deployment_id,),
                )
                self.db.executemany(
                    """
                    INSERT INTO subscription_nodes (
                        subscription_id, node_client_id, display_name, created_at
                    ) VALUES (?, ?, ?, ?)
                    """,
                    [
                        (default_deployment_id, node_id, display_name, stamp)
                        for node_id, _quota_bytes, display_name in selected
                    ],
                )
            self.db.execute(
                "DELETE FROM subscription_chain_entries WHERE subscription_id = ?",
                (subscription_id,),
            )
            self.db.executemany(
                """
                INSERT INTO subscription_chain_entries (
                    subscription_id, chain_id, display_name, created_at
                ) VALUES (?, ?, ?, ?)
                """,
                [
                    (subscription_id, chain_id, display_name, stamp)
                    for chain_id, display_name in selected_chains
                ],
            )
        return self.get_managed_subscription_config(subscription_id)

    def delete_subscription(self, subscription_id: str) -> dict[str, str]:
        self.get_subscription(subscription_id)
        self.db.execute("DELETE FROM subscriptions WHERE id = ?", (subscription_id,))
        return {"deleted": subscription_id}

    def rotate_subscription_token(self, subscription_id: str) -> dict[str, Any]:
        self.get_subscription(subscription_id)
        self.db.execute(
            "UPDATE subscriptions SET token = ?, updated_at = ? WHERE id = ?",
            (secrets.token_urlsafe(24), now_iso(), subscription_id),
        )
        return self.get_subscription(subscription_id)

    def render_managed_subscription(self, token: str, output_format: str = "base64") -> str:
        subscription = self.db.query_one(
            "SELECT id FROM subscriptions WHERE token = ?",
            (token,),
        )
        if not subscription:
            raise ValueError("subscription not found")
        rows = self.db.query_all(
            """
            SELECT c.share_link, se.display_name
            FROM subscription_entries se
            JOIN clients c ON c.id = se.node_client_id
            WHERE se.subscription_id = ? AND c.enabled = 1
            ORDER BY se.created_at ASC, c.created_at ASC
            """,
            (subscription["id"],),
        )
        chain_rows = self.db.query_all(
            """
            SELECT pc.share_link, sce.display_name
            FROM subscription_chain_entries sce
            JOIN proxy_chains pc ON pc.id = sce.chain_id
            WHERE sce.subscription_id = ? AND pc.share_link != ''
            ORDER BY sce.created_at ASC, pc.created_at ASC
            """,
            (subscription["id"],),
        )
        links = [
            _share_link_with_display_name(row["share_link"], row.get("display_name", ""))
            for row in rows
            if row.get("share_link")
        ]
        links.extend(
            _share_link_with_display_name(row["share_link"], row["display_name"])
            for row in chain_rows
            if row.get("share_link")
        )
        return _render_subscription_links(links, output_format)

    def _delete_default_subscription(self, deployment_id: str) -> None:
        self.db.execute(
            "DELETE FROM subscriptions WHERE id = ? OR token = ?",
            (f"sub_{deployment_id}", deployment_id),
        )
