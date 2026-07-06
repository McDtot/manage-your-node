import base64
import json
import random
import secrets
import socket
import threading
import time
import uuid
from datetime import date, datetime, time as datetime_time, timedelta, timezone
from typing import Any
from urllib.parse import quote, urlencode, urlparse

from .database import Database
from .provisioning import native_3xui_script, shell_quote
from .security import SecretBox
from .ssh_runner import SshRunner
from .xui_api import XuiApiClient


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return f"{prefix}_{secrets.token_urlsafe(10)}"


def require_text(payload: dict[str, Any], key: str) -> str:
    value = str(payload.get(key, "")).strip()
    if not value:
        raise ValueError(f"{key} is required")
    return value


def int_field(payload: dict[str, Any], key: str, default: int) -> int:
    value = payload.get(key, default)
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{key} must be a number") from exc


class AppServices:
    def __init__(self, db: Database, secret_box: SecretBox):
        self.db = db
        self.secret_box = secret_box
        self.ssh = SshRunner(secret_box)

    def summary(self) -> dict[str, Any]:
        servers = self.db.query_one("SELECT COUNT(*) AS count FROM servers")["count"]
        ready = self.db.query_one(
            "SELECT COUNT(*) AS count FROM deployments WHERE status = 'ready'"
        )["count"]
        clients = self.db.query_one("SELECT COUNT(*) AS count FROM clients")["count"]
        chains = self.db.query_one("SELECT COUNT(*) AS count FROM proxy_chains")["count"]
        traffic = self.db.query_one(
            "SELECT COALESCE(SUM(used_bytes), 0) AS used, "
            "COALESCE(SUM(quota_bytes), 0) AS quota FROM clients"
        )
        soon = (datetime.now(timezone.utc) + timedelta(days=7)).date().isoformat()
        expiring = self.db.query_one(
            "SELECT COUNT(*) AS count FROM clients "
            "WHERE enabled = 1 AND expires_at <= ?",
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

    def list_servers(self) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            "SELECT id, name, host, ssh_port, ssh_user, auth_type, secret_label, "
            "os, arch, status, last_check_at, created_at, updated_at "
            "FROM servers ORDER BY created_at DESC"
        )
        return rows

    def create_server(self, payload: dict[str, Any]) -> dict[str, Any]:
        server_id = new_id("srv")
        stamp = now_iso()
        secret = str(payload.get("secret", ""))
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
                require_text(payload, "host"),
                int_field(payload, "sshPort", 22),
                require_text(payload, "sshUser"),
                require_text(payload, "authType"),
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
            "SELECT id, name, host, ssh_port, ssh_user, auth_type, secret_label, "
            "os, arch, status, last_check_at, created_at, updated_at "
            "FROM servers WHERE id = ?",
            (server_id,),
        )
        if not row:
            raise ValueError("server not found")
        return row

    def _get_server_row(self, server_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        if not row:
            raise ValueError("server not found")
        return row

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

    def list_deployments(self) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            """
            SELECT d.id, d.server_id, s.name AS server_name, s.host,
                   d.engine, d.protocol, d.install_method, d.panel_scheme, d.panel_port,
                   d.panel_path, d.panel_username, d.encrypted_panel_password,
                   d.encrypted_api_token, d.proxy_port, d.xui_inbound_id, d.status,
                   d.subscription_url, d.last_error, d.created_at, d.updated_at,
                   COUNT(c.id) AS client_count,
                   (
                       SELECT COUNT(*)
                       FROM subscription_nodes sn
                       WHERE sn.subscription_id = d.id
                   ) AS subscription_node_count
            FROM deployments d
            JOIN servers s ON s.id = d.server_id
            LEFT JOIN clients c ON c.deployment_id = d.id
            GROUP BY d.id
            ORDER BY d.created_at DESC
            """
        )
        for row in rows:
            self._attach_deployment_secrets(row)
        return rows

    def start_deployment(self, server_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        server = self.db.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        if not server:
            raise ValueError("server not found")

        deployment_id = new_id("dep")
        job_id = new_id("job")
        stamp = now_iso()
        proxy_port = int_field(payload, "proxyPort", 443)
        panel_port = int_field(payload, "panelPort", random.randint(32000, 39000))
        protocol = str(payload.get("protocol", "VLESS + REALITY")).strip()
        install_method = str(payload.get("installMethod", "dry-run")).strip()
        if install_method not in {"dry-run", "native"}:
            raise ValueError("installMethod must be dry-run or native")
        panel_path = "/" + secrets.token_urlsafe(8)
        panel_username = "myn_" + secrets.token_urlsafe(5).replace("-", "A").replace("_", "B")
        panel_password = secrets.token_urlsafe(18).replace("-", "A").replace("_", "B")
        api_token = secrets.token_urlsafe(28)
        subscription_url = self._deployment_subscription_url(deployment_id)

        self.db.execute(
            """
            INSERT INTO deployments (
                id, server_id, engine, protocol, install_method, panel_scheme, panel_port, panel_path,
                panel_username, encrypted_panel_password, encrypted_api_token,
                proxy_port, subscription_configured, status, subscription_url, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                deployment_id,
                server_id,
                "3x-ui",
                protocol,
                install_method,
                "http",
                panel_port,
                panel_path,
                panel_username,
                self.secret_box.seal(panel_password),
                self.secret_box.seal(api_token),
                proxy_port,
                1,
                "provisioning",
                subscription_url,
                stamp,
                stamp,
            ),
        )
        self._ensure_deployment_subscription(deployment_id, server["name"], stamp)
        self.db.execute(
            """
            INSERT INTO jobs (
                id, type, server_id, deployment_id, status, logs,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                "deploy_3xui",
                server_id,
                deployment_id,
                "running",
                json.dumps([], ensure_ascii=False),
                stamp,
                stamp,
            ),
        )

        thread = threading.Thread(
            target=self._run_deployment,
            args=(job_id, deployment_id, server, payload),
            daemon=True,
        )
        thread.start()

        return {
            "job": self.get_job(job_id),
            "deployment": self.get_deployment(deployment_id),
        }

    def _run_deployment(
        self,
        job_id: str,
        deployment_id: str,
        server: dict[str, Any],
        payload: dict[str, Any],
    ) -> None:
        if str(payload.get("installMethod", "dry-run")) == "native":
            self._run_native_deployment(job_id, deployment_id, server, payload)
            return
        self._run_dry_deployment(job_id, deployment_id, server, payload)

    def _run_dry_deployment(
        self,
        job_id: str,
        deployment_id: str,
        server: dict[str, Any],
        payload: dict[str, Any],
    ) -> None:
        stages = [
            "Dry-run: check SSH host identity",
            "Dry-run: check OS, CPU architecture, and sudo access",
            "Dry-run: check Docker and Compose plugin",
            "Dry-run: prepare /opt/manage-node/3x-ui",
            "Dry-run: generate 3x-ui configuration",
            "Dry-run: wait for panel health check",
            "Dry-run: initialize panel credentials and API token",
            "Dry-run: create default VLESS + REALITY inbound",
        ]
        try:
            for stage in stages:
                self._append_job_log(job_id, stage)
                time.sleep(0.35)

            self.db.execute(
                "UPDATE deployments SET status = ?, updated_at = ? WHERE id = ?",
                ("ready", now_iso(), deployment_id),
            )
            self._append_job_log(
                job_id,
                f"Dry-run finished: generated 3x-ui deployment data for {server['host']}",
            )

            if payload.get("createInitialClient", True):
                self.create_client(
                    deployment_id,
                    {
                        "name": payload.get("clientName") or "default-client",
                        "quotaGb": payload.get("quotaGb") or 100,
                        "expiresAt": payload.get("expiresAt")
                        or (datetime.now(timezone.utc) + timedelta(days=30))
                        .date()
                        .isoformat(),
                    },
                )
                self._append_job_log(job_id, "Created initial local client and share link")

            self._finish_job(job_id, "success", None)
        except Exception as exc:  # noqa: BLE001
            self.db.execute(
                "UPDATE deployments SET status = ?, last_error = ?, updated_at = ? "
                "WHERE id = ?",
                ("failed", str(exc), now_iso(), deployment_id),
            )
            self._finish_job(job_id, "failed", str(exc))

    def _run_native_deployment(
        self,
        job_id: str,
        deployment_id: str,
        server: dict[str, Any],
        payload: dict[str, Any],
    ) -> None:
        try:
            deployment = self._get_deployment_row(deployment_id)
            panel_password = self.secret_box.open(deployment["encrypted_panel_password"])
            script = native_3xui_script(
                panel_port=deployment["panel_port"],
                panel_path=deployment["panel_path"],
                panel_username=deployment["panel_username"],
                panel_password=panel_password,
                server_host=server["host"],
            )
            self._append_job_log(job_id, "Starting real SSH deployment with official 3x-ui installer")
            lines = self.ssh.run_script(
                server,
                script,
                lambda line: self._append_job_log(job_id, line),
                timeout=1200,
            )
            result = self._parse_install_result(lines)
            if result:
                self._apply_install_result(deployment_id, result)
            deployment = self.get_deployment(deployment_id)
            self._append_job_log(job_id, "Waiting for 3x-ui API to become ready")
            xui = self._xui_client(deployment)
            xui.wait_ready()
            xui.login()
            self._append_job_log(job_id, "Creating default VLESS + REALITY inbound through 3x-ui API")
            inbound = xui.create_vless_reality_inbound(
                port=deployment["proxy_port"],
                remark=f"myn-{server['name']}-{deployment['proxy_port']}",
            )
            self.db.execute(
                "UPDATE deployments SET xui_inbound_id = ?, updated_at = ? WHERE id = ?",
                (int(inbound["id"]), now_iso(), deployment_id),
            )
            self._append_job_log(job_id, f"Created 3x-ui inbound id={inbound['id']}")
            self.db.execute(
                "UPDATE deployments SET status = ?, updated_at = ? WHERE id = ?",
                ("ready", now_iso(), deployment_id),
            )
            self._append_job_log(job_id, "3x-ui panel is installed and default inbound is ready")

            if payload.get("createInitialClient", True):
                self.create_client(
                    deployment_id,
                    {
                        "name": payload.get("clientName") or "default-client",
                        "quotaGb": payload.get("quotaGb") or 100,
                        "expiresAt": payload.get("expiresAt")
                        or (datetime.now(timezone.utc) + timedelta(days=30))
                        .date()
                        .isoformat(),
                    },
                )
                self._append_job_log(job_id, "Created initial client in 3x-ui and stored share link")

            try:
                xui.restart_xray()
                self._append_job_log(job_id, "Requested Xray restart")
            except Exception as exc:  # noqa: BLE001
                self._append_job_log(job_id, f"Xray restart request failed, panel may restart it soon: {exc}")

            self._finish_job(job_id, "success", None)
        except Exception as exc:  # noqa: BLE001
            self.db.execute(
                "UPDATE deployments SET status = ?, last_error = ?, updated_at = ? "
                "WHERE id = ?",
                ("failed", str(exc), now_iso(), deployment_id),
            )
            self._append_job_log(job_id, f"Deployment failed: {exc}")
            self._finish_job(job_id, "failed", str(exc))

    def _parse_install_result(self, lines: list[str]) -> dict[str, str]:
        capture = False
        result: dict[str, str] = {}
        for line in lines:
            if line.strip() == "__MYN_RESULT_BEGIN__":
                capture = True
                continue
            if line.strip() == "__MYN_RESULT_END__":
                break
            if not capture or "=" not in line:
                continue
            key, value = line.split("=", 1)
            result[key.strip()] = value.strip().strip("'\"")
        return result

    def _apply_install_result(self, deployment_id: str, result: dict[str, str]) -> None:
        panel_port = int(result.get("XUI_PANEL_PORT") or result.get("PANEL_PORT") or 0)
        panel_path = "/" + (result.get("XUI_WEB_BASE_PATH") or "").strip("/")
        panel_scheme = ""
        access_url = result.get("XUI_ACCESS_URL") or ""
        if access_url:
            parsed = urlparse(access_url)
            panel_scheme = parsed.scheme
            if parsed.port:
                panel_port = parsed.port
            if parsed.path and parsed.path != "/":
                panel_path = "/" + parsed.path.strip("/")
        username = result.get("XUI_USERNAME") or ""
        password = result.get("XUI_PASSWORD") or ""
        api_token = result.get("XUI_API_TOKEN") or ""
        updates: list[str] = []
        params: list[Any] = []
        if panel_port:
            updates.append("panel_port = ?")
            params.append(panel_port)
        if panel_scheme:
            updates.append("panel_scheme = ?")
            params.append(panel_scheme)
        if panel_path != "/":
            updates.append("panel_path = ?")
            params.append(panel_path)
        if username:
            updates.append("panel_username = ?")
            params.append(username)
        if password:
            updates.append("encrypted_panel_password = ?")
            params.append(self.secret_box.seal(password))
        if api_token:
            updates.append("encrypted_api_token = ?")
            params.append(self.secret_box.seal(api_token))
        if not updates:
            return
        updates.append("updated_at = ?")
        params.append(now_iso())
        params.append(deployment_id)
        self.db.execute(
            f"UPDATE deployments SET {', '.join(updates)} WHERE id = ?",
            tuple(params),
        )

    def _append_job_log(self, job_id: str, line: str) -> None:
        job = self.db.query_one("SELECT logs FROM jobs WHERE id = ?", (job_id,))
        if not job:
            return
        logs = json.loads(job["logs"])
        logs.append({"at": now_iso(), "line": line})
        self.db.execute(
            "UPDATE jobs SET logs = ?, updated_at = ? WHERE id = ?",
            (json.dumps(logs, ensure_ascii=False), now_iso(), job_id),
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

    def get_deployment(self, deployment_id: str) -> dict[str, Any]:
        row = self.db.query_one(
            """
            SELECT d.id, d.server_id, s.name AS server_name, s.host,
                   d.engine, d.protocol, d.install_method, d.panel_scheme, d.panel_port,
                   d.panel_path, d.panel_username, d.encrypted_panel_password,
                   d.encrypted_api_token, d.proxy_port, d.xui_inbound_id, d.status,
                   d.subscription_url, d.last_error, d.created_at, d.updated_at,
                   (
                       SELECT COUNT(*)
                       FROM subscription_nodes sn
                       WHERE sn.subscription_id = d.id
                   ) AS subscription_node_count
            FROM deployments d
            JOIN servers s ON s.id = d.server_id
            WHERE d.id = ?
            """,
            (deployment_id,),
        )
        if not row:
            raise ValueError("deployment not found")
        self._attach_deployment_secrets(row)
        return row

    def _get_deployment_row(self, deployment_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM deployments WHERE id = ?", (deployment_id,))
        if not row:
            raise ValueError("deployment not found")
        return row

    def _attach_deployment_secrets(self, row: dict[str, Any]) -> None:
        row["panel_url"] = f"{row['panel_scheme']}://{row['host']}:{row['panel_port']}{row['panel_path']}/"
        row["subscription_url"] = self._deployment_subscription_url(row["id"])
        row["panel_password"] = self.secret_box.open(row.pop("encrypted_panel_password", ""))
        row["api_token"] = self.secret_box.open(row.pop("encrypted_api_token", ""))

    def _deployment_subscription_url(self, deployment_id: str) -> str:
        return f"/sub/deployments/{deployment_id}"

    def _subscription_url(self, token: str) -> str:
        return f"/sub/links/{token}"

    def _chain_subscription_url(self, token: str) -> str:
        return f"/sub/chains/{token}"

    def _ensure_deployment_subscription(
        self,
        deployment_id: str,
        server_name: str,
        stamp: str | None = None,
    ) -> None:
        created_at = stamp or now_iso()
        self.db.execute(
            """
            INSERT OR IGNORE INTO subscriptions (
                id, name, token, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (
                f"sub_{deployment_id}",
                f"{server_name} 默认订阅",
                deployment_id,
                created_at,
                created_at,
            ),
        )

    def _xui_client(self, deployment: dict[str, Any]) -> XuiApiClient:
        return XuiApiClient(
            base_url=deployment["panel_url"],
            username=deployment["panel_username"],
            password=deployment["panel_password"],
            api_token=deployment.get("api_token") or "",
        )

    def list_clients(self) -> list[dict[str, Any]]:
        return self.db.query_all(
            """
            SELECT c.id, c.deployment_id, d.server_id, s.name AS server_name,
                   s.host, c.name, c.uuid, c.quota_bytes, c.used_bytes,
                   c.expires_at, c.enabled, c.share_link, c.subscription_url,
                   c.created_at, c.updated_at
            FROM clients c
            JOIN deployments d ON d.id = c.deployment_id
            JOIN servers s ON s.id = d.server_id
            ORDER BY c.created_at DESC
            """
        )

    def list_proxy_chains(self) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            """
            SELECT id, name, token, client_uuid, status, share_link,
                   last_error, created_at, updated_at
            FROM proxy_chains
            ORDER BY created_at DESC
            """
        )
        for row in rows:
            nodes = self._proxy_chain_nodes(row["id"])
            row["nodes"] = nodes
            row["path"] = " -> ".join(node["server_name"] for node in nodes)
            row["entry_server_name"] = nodes[0]["server_name"] if nodes else ""
            row["exit_server_name"] = nodes[-1]["server_name"] if nodes else ""
            row["subscription_url"] = self._chain_subscription_url(row["token"])
        return rows

    def create_proxy_chain(self, payload: dict[str, Any]) -> dict[str, Any]:
        deployment_ids = payload.get("deploymentIds") or payload.get("nodeIds") or []
        if not isinstance(deployment_ids, list):
            raise ValueError("deploymentIds must be a list")

        ordered_ids: list[str] = []
        seen = set()
        for deployment_id in deployment_ids:
            text_id = str(deployment_id).strip()
            if not text_id or text_id in seen:
                continue
            ordered_ids.append(text_id)
            seen.add(text_id)

        if len(ordered_ids) < 2:
            raise ValueError("proxy chain requires at least two deployments")
        if len(ordered_ids) > 6:
            raise ValueError("proxy chain supports up to six deployments for now")

        deployments = self._chain_deployments_by_id(ordered_ids)
        missing = [deployment_id for deployment_id in ordered_ids if deployment_id not in deployments]
        if missing:
            raise ValueError("selected deployment not found")
        not_ready = [deployments[deployment_id]["server_name"] for deployment_id in ordered_ids if deployments[deployment_id]["status"] != "ready"]
        if not_ready:
            raise ValueError(f"deployment is not ready: {', '.join(not_ready)}")

        name = str(payload.get("name", "")).strip()
        if not name:
            name = " -> ".join(deployments[deployment_id]["server_name"] for deployment_id in ordered_ids)

        chain_id = new_id("chn")
        token = secrets.token_urlsafe(14)
        client_uuid = str(uuid.uuid4())
        stamp = now_iso()
        self.db.execute(
            """
            INSERT INTO proxy_chains (
                id, name, token, client_uuid, status, share_link, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (chain_id, name, token, client_uuid, "planned", "", stamp, stamp),
        )
        self.db.executemany(
            """
            INSERT INTO proxy_chain_nodes (
                chain_id, deployment_id, position, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            [
                (chain_id, deployment_id, index, stamp)
                for index, deployment_id in enumerate(ordered_ids)
            ],
        )
        return self.get_proxy_chain(chain_id)

    def get_proxy_chain(self, chain_id: str) -> dict[str, Any]:
        rows = [chain for chain in self.list_proxy_chains() if chain["id"] == chain_id]
        if not rows:
            raise ValueError("proxy chain not found")
        return rows[0]

    def delete_proxy_chain(self, chain_id: str) -> dict[str, Any]:
        logs = self._cleanup_proxy_chain_services(chain_id)
        self.db.execute("DELETE FROM proxy_chains WHERE id = ?", (chain_id,))
        return {"deleted": chain_id, "remoteLogs": logs[-20:]}

    def start_proxy_chain_deployment(self, chain_id: str) -> dict[str, Any]:
        self.get_proxy_chain(chain_id)
        job_id = new_id("job")
        stamp = now_iso()
        self.db.execute(
            """
            INSERT INTO jobs (
                id, type, chain_id, status, logs, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                job_id,
                "deploy_proxy_chain",
                chain_id,
                "running",
                json.dumps([], ensure_ascii=False),
                stamp,
                stamp,
            ),
        )
        self.db.execute(
            """
            UPDATE proxy_chains
            SET status = ?, last_error = NULL, updated_at = ?
            WHERE id = ?
            """,
            ("deploying", stamp, chain_id),
        )
        thread = threading.Thread(
            target=self._run_proxy_chain_deployment,
            args=(job_id, chain_id),
            daemon=True,
        )
        thread.start()
        return {
            "job": self.get_job(job_id),
            "chain": self.get_proxy_chain(chain_id),
        }

    def _run_proxy_chain_deployment(self, job_id: str, chain_id: str) -> None:
        try:
            chain = self.get_proxy_chain(chain_id)
            nodes = self._proxy_chain_full_nodes(chain_id)
            if len(nodes) < 2:
                raise ValueError("proxy chain requires at least two deployments")
            if all(node["install_method"] == "dry-run" for node in nodes):
                self._run_dry_proxy_chain_deployment(job_id, chain_id, chain, nodes)
                return

            invalid = [
                node["server_name"]
                for node in nodes
                if node["install_method"] != "native" or node["deployment_status"] != "ready"
            ]
            if invalid:
                raise ValueError(
                    "real chain deployment requires every node to be a ready native deployment: "
                    + ", ".join(invalid)
                )

            self._append_job_log(job_id, f"Preparing proxy chain: {chain['path']}")
            nodes = self._prepare_proxy_chain_nodes(job_id, chain_id, nodes, dry_run=False)
            self._append_job_log(job_id, "Installing chain services from exit to entry")
            for index in range(len(nodes) - 1, -1, -1):
                node = nodes[index]
                next_node = nodes[index + 1] if index + 1 < len(nodes) else None
                config = self._chain_xray_config(node, next_node)
                self._install_proxy_chain_service(job_id, chain_id, node, config)
                self.db.execute(
                    """
                    UPDATE proxy_chain_nodes
                    SET status = ?, updated_at = ?
                    WHERE chain_id = ? AND position = ?
                    """,
                    ("ready", now_iso(), chain_id, node["position"]),
                )

            self._finish_proxy_chain_deployment(job_id, chain_id, chain["name"])
        except Exception as exc:  # noqa: BLE001
            self.db.execute(
                """
                UPDATE proxy_chains
                SET status = ?, last_error = ?, updated_at = ?
                WHERE id = ?
                """,
                ("failed", str(exc), now_iso(), chain_id),
            )
            self._append_job_log(job_id, f"Proxy chain deployment failed: {exc}")
            self._finish_job(job_id, "failed", str(exc))

    def _run_dry_proxy_chain_deployment(
        self,
        job_id: str,
        chain_id: str,
        chain: dict[str, Any],
        nodes: list[dict[str, Any]],
    ) -> None:
        self._append_job_log(job_id, f"Dry-run: preparing proxy chain {chain['path']}")
        nodes = self._prepare_proxy_chain_nodes(job_id, chain_id, nodes, dry_run=True)
        for index, node in enumerate(nodes):
            role = "exit" if index == len(nodes) - 1 else "relay"
            self._append_job_log(
                job_id,
                f"Dry-run: {node['server_name']} prepared as {role} on port {node['inbound_port']}",
            )
            time.sleep(0.15)
            self.db.execute(
                """
                UPDATE proxy_chain_nodes
                SET status = ?, updated_at = ?
                WHERE chain_id = ? AND position = ?
                """,
                ("ready", now_iso(), chain_id, node["position"]),
            )
        self._finish_proxy_chain_deployment(job_id, chain_id, chain["name"])

    def _finish_proxy_chain_deployment(self, job_id: str, chain_id: str, name: str) -> None:
        nodes = self._proxy_chain_full_nodes(chain_id)
        if not nodes:
            raise ValueError("proxy chain has no nodes")
        entry = nodes[0]
        share_link = self._chain_share_link(entry, name)
        stamp = now_iso()
        self.db.execute(
            """
            UPDATE proxy_chains
            SET client_uuid = ?, status = ?, share_link = ?, last_error = NULL, updated_at = ?
            WHERE id = ?
            """,
            (entry["node_client_uuid"], "ready", share_link, stamp, chain_id),
        )
        self._append_job_log(job_id, f"Proxy chain is ready: {self.get_proxy_chain(chain_id)['path']}")
        self._finish_job(job_id, "success", None)

    def _prepare_proxy_chain_nodes(
        self,
        job_id: str,
        chain_id: str,
        nodes: list[dict[str, Any]],
        dry_run: bool,
    ) -> list[dict[str, Any]]:
        used_ports = {
            int(row["inbound_port"])
            for row in nodes
            if row.get("inbound_port")
        }
        used_ports.update(
            int(row["proxy_port"])
            for row in nodes
            if row.get("proxy_port")
        )
        prepared: list[dict[str, Any]] = []
        for node in nodes:
            update: dict[str, Any] = {}
            if not node.get("inbound_port"):
                update["inbound_port"] = self._new_chain_port(used_ports)
                used_ports.add(update["inbound_port"])
            if not node.get("node_client_uuid"):
                update["client_uuid"] = str(uuid.uuid4())
            if not node.get("short_id"):
                update["short_id"] = secrets.token_hex(4)
            if not node.get("public_key") or not node.get("encrypted_private_key"):
                if dry_run:
                    private_key, public_key = self._dry_reality_keypair()
                else:
                    self._append_job_log(job_id, f"Generating REALITY keypair on {node['server_name']}")
                    private_key, public_key = self._remote_x25519_keypair(node)
                update["encrypted_private_key"] = self.secret_box.seal(private_key)
                update["public_key"] = public_key
            if not node.get("remote_service_name"):
                update["remote_service_name"] = f"myn-chain-{chain_id}-{node['position']}"

            if update:
                assignments = ", ".join(f"{column} = ?" for column in update)
                params = list(update.values())
                params.extend([now_iso(), chain_id, node["position"]])
                self.db.execute(
                    f"""
                    UPDATE proxy_chain_nodes
                    SET {assignments}, updated_at = ?
                    WHERE chain_id = ? AND position = ?
                    """,
                    tuple(params),
                )
            prepared.append(self._proxy_chain_full_nodes(chain_id)[node["position"]])
        return prepared

    def _new_chain_port(self, used_ports: set[int]) -> int:
        for _ in range(80):
            port = random.randint(41000, 60999)
            if port not in used_ports:
                return port
        raise ValueError("could not allocate a chain port")

    def _dry_reality_keypair(self) -> tuple[str, str]:
        return secrets.token_urlsafe(32)[:43], secrets.token_urlsafe(32)[:43]

    def _remote_x25519_keypair(self, node: dict[str, Any]) -> tuple[str, str]:
        lines = self.ssh.run_script(
            node,
            self._xray_keypair_script(),
            lambda _: None,
            timeout=60,
        )
        private_key = ""
        public_key = ""
        for line in lines:
            text = line.strip()
            if text.lower().startswith("private key:"):
                private_key = text.split(":", 1)[1].strip()
            if text.lower().startswith("public key:"):
                public_key = text.split(":", 1)[1].strip()
        if not private_key or not public_key:
            raise ValueError(f"could not generate X25519 keypair on {node['server_name']}")
        return private_key, public_key

    def _xray_keypair_script(self) -> str:
        return r"""
set -Eeuo pipefail
find_xray() {
  for candidate in \
    /usr/local/x-ui/bin/xray \
    /usr/local/x-ui/bin/xray-linux-* \
    /usr/bin/xray \
    /usr/local/bin/xray
  do
    for path in $candidate; do
      if [ -x "$path" ]; then
        printf '%s\n' "$path"
        return 0
      fi
    done
  done
  if command -v xray >/dev/null 2>&1; then
    command -v xray
    return 0
  fi
  return 1
}
XRAY="$(find_xray)" || { echo "xray binary not found" >&2; exit 42; }
echo "Using Xray: $XRAY"
"$XRAY" x25519
"""

    def _install_proxy_chain_service(
        self,
        job_id: str,
        chain_id: str,
        node: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        service_name = node["remote_service_name"]
        self._append_job_log(
            job_id,
            f"Installing {service_name} on {node['server_name']}:{node['inbound_port']}",
        )
        self.ssh.run_script(
            node,
            self._chain_install_script(service_name, int(node["inbound_port"]), config),
            lambda line: self._append_job_log(job_id, f"{node['server_name']}: {line}"),
            timeout=240,
        )

    def _chain_install_script(
        self,
        service_name: str,
        inbound_port: int,
        config: dict[str, Any],
    ) -> str:
        encoded_config = base64.b64encode(
            json.dumps(config, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        ).decode("ascii")
        return f"""#!/usr/bin/env bash
set -Eeuo pipefail

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  if ! command -v sudo >/dev/null 2>&1; then
    echo "sudo is required when SSH user is not root" >&2
    exit 20
  fi
  SUDO="sudo"
fi

find_xray() {{
  for candidate in \\
    /usr/local/x-ui/bin/xray \\
    /usr/local/x-ui/bin/xray-linux-* \\
    /usr/bin/xray \\
    /usr/local/bin/xray
  do
    for path in $candidate; do
      if [ -x "$path" ]; then
        printf '%s\\n' "$path"
        return 0
      fi
    done
  done
  if command -v xray >/dev/null 2>&1; then
    command -v xray
    return 0
  fi
  return 1
}}

XRAY="$(find_xray)" || {{ echo "xray binary not found" >&2; exit 42; }}
SERVICE_NAME={shell_quote(service_name)}
INSTALL_DIR="/opt/manage-node/chains/$SERVICE_NAME"
CONFIG_FILE="$INSTALL_DIR/config.json"
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"
CONFIG_B64={shell_quote(encoded_config)}

echo "Using Xray: $XRAY"
$SUDO install -d -m 0755 "$INSTALL_DIR"
printf '%s' "$CONFIG_B64" | base64 -d | $SUDO tee "$CONFIG_FILE.tmp" >/dev/null
$SUDO chmod 0644 "$CONFIG_FILE.tmp"

if $SUDO "$XRAY" run -test -config "$CONFIG_FILE.tmp" >/tmp/"$SERVICE_NAME".test.log 2>&1; then
  true
elif $SUDO "$XRAY" -test -config "$CONFIG_FILE.tmp" >/tmp/"$SERVICE_NAME".test.log 2>&1; then
  true
else
  cat /tmp/"$SERVICE_NAME".test.log >&2 || true
  exit 43
fi

$SUDO mv "$CONFIG_FILE.tmp" "$CONFIG_FILE"
$SUDO tee "$UNIT_FILE" >/dev/null <<EOF
[Unit]
Description=Manage Your Node proxy chain $SERVICE_NAME
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=$XRAY run -config $CONFIG_FILE
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF

$SUDO systemctl daemon-reload
$SUDO systemctl enable "$SERVICE_NAME" >/dev/null
$SUDO systemctl restart "$SERVICE_NAME"
$SUDO systemctl is-active --quiet "$SERVICE_NAME"

if command -v ufw >/dev/null 2>&1; then
  $SUDO ufw allow {shell_quote(inbound_port)}/tcp >/dev/null 2>&1 || true
fi
if command -v firewall-cmd >/dev/null 2>&1; then
  $SUDO firewall-cmd --permanent --add-port={shell_quote(inbound_port)}/tcp >/dev/null 2>&1 || true
  $SUDO firewall-cmd --reload >/dev/null 2>&1 || true
fi

echo "Service $SERVICE_NAME is active"
"""

    def _chain_xray_config(
        self,
        node: dict[str, Any],
        next_node: dict[str, Any] | None,
    ) -> dict[str, Any]:
        inbound = {
            "tag": "myn-chain-in",
            "listen": "",
            "port": int(node["inbound_port"]),
            "protocol": "vless",
            "settings": {
                "clients": [
                    {
                        "id": node["node_client_uuid"],
                        "email": f"myn-chain-{node['position']}",
                        "flow": "xtls-rprx-vision",
                    }
                ],
                "decryption": "none",
            },
            "streamSettings": {
                "network": "tcp",
                "tcpSettings": {"header": {"type": "none"}},
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "dest": "www.yahoo.com:443",
                    "xver": 0,
                    "serverNames": ["www.yahoo.com"],
                    "privateKey": self.secret_box.open(node["encrypted_private_key"]),
                    "shortIds": [node["short_id"]],
                },
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic"],
                "metadataOnly": False,
                "routeOnly": False,
            },
        }
        if next_node:
            outbound = {
                "tag": "myn-chain-next",
                "protocol": "vless",
                "settings": {
                    "vnext": [
                        {
                            "address": next_node["host"],
                            "port": int(next_node["inbound_port"]),
                            "users": [
                                {
                                    "id": next_node["node_client_uuid"],
                                    "encryption": "none",
                                    "flow": "xtls-rprx-vision",
                                }
                            ],
                        }
                    ]
                },
                "streamSettings": {
                    "network": "tcp",
                    "tcpSettings": {"header": {"type": "none"}},
                    "security": "reality",
                    "realitySettings": {
                        "serverName": "www.yahoo.com",
                        "fingerprint": "chrome",
                        "publicKey": next_node["public_key"],
                        "shortId": next_node["short_id"],
                        "spiderX": "/",
                    },
                },
            }
        else:
            outbound = {"tag": "direct", "protocol": "freedom"}
        return {
            "log": {"loglevel": "warning"},
            "inbounds": [inbound],
            "outbounds": [outbound],
        }

    def _chain_share_link(self, entry: dict[str, Any], name: str) -> str:
        params = {
            "security": "reality",
            "type": "tcp",
            "flow": "xtls-rprx-vision",
            "pbk": entry["public_key"],
            "fp": "chrome",
            "sni": "www.yahoo.com",
            "sid": entry["short_id"],
            "spx": "/",
        }
        tag = quote(name)
        return (
            f"vless://{entry['node_client_uuid']}@{entry['host']}:{entry['inbound_port']}"
            f"?{urlencode(params)}#{tag}"
        )

    def _cleanup_proxy_chain_services(self, chain_id: str) -> list[str]:
        nodes = self._proxy_chain_full_nodes(chain_id)
        logs: list[str] = []
        for node in nodes:
            service_name = node.get("remote_service_name")
            if node.get("install_method") != "native" or not service_name:
                continue
            try:
                lines = self.ssh.run_script(
                    node,
                    self._chain_cleanup_script(service_name),
                    lambda _: None,
                    timeout=120,
                )
                logs.extend(f"{node['server_name']}: {line}" for line in lines if line)
            except Exception as exc:  # noqa: BLE001
                logs.append(f"{node['server_name']}: cleanup failed: {exc}")
        return logs

    def _cleanup_proxy_chains_for_deployments(self, deployment_ids: list[str]) -> list[str]:
        if not deployment_ids:
            return []
        placeholders = ",".join("?" for _ in deployment_ids)
        rows = self.db.query_all(
            f"""
            SELECT DISTINCT chain_id
            FROM proxy_chain_nodes
            WHERE deployment_id IN ({placeholders})
            """,
            tuple(deployment_ids),
        )
        logs: list[str] = []
        for row in rows:
            logs.extend(self._cleanup_proxy_chain_services(row["chain_id"]))
        return logs

    def _chain_cleanup_script(self, service_name: str) -> str:
        return f"""#!/usr/bin/env bash
set -u
if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi
SERVICE_NAME={shell_quote(service_name)}
INSTALL_DIR="/opt/manage-node/chains/$SERVICE_NAME"
UNIT_FILE="/etc/systemd/system/$SERVICE_NAME.service"
echo "Stopping $SERVICE_NAME"
$SUDO systemctl stop "$SERVICE_NAME" 2>/dev/null || true
$SUDO systemctl disable "$SERVICE_NAME" 2>/dev/null || true
$SUDO rm -f "$UNIT_FILE"
$SUDO rm -rf "$INSTALL_DIR"
$SUDO systemctl daemon-reload 2>/dev/null || true
$SUDO systemctl reset-failed "$SERVICE_NAME" 2>/dev/null || true
echo "Removed $SERVICE_NAME"
"""

    def _proxy_chain_full_nodes(self, chain_id: str) -> list[dict[str, Any]]:
        return self.db.query_all(
            """
            SELECT pcn.position, pcn.inbound_port,
                   pcn.client_uuid AS node_client_uuid,
                   pcn.encrypted_private_key, pcn.public_key, pcn.short_id,
                   pcn.remote_service_name, pcn.status AS node_status,
                   d.id AS deployment_id, d.install_method,
                   d.status AS deployment_status, d.protocol, d.proxy_port,
                   s.id AS server_id, s.name AS server_name, s.host, s.ssh_port,
                   s.ssh_user, s.auth_type, s.encrypted_secret, s.secret_label
            FROM proxy_chain_nodes pcn
            JOIN deployments d ON d.id = pcn.deployment_id
            JOIN servers s ON s.id = d.server_id
            WHERE pcn.chain_id = ?
            ORDER BY pcn.position ASC
            """,
            (chain_id,),
        )

    def render_proxy_chain_subscription(self, token: str) -> str:
        row = self.db.query_one(
            "SELECT share_link FROM proxy_chains WHERE token = ?",
            (token,),
        )
        if not row:
            raise ValueError("proxy chain not found")
        return base64.b64encode(row["share_link"].encode("utf-8")).decode("ascii")

    def _proxy_chain_nodes(self, chain_id: str) -> list[dict[str, Any]]:
        return self.db.query_all(
            """
            SELECT pcn.position, d.id AS deployment_id, s.name AS server_name,
                   s.host, d.protocol, d.proxy_port, d.status,
                   pcn.inbound_port, pcn.client_uuid, pcn.public_key,
                   pcn.short_id, pcn.remote_service_name, pcn.status AS node_status
            FROM proxy_chain_nodes pcn
            JOIN deployments d ON d.id = pcn.deployment_id
            JOIN servers s ON s.id = d.server_id
            WHERE pcn.chain_id = ?
            ORDER BY pcn.position ASC
            """,
            (chain_id,),
        )

    def _chain_deployments_by_id(self, deployment_ids: list[str]) -> dict[str, dict[str, Any]]:
        if not deployment_ids:
            return {}
        placeholders = ",".join("?" for _ in deployment_ids)
        rows = self.db.query_all(
            f"""
            SELECT d.id, s.name AS server_name, s.host,
                   d.protocol, d.proxy_port, d.status, d.install_method
            FROM deployments d
            JOIN servers s ON s.id = d.server_id
            WHERE d.id IN ({placeholders})
            """,
            tuple(deployment_ids),
        )
        return {row["id"]: row for row in rows}

    def create_client(self, deployment_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        deployment = self.get_deployment(deployment_id)
        client_id = new_id("cli")
        client_uuid = str(uuid.uuid4())
        quota_gb = float(payload.get("quotaGb", 100))
        quota_bytes = int(quota_gb * 1024 * 1024 * 1024)
        expires_at = str(payload.get("expiresAt", "")).strip()
        if not expires_at:
            expires_at = (datetime.now(timezone.utc) + timedelta(days=30)).date().isoformat()
        name = require_text(payload, "name")
        tag = quote(name)
        share_link = (
            f"vless://{client_uuid}@{deployment['host']}:{deployment['proxy_port']}"
            f"?security=reality&type=tcp&flow=xtls-rprx-vision#{tag}"
        )
        sub_id = client_id[-12:]
        if (
            deployment.get("install_method") == "native"
            and deployment.get("status") == "ready"
            and deployment.get("xui_inbound_id")
        ):
            xui = self._xui_client(deployment)
            xui.wait_ready(seconds=30)
            xui.login()
            links = xui.create_client(
                inbound_id=int(deployment["xui_inbound_id"]),
                email=name,
                client_uuid=client_uuid,
                sub_id=sub_id,
                quota_bytes=quota_bytes,
                expires_ms=self._expires_ms(expires_at),
            )
            if links:
                share_link = links[0]
        stamp = now_iso()
        self.db.execute(
            """
            INSERT INTO clients (
                id, deployment_id, name, uuid, quota_bytes, used_bytes,
                expires_at, enabled, share_link, subscription_url,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                client_id,
                deployment_id,
                name,
                client_uuid,
                quota_bytes,
                0,
                expires_at,
                1,
                share_link,
                deployment["subscription_url"],
                stamp,
                stamp,
            ),
        )
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
            ) VALUES (?, ?, ?, ?, ?)
            """,
            (f"sub_{deployment_id}", client_id, quota_bytes, stamp, stamp),
        )
        return self.get_client(client_id)

    def _default_share_link(self, deployment: dict[str, Any], client_uuid: str, name: str) -> str:
        tag = quote(name)
        return (
            f"vless://{client_uuid}@{deployment['host']}:{deployment['proxy_port']}"
            f"?security=reality&type=tcp&flow=xtls-rprx-vision#{tag}"
        )

    def _expires_ms(self, expires_at: str) -> int:
        if not expires_at:
            return 0
        parsed = date.fromisoformat(expires_at)
        dt = datetime.combine(parsed, datetime_time.min, tzinfo=timezone.utc)
        return int(dt.timestamp() * 1000)

    def get_client(self, client_id: str) -> dict[str, Any]:
        rows = [row for row in self.list_clients() if row["id"] == client_id]
        if not rows:
            raise ValueError("client not found")
        return rows[0]

    def update_client(self, client_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        client = self.get_client(client_id)
        deployment = self.get_deployment(client["deployment_id"])
        name = str(payload.get("name", client["name"])).strip()
        if not name:
            raise ValueError("name is required")
        quota_gb = float(payload.get("quotaGb", client["quota_bytes"] / 1024 / 1024 / 1024))
        if quota_gb < 0:
            raise ValueError("quotaGb must be zero or greater")
        quota_bytes = int(quota_gb * 1024 * 1024 * 1024)
        expires_at = str(payload.get("expiresAt", client["expires_at"]))
        enabled = 1 if bool(payload.get("enabled", client["enabled"])) else 0
        share_link = client["share_link"]
        if (
            deployment.get("install_method") == "native"
            and deployment.get("status") == "ready"
            and deployment.get("xui_inbound_id")
        ):
            xui = self._xui_client(deployment)
            xui.wait_ready(seconds=30)
            xui.login()
            remote = xui.get_client(client["name"])
            remote_client = remote.get("client") if isinstance(remote.get("client"), dict) else remote
            if not isinstance(remote_client, dict):
                raise ValueError("3x-ui client payload is invalid")
            updated_remote = dict(remote_client)
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
            updated_remote["enable"] = bool(enabled)
            xui.update_client(client["name"], updated_remote)
            try:
                links = xui.client_links(name)
                if links:
                    share_link = links[0]
            except Exception:  # noqa: BLE001
                pass
            try:
                xui.restart_xray()
            except Exception:  # noqa: BLE001
                pass
        else:
            share_link = self._default_share_link(deployment, client["uuid"], name)
        stamp = now_iso()
        self.db.execute(
            """
            UPDATE clients
            SET name = ?, quota_bytes = ?, expires_at = ?, enabled = ?, share_link = ?, updated_at = ?
            WHERE id = ?
            """,
            (name, quota_bytes, expires_at, enabled, share_link, stamp, client_id),
        )
        return self.get_client(client_id)

    def reset_client(self, client_id: str) -> dict[str, Any]:
        self.get_client(client_id)
        self.db.execute(
            "UPDATE clients SET used_bytes = 0, updated_at = ? WHERE id = ?",
            (now_iso(), client_id),
        )
        return self.get_client(client_id)

    def delete_deployment(self, deployment_id: str) -> dict[str, Any]:
        deployment = self.get_deployment(deployment_id)
        chain_logs = self._cleanup_proxy_chains_for_deployments([deployment_id])
        other_native = self.db.query_one(
            """
            SELECT COUNT(*) AS count
            FROM deployments
            WHERE server_id = ? AND id <> ? AND install_method = 'native'
            """,
            (deployment["server_id"], deployment_id),
        )["count"]
        remote_logs = self._cleanup_remote_deployment(
            deployment,
            uninstall_panel=deployment.get("install_method") == "native" and other_native == 0,
        )
        self._delete_deployment_records(deployment_id)
        return {
            "deleted": deployment_id,
            "remoteLogs": (chain_logs + remote_logs)[-20:],
        }

    def delete_server(self, server_id: str) -> dict[str, Any]:
        server = self._get_server_row(server_id)
        deployments = self.db.query_all(
            "SELECT id, install_method FROM deployments WHERE server_id = ?",
            (server_id,),
        )
        chain_logs = self._cleanup_proxy_chains_for_deployments(
            [deployment["id"] for deployment in deployments]
        )
        remote_logs: list[str] = []
        if any(row["install_method"] == "native" for row in deployments):
            remote_logs = self._uninstall_remote_xui(server)
        for deployment in deployments:
            self._delete_default_subscription(deployment["id"])
        self.db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        return {
            "deleted": server_id,
            "remoteLogs": (chain_logs + remote_logs)[-20:],
        }

    def _delete_deployment_records(self, deployment_id: str) -> None:
        self._delete_default_subscription(deployment_id)
        self.db.execute("DELETE FROM deployments WHERE id = ?", (deployment_id,))

    def _delete_default_subscription(self, deployment_id: str) -> None:
        self.db.execute(
            "DELETE FROM subscriptions WHERE id = ? OR token = ?",
            (f"sub_{deployment_id}", deployment_id),
        )

    def _cleanup_remote_deployment(
        self,
        deployment: dict[str, Any],
        uninstall_panel: bool,
    ) -> list[str]:
        if deployment.get("install_method") != "native":
            return []
        server = self._get_server_row(deployment["server_id"])
        if uninstall_panel:
            return self._uninstall_remote_xui(server)
        if not deployment.get("xui_inbound_id"):
            return []

        logs = [f"Deleting 3x-ui inbound id={deployment['xui_inbound_id']}"]
        xui = self._xui_client(deployment)
        xui.wait_ready(seconds=20)
        xui.login()
        xui.delete_inbound(int(deployment["xui_inbound_id"]))
        logs.append("Deleted 3x-ui inbound")
        try:
            xui.restart_xray()
            logs.append("Requested Xray restart")
        except Exception as exc:  # noqa: BLE001
            logs.append(f"Xray restart request failed: {exc}")
        return logs

    def _uninstall_remote_xui(self, server: dict[str, Any]) -> list[str]:
        return self.ssh.run_script(
            server,
            self._xui_uninstall_script(),
            lambda _: None,
            timeout=240,
        )

    def _xui_uninstall_script(self) -> str:
        return r"""
set -u
echo "Stopping 3x-ui service"
if command -v systemctl >/dev/null 2>&1; then
  systemctl stop x-ui 2>/dev/null || true
  systemctl disable x-ui 2>/dev/null || true
fi

echo "Running 3x-ui uninstall command when available"
if command -v x-ui >/dev/null 2>&1; then
  printf 'y\n' | x-ui uninstall 2>/dev/null || true
fi

echo "Removing remaining 3x-ui files"
rm -f /etc/systemd/system/x-ui.service
rm -f /etc/systemd/system/multi-user.target.wants/x-ui.service
rm -f /usr/bin/x-ui /usr/local/bin/x-ui
rm -rf /usr/local/x-ui /etc/x-ui /var/log/x-ui
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload 2>/dev/null || true
  systemctl reset-failed x-ui 2>/dev/null || true
fi
echo "3x-ui cleanup completed"
"""

    def list_subscriptions(self) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            """
            SELECT s.id, s.name, s.token, s.created_at, s.updated_at,
                   COUNT(se.node_client_id) AS node_count,
                   COALESCE(SUM(se.quota_bytes), 0) AS quota_bytes
            FROM subscriptions s
            LEFT JOIN subscription_entries se ON se.subscription_id = s.id
            GROUP BY s.id
            ORDER BY s.created_at DESC
            """
        )
        for row in rows:
            row["subscription_url"] = self._subscription_url(row["token"])
        return rows

    def create_subscription(self, payload: dict[str, Any]) -> dict[str, Any]:
        stamp = now_iso()
        subscription_id = new_id("sub")
        name = str(payload.get("name", "")).strip() or "新订阅"
        token = secrets.token_urlsafe(14)
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
        row = self.db.query_one(
            """
            SELECT s.id, s.name, s.token, s.created_at, s.updated_at,
                   COUNT(se.node_client_id) AS node_count,
                   COALESCE(SUM(se.quota_bytes), 0) AS quota_bytes
            FROM subscriptions s
            LEFT JOIN subscription_entries se ON se.subscription_id = s.id
            WHERE s.id = ?
            GROUP BY s.id
            """,
            (subscription_id,),
        )
        if not row:
            raise ValueError("subscription not found")
        row["subscription_url"] = self._subscription_url(row["token"])
        return row

    def get_managed_subscription_config(self, subscription_id: str) -> dict[str, Any]:
        subscription = self.get_subscription(subscription_id)
        selected = self.db.query_all(
            """
            SELECT node_client_id, quota_bytes
            FROM subscription_entries
            WHERE subscription_id = ?
            ORDER BY created_at ASC
            """,
            (subscription_id,),
        )
        return {
            "subscription": subscription,
            "availableNodes": self.list_clients(),
            "selectedNodes": [
                {
                    "nodeClientId": row["node_client_id"],
                    "quotaBytes": row["quota_bytes"],
                }
                for row in selected
            ],
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

        clients = {client["id"]: client for client in self.list_clients()}
        selected: list[tuple[str, int]] = []
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
            selected.append((node_id, quota_bytes))
            seen.add(node_id)

        for node_id, quota_bytes in selected:
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
                subscription_id, node_client_id, quota_bytes, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?)
            """,
            [
                (subscription_id, node_id, quota_bytes, stamp, stamp)
                for node_id, quota_bytes in selected
            ],
        )
        return self.get_managed_subscription_config(subscription_id)

    def delete_subscription(self, subscription_id: str) -> dict[str, str]:
        self.get_subscription(subscription_id)
        self.db.execute("DELETE FROM subscriptions WHERE id = ?", (subscription_id,))
        return {"deleted": subscription_id}

    def render_managed_subscription(self, token: str) -> str:
        subscription = self.db.query_one(
            "SELECT id FROM subscriptions WHERE token = ?",
            (token,),
        )
        if not subscription:
            raise ValueError("subscription not found")
        rows = self.db.query_all(
            """
            SELECT c.share_link
            FROM subscription_entries se
            JOIN clients c ON c.id = se.node_client_id
            WHERE se.subscription_id = ? AND c.enabled = 1
            ORDER BY se.created_at ASC, c.created_at ASC
            """,
            (subscription["id"],),
        )
        raw = "\n".join(row["share_link"] for row in rows if row.get("share_link"))
        return base64.b64encode(raw.encode("utf-8")).decode("ascii")

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
        self.db.execute("DELETE FROM subscription_nodes WHERE subscription_id = ?", (deployment_id,))
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
            SET subscription_configured = 1, updated_at = ?
            WHERE id = ?
            """,
            (stamp, deployment_id),
        )
        return self.get_subscription_config(deployment_id)

    def render_deployment_subscription(self, deployment_id: str) -> str:
        self.get_deployment(deployment_id)
        rows = self.db.query_all(
            """
            SELECT c.share_link
            FROM subscription_nodes sn
            JOIN clients c ON c.id = sn.node_client_id
            WHERE sn.subscription_id = ? AND c.enabled = 1
            ORDER BY sn.created_at ASC, c.created_at ASC
            """,
            (deployment_id,),
        )
        raw = "\n".join(row["share_link"] for row in rows if row.get("share_link"))
        return base64.b64encode(raw.encode("utf-8")).decode("ascii")

    def get_job(self, job_id: str) -> dict[str, Any]:
        row = self.db.query_one("SELECT * FROM jobs WHERE id = ?", (job_id,))
        if not row:
            raise ValueError("job not found")
        row["logs"] = json.loads(row["logs"])
        return row
