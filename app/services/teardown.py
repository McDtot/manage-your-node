import json
import random
import secrets
import threading
from collections.abc import Callable
from typing import Any

from ..provisioning import native_3xui_script
from .helpers import (
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
    DEPLOYMENT_PROTOCOL_VLESS_REALITY,
    DEPLOYMENT_PROTOCOLS,
    DEPLOYMENT_SS_METHOD,
    _redact_native_install_log,
    host_field,
    new_id,
    new_ss2022_password,
    now_iso,
    parse_reality_destination,
    port_field,
    require_text,
)
from .subscriptions import SubscriptionsService


class TeardownService(SubscriptionsService):
    def start_deployment(self, server_id: str, payload: dict[str, Any]) -> dict[str, Any]:
        server = self.db.query_one("SELECT * FROM servers WHERE id = ?", (server_id,))
        if not server:
            raise ValueError("server not found")

        deployment_id = new_id("dep")
        job_id = new_id("job")
        stamp = now_iso()
        proxy_port = port_field(payload, "proxyPort", 443)
        panel_port = port_field(payload, "panelPort", random.randint(32000, 39000))
        if proxy_port == panel_port:
            raise ValueError("proxyPort and panelPort must be different")
        protocol = str(payload.get("protocol", DEPLOYMENT_PROTOCOL_VLESS_REALITY)).strip()
        if protocol not in DEPLOYMENT_PROTOCOLS:
            raise ValueError("only VLESS + REALITY and Shadowsocks 2022 are supported")
        install_method = str(payload.get("installMethod", "native")).strip() or "native"
        if install_method != "native":
            raise ValueError("only native deployments are supported")
        is_shadowsocks = protocol == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022
        if is_shadowsocks:
            reality_mode = "manual"
            selected_reality_dest, selected_reality_sni = "", ""
            ss_password = new_ss2022_password()
        else:
            ss_password = ""
            reality_mode = str(payload.get("realityMode", "auto")).strip().lower()
            if reality_mode not in {"auto", "manual"}:
                raise ValueError("realityMode must be auto or manual")
            if reality_mode == "manual":
                selected_reality_dest, target_host = parse_reality_destination(
                    require_text(payload, "realityDest")
                )
                selected_reality_sni = str(payload.get("realitySni", "")).strip()
                selected_reality_sni = host_field(
                    {"realitySni": selected_reality_sni or target_host},
                    "realitySni",
                )
            else:
                selected_reality_dest, selected_reality_sni = "", ""
        if server["status"] != "reachable":
            raise ValueError("test SSH successfully before starting a native deployment")
        host_key = self.db.query_one(
            "SELECT trusted FROM ssh_host_keys WHERE server_id = ?",
            (server_id,),
        )
        if not host_key or not bool(host_key["trusted"]):
            raise ValueError("verify and approve the SSH host key before native deployment")
        existing = self.db.query_one(
            "SELECT id FROM deployments WHERE server_id = ? AND install_method = 'native'",
            (server_id,),
        )
        if existing:
            raise ValueError("this server already has a native 3x-ui deployment")
        panel_path = "/" + secrets.token_urlsafe(8)
        panel_username = "myn_" + secrets.token_urlsafe(5).replace("-", "A").replace("_", "B")
        panel_password = secrets.token_urlsafe(18).replace("-", "A").replace("_", "B")
        api_token = ""
        with self.db.transaction():
            self._acquire_operation_locks(job_id, [("server", server_id)])
            self.db.execute(
                """
                INSERT INTO deployments (
                    id, server_id, engine, protocol, install_method, panel_scheme, panel_port, panel_path,
                    panel_username, encrypted_panel_password, encrypted_api_token,
                    proxy_port, reality_mode, reality_dest, reality_sni,
                    ss_method, encrypted_ss_password,
                    subscription_configured, status, subscription_url, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    reality_mode,
                    selected_reality_dest,
                    selected_reality_sni,
                    DEPLOYMENT_SS_METHOD,
                    self.secret_box.seal(ss_password),
                    0,
                    "provisioning",
                    "",
                    stamp,
                    stamp,
                ),
            )
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
            args=(job_id, deployment_id, server),
            daemon=True,
        )
        self._track_worker(thread)
        try:
            thread.start()
        except Exception:
            with self._workers_lock:
                self._workers.discard(thread)
            with self.db.transaction():
                self._release_operation_locks(job_id)
                self._finish_job(job_id, "failed", "could not start deployment worker")
                self.db.execute(
                    "UPDATE deployments SET status = 'failed', last_error = ?, updated_at = ? WHERE id = ?",
                    ("Could not start deployment worker.", now_iso(), deployment_id),
                )
            raise

        return {
            "job": self.get_job(job_id),
            "deployment": self.get_deployment(deployment_id, reveal_secrets=False),
        }

    def _run_deployment(
        self,
        job_id: str,
        deployment_id: str,
        server: dict[str, Any],
    ) -> None:
        try:
            self._run_native_deployment(job_id, deployment_id, server)
        finally:
            self._release_operation_locks(job_id)
            self._forget_current_worker()

    def _run_native_deployment(
        self,
        job_id: str,
        deployment_id: str,
        server: dict[str, Any],
    ) -> None:
        install_applied = False
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
            def safe_remote_log(line: str) -> None:
                self._append_job_log(
                    job_id,
                    _redact_native_install_log(line, panel_password),
                )

            self._append_job_log(job_id, "Starting real SSH deployment with official 3x-ui installer")
            lines = self.ssh.run_script(
                server,
                script,
                safe_remote_log,
                timeout=1200,
            )
            result = self._parse_install_result(lines)
            if result:
                self._apply_install_result(deployment_id, result)
                install_applied = True
            deployment = self.get_deployment(deployment_id)
            is_shadowsocks = deployment.get("protocol") == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022
            if not is_shadowsocks:
                selected_reality_dest, selected_reality_sni = self._resolve_reality_target(
                    job_id,
                    deployment_id,
                    server,
                    deployment,
                )
                deployment = self.get_deployment(deployment_id)
            self._append_job_log(job_id, "Waiting for 3x-ui API to become ready over SSH tunnel")
            with self._xui_session(deployment) as xui:
                xui.wait_ready()
                xui.login()
                if is_shadowsocks:
                    self._append_job_log(
                        job_id, "Creating default Shadowsocks 2022 inbound through 3x-ui API"
                    )
                    inbound = xui.create_shadowsocks_inbound(
                        port=deployment["proxy_port"],
                        remark=f"myn-{server['name']}-{deployment['proxy_port']}",
                        method=deployment.get("ss_method") or DEPLOYMENT_SS_METHOD,
                        server_password=deployment.get("ss_password") or "",
                    )
                else:
                    self._append_job_log(job_id, "Creating default VLESS + REALITY inbound through 3x-ui API")
                    inbound = xui.create_vless_reality_inbound(
                        port=deployment["proxy_port"],
                        remark=f"myn-{server['name']}-{deployment['proxy_port']}",
                        target=selected_reality_dest,
                        server_names=[selected_reality_sni],
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

            try:
                with self._xui_session(self.get_deployment(deployment_id)) as xui:
                    xui.login()
                    xui.restart_xray()
                self._append_job_log(job_id, "Requested Xray restart")
            except Exception as exc:  # noqa: BLE001
                self._append_job_log(job_id, f"Xray restart request failed, panel may restart it soon: {exc}")

            self._finish_job(job_id, "success", None)
        except Exception as exc:  # noqa: BLE001
            error_text = _redact_native_install_log(
                str(exc),
                panel_password if "panel_password" in locals() else "",
            )
            self.db.execute(
                "UPDATE deployments SET status = ?, last_error = ?, updated_at = ? "
                "WHERE id = ?",
                ("failed", error_text, now_iso(), deployment_id),
            )
            self._append_job_log(job_id, f"Deployment failed: {error_text}")
            if install_applied:
                self._append_job_log(
                    job_id,
                    "Rolling back: uninstalling partial 3x-ui install on the target host",
                )
                try:
                    for line in self._uninstall_remote_xui(server):
                        if line:
                            self._append_job_log(job_id, line)
                except Exception as cleanup_exc:  # noqa: BLE001
                    self._append_job_log(
                        job_id,
                        f"Rollback uninstall failed (manual cleanup may be needed): {cleanup_exc}",
                    )
            self._finish_job(job_id, "failed", error_text)

    def delete_deployment(self, deployment_id: str) -> dict[str, Any]:
        deployment = self.get_deployment(deployment_id)
        self._assert_not_busy("server", deployment["server_id"])
        chain_logs = self._cleanup_proxy_chains_for_deployments([deployment_id])
        other_native = self.db.query_row(
            """
            SELECT COUNT(*) AS count
            FROM deployments
            WHERE server_id = ? AND id <> ? AND install_method = 'native'
            """,
            (deployment["server_id"], deployment_id),
        )["count"]
        remote_logs, remote_cleanup_ok = self._best_effort_remote_cleanup(
            lambda: self._cleanup_remote_deployment(
                deployment,
                uninstall_panel=(
                    deployment.get("install_method") == "native" and other_native == 0
                ),
            )
        )
        self._delete_deployment_records(deployment_id)
        return {
            "deleted": deployment_id,
            "remoteCleanupOk": remote_cleanup_ok,
            "remoteLogs": (chain_logs + remote_logs)[-20:],
        }

    def delete_server(self, server_id: str) -> dict[str, Any]:
        self._assert_not_busy("server", server_id)
        server = self._get_server_row(server_id)
        deployments = self.db.query_all(
            "SELECT id, install_method FROM deployments WHERE server_id = ?",
            (server_id,),
        )
        chain_logs = self._cleanup_proxy_chains_for_deployments(
            [deployment["id"] for deployment in deployments]
        )
        remote_logs: list[str] = []
        remote_cleanup_ok = True
        if any(row["install_method"] == "native" for row in deployments):
            remote_logs, remote_cleanup_ok = self._best_effort_remote_cleanup(
                lambda: self._uninstall_remote_xui(server)
            )
        with self.db.transaction():
            for deployment in deployments:
                self._delete_default_subscription(deployment["id"])
            self.db.execute("DELETE FROM servers WHERE id = ?", (server_id,))
        return {
            "deleted": server_id,
            "remoteCleanupOk": remote_cleanup_ok,
            "remoteLogs": (chain_logs + remote_logs)[-20:],
        }

    def _best_effort_remote_cleanup(
        self,
        cleanup: Callable[[], list[str]],
    ) -> tuple[list[str], bool]:
        """Run remote cleanup without blocking local record deletion."""
        try:
            logs = cleanup()
            return list(logs or []), True
        except Exception as exc:  # noqa: BLE001
            return (
                [f"Remote cleanup failed (local record deleted anyway): {exc}"],
                False,
            )

    def _delete_deployment_records(self, deployment_id: str) -> None:
        with self.db.transaction():
            self._delete_default_subscription(deployment_id)
            self.db.execute("DELETE FROM deployments WHERE id = ?", (deployment_id,))

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
        with self._xui_session(deployment) as xui:
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
