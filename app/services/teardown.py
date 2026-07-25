import json
import threading
from collections.abc import Callable
from typing import Any

from ..provisioning import (
    node_service_name,
    singbox_install_script,
    singbox_uninstall_script,
)
from .helpers import (
    DEPLOYMENT_PROTOCOL_ANYTLS,
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
    DEPLOYMENT_PROTOCOL_VLESS_REALITY,
    DEPLOYMENT_PROTOCOLS,
    DEPLOYMENT_SS_METHOD,
    host_field,
    new_id,
    new_ss2022_password,
    now_iso,
    parse_reality_destination,
    port_field,
    require_text,
)
from .singbox import new_reality_keypair, new_short_id
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
        protocol = str(payload.get("protocol", DEPLOYMENT_PROTOCOL_VLESS_REALITY)).strip()
        if protocol not in DEPLOYMENT_PROTOCOLS:
            raise ValueError(
                "only VLESS + REALITY, Shadowsocks 2022 and AnyTLS are supported"
            )
        install_method = str(payload.get("installMethod", "native")).strip() or "native"
        if install_method != "native":
            raise ValueError("only native deployments are supported")
        is_shadowsocks = protocol == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022
        is_anytls = protocol == DEPLOYMENT_PROTOCOL_ANYTLS
        anytls_domain = ""
        ss_password = ""
        reality_private_key, reality_public_key, reality_short_id = "", "", ""
        if is_anytls:
            reality_mode = "manual"
            selected_reality_dest, selected_reality_sni = "", ""
            raw_domain = str(payload.get("anytlsDomain", "")).strip()
            if raw_domain:
                anytls_domain = host_field({"anytlsDomain": raw_domain}, "anytlsDomain")
        elif is_shadowsocks:
            reality_mode = "manual"
            selected_reality_dest, selected_reality_sni = "", ""
            ss_password = new_ss2022_password()
        else:
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
            reality_private_key, reality_public_key = new_reality_keypair()
            reality_short_id = new_short_id()
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
            raise ValueError("this server already has a native deployment")
        with self.db.transaction():
            self._acquire_operation_locks(job_id, [("server", server_id)])
            self.db.execute(
                """
                INSERT INTO deployments (
                    id, server_id, engine, protocol, install_method, proxy_port,
                    reality_mode, reality_dest, reality_sni,
                    encrypted_reality_private_key, reality_public_key, reality_short_id,
                    ss_method, encrypted_ss_password, anytls_domain,
                    subscription_configured, status, subscription_url,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    deployment_id,
                    server_id,
                    "sing-box",
                    protocol,
                    install_method,
                    proxy_port,
                    reality_mode,
                    selected_reality_dest,
                    selected_reality_sni,
                    self.secret_box.seal(reality_private_key),
                    reality_public_key,
                    reality_short_id,
                    DEPLOYMENT_SS_METHOD,
                    self.secret_box.seal(ss_password),
                    anytls_domain,
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
                    "deploy_node",
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
        service_name = node_service_name(deployment_id)
        install_started = False
        try:
            deployment = self.get_deployment(deployment_id)
            if deployment.get("protocol") == DEPLOYMENT_PROTOCOL_VLESS_REALITY:
                self._resolve_reality_target(job_id, deployment_id, server, deployment)
                deployment = self.get_deployment(deployment_id)
            config = self._render_node_config(deployment)
            self._append_job_log(
                job_id,
                f"Installing pinned sing-box and starting {service_name} over SSH",
            )
            install_started = True
            self.ssh.run_script(
                server,
                singbox_install_script(
                    service_name=service_name,
                    config=config,
                    proxy_port=int(deployment["proxy_port"]),
                    server_host=server["host"],
                    **self._node_install_options(deployment),
                ),
                lambda line: self._append_job_log(job_id, line),
                timeout=1200,
            )
            self.db.execute(
                """
                UPDATE deployments
                SET status = ?, last_config_hash = ?, updated_at = ?
                WHERE id = ?
                """,
                ("ready", self._config_hash(config), now_iso(), deployment_id),
            )
            self._append_job_log(job_id, self._ready_message(deployment))
            self._finish_job(job_id, "success", None)
        except Exception as exc:  # noqa: BLE001
            error_text = str(exc)
            self.db.execute(
                "UPDATE deployments SET status = ?, last_error = ?, updated_at = ? WHERE id = ?",
                ("failed", error_text, now_iso(), deployment_id),
            )
            self._append_job_log(job_id, f"Deployment failed: {error_text}")
            if install_started:
                self._append_job_log(
                    job_id,
                    "Rolling back: removing any partial sing-box service",
                )
                try:
                    for line in self.ssh.run_script(
                        server,
                        singbox_uninstall_script(service_name),
                        lambda _: None,
                        timeout=120,
                    ):
                        if line:
                            self._append_job_log(job_id, line)
                except Exception as cleanup_exc:  # noqa: BLE001
                    self._append_job_log(
                        job_id,
                        f"Rollback uninstall failed (manual cleanup may be needed): {cleanup_exc}",
                    )
            self._finish_job(job_id, "failed", error_text)
        finally:
            self._release_operation_locks(job_id)
            self._forget_current_worker()

    def _ready_message(self, deployment: dict[str, Any]) -> str:
        protocol = deployment.get("protocol")
        if protocol != DEPLOYMENT_PROTOCOL_ANYTLS:
            return f"sing-box {protocol} inbound is installed and ready"
        certificate = (
            "Let's Encrypt certificate"
            if str(deployment.get("anytls_domain") or "").strip()
            else "self-signed certificate"
        )
        return f"sing-box AnyTLS inbound is installed and ready ({certificate})"

    def delete_deployment(self, deployment_id: str) -> dict[str, Any]:
        deployment = self.get_deployment(deployment_id)
        self._assert_not_busy("server", deployment["server_id"])
        chain_logs = self._cleanup_proxy_chains_for_deployments([deployment_id])
        remote_logs, remote_cleanup_ok = self._best_effort_remote_cleanup(
            lambda: self._cleanup_remote_deployment(deployment)
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
        native = [row for row in deployments if row["install_method"] == "native"]
        if native:
            remote_logs, remote_cleanup_ok = self._best_effort_remote_cleanup(
                lambda: self._uninstall_server_deployments(server, native)
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

    def _cleanup_remote_deployment(self, deployment: dict[str, Any]) -> list[str]:
        if deployment.get("install_method") != "native":
            return []
        server = self._get_server_row(deployment["server_id"])
        return self.ssh.run_script(
            server,
            singbox_uninstall_script(node_service_name(deployment["id"])),
            lambda _: None,
            timeout=120,
        )

    def _uninstall_server_deployments(
        self,
        server: dict[str, Any],
        native_deployments: list[dict[str, Any]],
    ) -> list[str]:
        """Remove every sing-box node service installed on a server."""
        logs: list[str] = []
        for deployment in native_deployments:
            logs.extend(
                self.ssh.run_script(
                    server,
                    singbox_uninstall_script(node_service_name(deployment["id"])),
                    lambda _: None,
                    timeout=120,
                )
            )
        return logs
