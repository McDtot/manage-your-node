import json
import secrets
import threading
import uuid
from typing import Any

from ..provisioning import (
    chain_service_name,
    singbox_install_script,
    singbox_uninstall_script,
)
from .clients import ClientsService
from .helpers import (
    CHAIN_PROTOCOL_HYSTERIA2,
    CHAIN_PROTOCOL_SHADOWSOCKS_2022,
    CHAIN_PROTOCOL_VLESS_REALITY,
    CHAIN_PROTOCOL_VMESS,
    CHAIN_PROTOCOLS,
    CHAIN_SS_METHOD,
    _deployment_reality_settings,
    _render_subscription_links,
    new_hy2_password,
    new_id,
    new_ss2022_password,
    now_iso,
    vless_reality_share_link,
)
from .singbox import build_chain_config, new_reality_keypair, new_short_id


class ChainsService(ClientsService):
    def _query_proxy_chains(self, chain_id: str | None = None) -> list[dict[str, Any]]:
        where = "WHERE pc.id = ?" if chain_id else ""
        params = (chain_id,) if chain_id else ()
        rows = self.db.query_all(
            f"""
            SELECT pc.id, pc.name, pc.token, pc.client_uuid,
                   pc.status AS chain_status, pc.share_link, pc.last_error,
                   pc.created_at AS chain_created_at, pc.updated_at AS chain_updated_at,
                   pcn.position, d.id AS deployment_id, s.name AS server_name,
                   s.host, d.protocol, d.proxy_port, d.status AS deployment_status,
                   pcn.inbound_protocol, pcn.inbound_port, pcn.client_uuid AS node_client_uuid,
                   pcn.public_key, pcn.ss_method, pcn.short_id,
                   pcn.remote_service_name, pcn.status AS node_status
            FROM proxy_chains pc
            LEFT JOIN proxy_chain_nodes pcn ON pcn.chain_id = pc.id
            LEFT JOIN deployments d ON d.id = pcn.deployment_id
            LEFT JOIN servers s ON s.id = d.server_id
            {where}
            ORDER BY pc.created_at DESC, pc.id ASC, pcn.position ASC
            """,
            params,
        )

        chains: dict[str, dict[str, Any]] = {}
        for record in rows:
            current = chains.get(record["id"])
            if current is None:
                current = {
                    "id": record["id"],
                    "name": record["name"],
                    "token": record["token"],
                    "client_uuid": record["client_uuid"],
                    "status": record["chain_status"],
                    "share_link": record["share_link"],
                    "last_error": record["last_error"],
                    "created_at": record["chain_created_at"],
                    "updated_at": record["chain_updated_at"],
                    "nodes": [],
                }
                chains[record["id"]] = current
            if record["deployment_id"] is not None:
                current["nodes"].append(
                    {
                        "position": record["position"],
                        "deployment_id": record["deployment_id"],
                        "server_name": record["server_name"],
                        "host": record["host"],
                        "protocol": record["protocol"],
                        "proxy_port": record["proxy_port"],
                        "status": record["deployment_status"],
                        "inbound_protocol": record["inbound_protocol"],
                        "inbound_port": record["inbound_port"],
                        "client_uuid": record["node_client_uuid"],
                        "public_key": record["public_key"],
                        "ss_method": record["ss_method"],
                        "short_id": record["short_id"],
                        "remote_service_name": record["remote_service_name"],
                        "node_status": record["node_status"],
                    }
                )

        for chain in chains.values():
            nodes = chain["nodes"]
            chain["path"] = " -> ".join(node["server_name"] for node in nodes)
            chain["hops"] = [
                {
                    "fromDeploymentId": nodes[index - 1]["deployment_id"],
                    "fromServerName": nodes[index - 1]["server_name"],
                    "toDeploymentId": node["deployment_id"],
                    "toServerName": node["server_name"],
                    "protocol": node["inbound_protocol"],
                }
                for index, node in enumerate(nodes)
                if index > 0
            ]
            chain["entry_server_name"] = nodes[0]["server_name"] if nodes else ""
            chain["exit_server_name"] = nodes[-1]["server_name"] if nodes else ""
            chain["subscription_url"] = self._chain_subscription_url(chain["token"])
        return list(chains.values())

    def list_proxy_chains(self) -> list[dict[str, Any]]:
        return self._query_proxy_chains()

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

        raw_inbound_ports = payload.get("inboundPorts")
        if not isinstance(raw_inbound_ports, list) or len(raw_inbound_ports) != len(ordered_ids):
            raise ValueError("inboundPorts must contain one port per proxy-chain node")
        inbound_ports: list[int] = []
        for index, raw_port in enumerate(raw_inbound_ports):
            if isinstance(raw_port, bool) or (isinstance(raw_port, float) and not raw_port.is_integer()):
                raise ValueError(f"inboundPorts[{index}] must be a whole number")
            try:
                inbound_port = int(raw_port)
            except (TypeError, ValueError) as exc:
                raise ValueError(f"inboundPorts[{index}] must be a whole number") from exc
            if not 1 <= inbound_port <= 65535:
                raise ValueError(f"inboundPorts[{index}] must be between 1 and 65535")
            inbound_ports.append(inbound_port)

        raw_link_protocols = payload.get("linkProtocols")
        if raw_link_protocols is None:
            # Preserve the previous all-Reality API behavior for older clients.
            link_protocols = [CHAIN_PROTOCOL_VLESS_REALITY] * (len(ordered_ids) - 1)
        else:
            if not isinstance(raw_link_protocols, list):
                raise ValueError("linkProtocols must be a list")
            if len(raw_link_protocols) != len(ordered_ids) - 1:
                raise ValueError("linkProtocols must contain one protocol per server-to-server hop")
            link_protocols = [str(protocol).strip() for protocol in raw_link_protocols]
            if any(protocol not in CHAIN_PROTOCOLS for protocol in link_protocols):
                supported = ", ".join(sorted(CHAIN_PROTOCOLS))
                raise ValueError(f"unsupported chain protocol; choose one of: {supported}")

        inbound_protocols = [CHAIN_PROTOCOL_VLESS_REALITY, *link_protocols]

        deployments = self._chain_deployments_by_id(ordered_ids)
        missing = [deployment_id for deployment_id in ordered_ids if deployment_id not in deployments]
        if missing:
            raise ValueError("selected deployment not found")
        unavailable = [
            deployments[deployment_id]["server_name"]
            for deployment_id in ordered_ids
            if deployments[deployment_id]["install_method"] != "native"
            or deployments[deployment_id]["status"] != "ready"
        ]
        if unavailable:
            raise ValueError(
                f"deployment is not a ready native deployment: {', '.join(unavailable)}"
            )
        name = str(payload.get("name", "")).strip()
        if not name:
            name = " -> ".join(deployments[deployment_id]["server_name"] for deployment_id in ordered_ids)

        chain_id = new_id("chn")
        token = secrets.token_urlsafe(24)
        client_uuid = str(uuid.uuid4())
        stamp = now_iso()
        with self.db.transaction():
            self._assert_proxy_chain_ports_available(ordered_ids, inbound_ports, deployments)
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
                    chain_id, deployment_id, position, inbound_protocol, inbound_port,
                    ss_method, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        chain_id,
                        deployment_id,
                        index,
                        inbound_protocols[index],
                        inbound_ports[index],
                        CHAIN_SS_METHOD,
                        stamp,
                    )
                    for index, deployment_id in enumerate(ordered_ids)
                ],
            )
        return self.get_proxy_chain(chain_id)

    def _assert_proxy_chain_ports_available(
        self,
        deployment_ids: list[str],
        inbound_ports: list[int],
        deployments: dict[str, dict[str, Any]],
    ) -> None:
        selected_endpoints: dict[tuple[str, int], str] = {}
        for deployment_id, inbound_port in zip(deployment_ids, inbound_ports, strict=True):
            deployment = deployments[deployment_id]
            server_name = deployment["server_name"]
            reserved_local_ports = {
                "SSH": int(deployment["ssh_port"]),
                "proxy": int(deployment["proxy_port"]),
            }
            for purpose, reserved_port in reserved_local_ports.items():
                if inbound_port == reserved_port:
                    raise ValueError(
                        f"chain port {inbound_port} on {server_name} conflicts with its {purpose} port"
                    )

            endpoint = (deployment["host"], inbound_port)
            previous_server = selected_endpoints.get(endpoint)
            if previous_server:
                raise ValueError(
                    f"chain endpoint {endpoint[0]}:{endpoint[1]} is selected for both "
                    f"{previous_server} and {server_name}"
                )
            selected_endpoints[endpoint] = server_name

        hosts = sorted({host for host, _ in selected_endpoints})
        placeholders = ",".join("?" for _ in hosts)
        ssh_endpoints = {
            (row["host"], int(row["ssh_port"])): row["name"]
            for row in self.db.query_all(
                f"SELECT name, host, ssh_port FROM servers WHERE host IN ({placeholders})",
                tuple(hosts),
            )
        }
        proxy_endpoints = {
            (row["host"], int(row["proxy_port"])): row["server_name"]
            for row in self.db.query_all(
                f"""
                SELECT s.name AS server_name, s.host, d.proxy_port
                FROM deployments d
                JOIN servers s ON s.id = d.server_id
                WHERE s.host IN ({placeholders})
                """,
                tuple(hosts),
            )
        }
        chain_endpoints = {
            (row["host"], int(row["inbound_port"])): row["chain_name"]
            for row in self.db.query_all(
                f"""
                SELECT pc.name AS chain_name, s.host, pcn.inbound_port
                FROM proxy_chain_nodes pcn
                JOIN proxy_chains pc ON pc.id = pcn.chain_id
                JOIN deployments d ON d.id = pcn.deployment_id
                JOIN servers s ON s.id = d.server_id
                WHERE s.host IN ({placeholders}) AND pcn.inbound_port IS NOT NULL
                """,
                tuple(hosts),
            )
        }
        for endpoint in selected_endpoints:
            if endpoint in ssh_endpoints:
                raise ValueError(
                    f"chain endpoint {endpoint[0]}:{endpoint[1]} conflicts with SSH on "
                    f"{ssh_endpoints[endpoint]}"
                )
            if endpoint in proxy_endpoints:
                raise ValueError(
                    f"chain endpoint {endpoint[0]}:{endpoint[1]} conflicts with the proxy on "
                    f"{proxy_endpoints[endpoint]}"
                )
            if endpoint in chain_endpoints:
                raise ValueError(
                    f"chain endpoint {endpoint[0]}:{endpoint[1]} is already reserved by proxy chain "
                    f"{chain_endpoints[endpoint]}"
                )

    def get_proxy_chain(self, chain_id: str) -> dict[str, Any]:
        rows = self._query_proxy_chains(chain_id)
        if not rows:
            raise ValueError("proxy chain not found")
        return rows[0]

    def delete_proxy_chain(self, chain_id: str) -> dict[str, Any]:
        self._assert_not_busy("chain", chain_id)
        logs = self._cleanup_proxy_chain_services(chain_id)
        self.db.execute("DELETE FROM proxy_chains WHERE id = ?", (chain_id,))
        return {"deleted": chain_id, "remoteLogs": logs[-20:]}

    def rotate_proxy_chain_token(self, chain_id: str) -> dict[str, Any]:
        self.get_proxy_chain(chain_id)
        self._assert_not_busy("chain", chain_id)
        self.db.execute(
            "UPDATE proxy_chains SET token = ?, updated_at = ? WHERE id = ?",
            (secrets.token_urlsafe(24), now_iso(), chain_id),
        )
        return self.get_proxy_chain(chain_id)

    def start_proxy_chain_deployment(self, chain_id: str) -> dict[str, Any]:
        self.get_proxy_chain(chain_id)
        nodes = self._proxy_chain_full_nodes(chain_id)
        job_id = new_id("job")
        stamp = now_iso()
        resources = [("chain", chain_id)] + [
            ("server", server_id)
            for server_id in dict.fromkeys(node["server_id"] for node in nodes)
        ]
        with self.db.transaction():
            self._acquire_operation_locks(job_id, resources)
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
        self._track_worker(thread)
        try:
            thread.start()
        except Exception:
            with self._workers_lock:
                self._workers.discard(thread)
            with self.db.transaction():
                self._release_operation_locks(job_id)
                self._finish_job(job_id, "failed", "could not start proxy-chain worker")
                self.db.execute(
                    "UPDATE proxy_chains SET status = 'failed', last_error = ?, updated_at = ? WHERE id = ?",
                    ("Could not start proxy-chain worker.", now_iso(), chain_id),
                )
            raise
        return {
            "job": self.get_job(job_id),
            "chain": self.get_proxy_chain(chain_id),
        }

    def _run_proxy_chain_deployment(self, job_id: str, chain_id: str) -> None:
        try:
            self._run_proxy_chain_deployment_locked(job_id, chain_id)
        finally:
            self._release_operation_locks(job_id)
            self._forget_current_worker()

    def _run_proxy_chain_deployment_locked(self, job_id: str, chain_id: str) -> None:
        try:
            chain = self.get_proxy_chain(chain_id)
            nodes = self._proxy_chain_full_nodes(chain_id)
            if len(nodes) < 2:
                raise ValueError("proxy chain requires at least two deployments")
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
            nodes = self._prepare_proxy_chain_nodes(job_id, chain_id, nodes)
            self._append_job_log(job_id, "Installing chain services from exit to entry")
            for index in range(len(nodes) - 1, -1, -1):
                node = nodes[index]
                next_node = nodes[index + 1] if index + 1 < len(nodes) else None
                config = build_chain_config(
                    self._chain_node_secrets(node),
                    self._chain_node_secrets(next_node) if next_node else None,
                )
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
            self._append_job_log(job_id, "Rolling back: removing any partial myn-chain services")
            for line in self._cleanup_proxy_chain_services(chain_id):
                self._append_job_log(job_id, line)
            self._finish_job(job_id, "failed", str(exc))

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
    ) -> list[dict[str, Any]]:
        prepared: list[dict[str, Any]] = []
        for node in nodes:
            update: dict[str, Any] = {}
            protocol = node.get("inbound_protocol") or CHAIN_PROTOCOL_VLESS_REALITY
            if protocol not in CHAIN_PROTOCOLS:
                raise ValueError(f"unsupported chain protocol on {node['server_name']}: {protocol}")
            if not node.get("inbound_port"):
                raise ValueError(
                    f"chain port is missing for {node['server_name']}; recreate the chain and choose "
                    "an allocated equal-mapping port for every node"
                )
            if protocol == CHAIN_PROTOCOL_VLESS_REALITY:
                if not node.get("node_client_uuid"):
                    update["client_uuid"] = str(uuid.uuid4())
                if not node.get("short_id"):
                    update["short_id"] = new_short_id()
                if not node.get("public_key") or not node.get("encrypted_private_key"):
                    self._append_job_log(
                        job_id,
                        f"Generating REALITY keypair for {node['server_name']}",
                    )
                    private_key, public_key = new_reality_keypair()
                    update["encrypted_private_key"] = self.secret_box.seal(private_key)
                    update["public_key"] = public_key
            elif protocol == CHAIN_PROTOCOL_SHADOWSOCKS_2022:
                if not node.get("encrypted_ss_password"):
                    update["encrypted_ss_password"] = self.secret_box.seal(
                        new_ss2022_password()
                    )
            elif protocol == CHAIN_PROTOCOL_HYSTERIA2:
                if not node.get("encrypted_hy2_password"):
                    update["encrypted_hy2_password"] = self.secret_box.seal(
                        new_hy2_password()
                    )
            elif protocol == CHAIN_PROTOCOL_VMESS:
                if not node.get("node_client_uuid"):
                    update["client_uuid"] = str(uuid.uuid4())
            if not node.get("remote_service_name"):
                update["remote_service_name"] = chain_service_name(
                    chain_id, node["position"]
                )

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

    def _chain_node_secrets(self, node: dict[str, Any]) -> dict[str, Any]:
        """Return the node row with its secrets decrypted for config rendering."""
        return {
            **node,
            "private_key": self.secret_box.open(node.get("encrypted_private_key") or ""),
            "ss_password": self.secret_box.open(node.get("encrypted_ss_password") or ""),
            "hy2_password": self.secret_box.open(node.get("encrypted_hy2_password") or ""),
        }

    def _install_proxy_chain_service(
        self,
        job_id: str,
        chain_id: str,
        node: dict[str, Any],
        config: dict[str, Any],
    ) -> None:
        service_name = node["remote_service_name"]
        protocol = node.get("inbound_protocol") or CHAIN_PROTOCOL_VLESS_REALITY
        self._append_job_log(
            job_id,
            f"Installing {service_name} on {node['server_name']}:{node['inbound_port']}",
        )
        self.ssh.run_script(
            node,
            singbox_install_script(
                service_name=service_name,
                config=config,
                proxy_port=int(node["inbound_port"]),
                server_host=node["host"],
                allow_udp=protocol
                in {CHAIN_PROTOCOL_SHADOWSOCKS_2022, CHAIN_PROTOCOL_HYSTERIA2},
                self_signed_cert=protocol == CHAIN_PROTOCOL_HYSTERIA2,
            ),
            lambda line: self._append_job_log(job_id, f"{node['server_name']}: {line}"),
            timeout=600,
        )

    def _chain_share_link(self, entry: dict[str, Any], name: str) -> str:
        if entry.get("inbound_protocol") != CHAIN_PROTOCOL_VLESS_REALITY:
            raise ValueError("proxy-chain entry must use VLESS + REALITY")
        return vless_reality_share_link(
            client_uuid=entry["node_client_uuid"],
            host=entry["host"],
            port=int(entry["inbound_port"]),
            name=name,
            public_key=entry["public_key"],
            short_id=entry["short_id"],
            sni=_deployment_reality_settings(entry)[1],
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
                    singbox_uninstall_script(service_name),
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

    def _proxy_chain_full_nodes(self, chain_id: str) -> list[dict[str, Any]]:
        return self.db.query_all(
            """
            SELECT pcn.position, pcn.inbound_protocol, pcn.inbound_port,
                   pcn.client_uuid AS node_client_uuid,
                   pcn.encrypted_private_key, pcn.public_key, pcn.short_id,
                   pcn.ss_method, pcn.encrypted_ss_password, pcn.encrypted_hy2_password,
                   pcn.remote_service_name, pcn.status AS node_status,
                   d.id AS deployment_id, d.install_method,
                   d.status AS deployment_status, d.protocol, d.proxy_port,
                   d.reality_mode, d.reality_dest, d.reality_sni,
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

    def render_proxy_chain_subscription(self, token: str, output_format: str = "base64") -> str:
        row = self.db.query_one(
            "SELECT share_link FROM proxy_chains WHERE token = ?",
            (token,),
        )
        if not row:
            raise ValueError("proxy chain not found")
        if not row["share_link"]:
            raise ValueError("proxy chain is not ready")
        return _render_subscription_links([row["share_link"]], output_format)

    def _proxy_chain_nodes(self, chain_id: str) -> list[dict[str, Any]]:
        return self.db.query_all(
            """
            SELECT pcn.position, d.id AS deployment_id, s.name AS server_name,
                   s.host, d.protocol, d.proxy_port, d.status,
                   pcn.inbound_protocol, pcn.inbound_port,
                   pcn.client_uuid, pcn.public_key, pcn.ss_method,
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
            SELECT d.id, d.server_id, s.name AS server_name, s.host, s.ssh_port,
                   d.protocol, d.engine, d.proxy_port, d.status, d.install_method
            FROM deployments d
            JOIN servers s ON s.id = d.server_id
            WHERE d.id IN ({placeholders})
            """,
            tuple(deployment_ids),
        )
        return {row["id"]: row for row in rows}
