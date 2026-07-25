from typing import Any

from ..provisioning import shell_quote
from .helpers import (
    ACME_HTTP_PORT,
    ACTIVE_CLIENT_CONDITION,
    DEPLOYMENT_PROTOCOL_ANYTLS,
    DEPLOYMENT_PROTOCOL_HYSTERIA2,
    DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022,
    DEPLOYMENT_PROTOCOL_VMESS,
    DEPLOYMENT_SS_METHOD,
    TLS_DOMAIN_PROTOCOLS,
    _render_subscription_links,
    _share_link_with_display_name,
    anytls_share_link,
    host_field,
    hy2_share_link,
    now_iso,
    parse_reality_destination,
    reality_candidates,
    reality_dest,
    ss_share_link,
    vless_reality_share_link,
    vmess_share_link,
)
from .servers import ServersService

DEPLOYMENT_COLUMNS = """
            d.id, d.server_id, s.name AS server_name, s.host,
            d.engine, d.protocol, d.install_method, d.proxy_port,
            d.reality_mode, d.reality_dest, d.reality_sni,
            d.encrypted_reality_private_key, d.reality_public_key,
            d.reality_short_id, d.ss_method, d.encrypted_ss_password,
            d.encrypted_hy2_obfs_password, d.anytls_domain, d.tls_cert_sha256,
            d.last_config_hash, d.status,
            d.subscription_url, d.last_error, d.created_at, d.updated_at
"""


class DeploymentsService(ServersService):
    def list_deployments(self) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            f"""
            SELECT {DEPLOYMENT_COLUMNS},
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
            self._attach_deployment_secrets(row, reveal=False)
        return rows

    def _node_install_options(self, deployment: dict[str, Any]) -> dict[str, Any]:
        """Firewall and certificate switches the installer needs per protocol."""
        protocol = deployment.get("protocol")
        if protocol == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022:
            return {"allow_udp": True, "self_signed_cert": False, "acme_http_port": 0}
        if protocol == DEPLOYMENT_PROTOCOL_HYSTERIA2:
            domain = str(deployment.get("anytls_domain") or "").strip()
            return {
                "allow_udp": True,
                "self_signed_cert": not domain,
                "acme_http_port": ACME_HTTP_PORT if domain else 0,
            }
        if protocol in TLS_DOMAIN_PROTOCOLS:
            domain = str(deployment.get("anytls_domain") or "").strip()
            return {
                "allow_udp": False,
                "self_signed_cert": not domain,
                "acme_http_port": ACME_HTTP_PORT if domain else 0,
            }
        return {"allow_udp": False, "self_signed_cert": False, "acme_http_port": 0}

    def _resolve_reality_target(
        self,
        job_id: str,
        deployment_id: str,
        server: dict[str, Any],
        deployment: dict[str, Any],
    ) -> tuple[str, str]:
        mode = deployment.get("reality_mode") or "manual"
        if mode == "manual":
            target, target_host = parse_reality_destination(
                deployment.get("reality_dest") or reality_dest(),
                "realityDest",
            )
            manual_sni = host_field(
                {"realitySni": deployment.get("reality_sni") or target_host},
                "realitySni",
            )
            candidates = [(target, manual_sni)]
            self._append_job_log(job_id, f"Validating manual REALITY target {target}")
        else:
            candidates = reality_candidates()
            self._append_job_log(
                job_id,
                f"Auto-selecting a REALITY target from {len(candidates)} candidates",
            )

        lines = self.ssh.run_script(
            server,
            self._reality_probe_script(candidates),
            lambda line: self._append_job_log(job_id, line),
            timeout=max(60, len(candidates) * 45),
        )
        selected_index: int | None = None
        marker = "__MYN_REALITY_SELECTED__="
        for line in lines:
            if line.strip().startswith(marker):
                try:
                    selected_index = int(line.strip()[len(marker) :])
                except ValueError:
                    selected_index = None
        if selected_index is None or not 0 <= selected_index < len(candidates):
            raise ValueError(
                "no REALITY camouflage target passed two TLS 1.3 certificate checks"
            )

        target, sni = candidates[selected_index]
        self.db.execute(
            """
            UPDATE deployments
            SET reality_dest = ?, reality_sni = ?, updated_at = ?
            WHERE id = ?
            """,
            (target, sni, now_iso(), deployment_id),
        )
        self._append_job_log(job_id, f"Selected REALITY target {target} (SNI {sni})")
        return target, sni

    def _reality_probe_script(self, candidates: list[tuple[str, str]]) -> str:
        probes = []
        for index, (target, sni) in enumerate(candidates):
            probes.append(
                f"probe {shell_quote(index)} {shell_quote(target)} {shell_quote(sni)}"
            )
        return r"""#!/usr/bin/env bash
set -u
export LC_ALL=C
if ! command -v openssl >/dev/null 2>&1; then
  echo "OpenSSL is required to test REALITY targets"
  exit 41
fi
if ! command -v timeout >/dev/null 2>&1; then
  echo "The timeout command is required to test REALITY targets"
  exit 42
fi
probe() {
  INDEX="$1"
  TARGET="$2"
  SNI="$3"
  echo "Testing REALITY target $TARGET (SNI $SNI)"
  ATTEMPT=1
  while [ "$ATTEMPT" -le 2 ]; do
    if OUTPUT="$(timeout 18 openssl s_client -connect "$TARGET" -servername "$SNI" \
        -tls1_3 -verify_hostname "$SNI" -verify_return_error -brief </dev/null 2>&1)" \
        && printf '%s\n' "$OUTPUT" | grep -Eq 'Protocol( version)?[[:space:]]*:[[:space:]]*TLSv1\.3'; then
      ATTEMPT=$((ATTEMPT + 1))
      continue
    fi
    echo "Rejected REALITY target $TARGET"
    return 1
  done
  echo "__MYN_REALITY_SELECTED__=$INDEX"
  return 0
}
""" + "\n".join(f"{probe} && exit 0" for probe in probes) + r"""
echo "No REALITY target passed validation"
exit 43
"""

    def get_deployment(
        self,
        deployment_id: str,
        reveal_secrets: bool = True,
    ) -> dict[str, Any]:
        row = self.db.query_one(
            f"""
            SELECT {DEPLOYMENT_COLUMNS},
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
        self._attach_deployment_secrets(row, reveal=reveal_secrets)
        return row

    def _default_share_link(
        self,
        deployment: dict[str, Any],
        client_uuid: str,
        name: str,
        ss_password: str = "",
        anytls_password: str = "",
        hy2_password: str = "",
    ) -> str:
        protocol = deployment.get("protocol")
        if protocol == DEPLOYMENT_PROTOCOL_SHADOWSOCKS_2022:
            return ss_share_link(
                method=deployment.get("ss_method") or DEPLOYMENT_SS_METHOD,
                server_password=deployment.get("ss_password") or "",
                user_password=ss_password,
                host=deployment["host"],
                port=int(deployment["proxy_port"]),
                name=name,
            )
        if protocol == DEPLOYMENT_PROTOCOL_ANYTLS:
            domain = str(deployment.get("anytls_domain") or "").strip()
            return anytls_share_link(
                password=anytls_password,
                host=domain or deployment["host"],
                port=int(deployment["proxy_port"]),
                name=name,
                sni=domain,
                insecure=not domain,
                cert_sha256=str(deployment.get("tls_cert_sha256") or ""),
            )
        if protocol == DEPLOYMENT_PROTOCOL_HYSTERIA2:
            domain = str(deployment.get("anytls_domain") or "").strip()
            return hy2_share_link(
                password=hy2_password,
                host=domain or deployment["host"],
                port=int(deployment["proxy_port"]),
                name=name,
                sni=domain,
                insecure=not domain,
                obfs_password=str(deployment.get("hy2_obfs_password") or ""),
                cert_sha256=str(deployment.get("tls_cert_sha256") or ""),
            )
        if protocol == DEPLOYMENT_PROTOCOL_VMESS:
            domain = str(deployment.get("anytls_domain") or "").strip()
            return vmess_share_link(
                client_uuid=client_uuid,
                host=domain or deployment["host"],
                port=int(deployment["proxy_port"]),
                name=name,
                sni=domain,
                tls=True,
                insecure=not domain,
                cert_sha256=str(deployment.get("tls_cert_sha256") or ""),
            )
        return vless_reality_share_link(
            client_uuid=client_uuid,
            host=deployment["host"],
            port=int(deployment["proxy_port"]),
            name=name,
            public_key=str(deployment.get("reality_public_key") or ""),
            short_id=str(deployment.get("reality_short_id") or ""),
            sni=str(deployment.get("reality_sni") or ""),
        )

    def render_deployment_subscription(
        self,
        deployment_id: str,
        output_format: str = "base64",
    ) -> str:
        deployment = self.get_deployment(deployment_id)
        if not deployment.get("subscription_url"):
            raise ValueError("subscription not found")
        rows = self.db.query_all(
            f"""
            SELECT c.share_link, sn.display_name
            FROM subscription_nodes sn
            JOIN clients c ON c.id = sn.node_client_id
            WHERE sn.subscription_id = ? AND {ACTIVE_CLIENT_CONDITION}
            ORDER BY sn.created_at ASC, c.created_at ASC
            """,
            (deployment_id,),
        )
        links = [
            _share_link_with_display_name(row["share_link"], row["display_name"])
            for row in rows
            if row.get("share_link")
        ]
        return _render_subscription_links(links, output_format)
