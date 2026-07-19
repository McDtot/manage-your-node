from datetime import UTC, date, datetime
from datetime import time as datetime_time
from typing import Any
from urllib.parse import quote, urlparse

from ..provisioning import shell_quote
from .helpers import (
    _render_subscription_links,
    _share_link_with_display_name,
    host_field,
    now_iso,
    parse_reality_destination,
    reality_candidates,
    reality_dest,
    url_host,
)
from .servers import ServersService


class DeploymentsService(ServersService):
    def list_deployments(self) -> list[dict[str, Any]]:
        rows = self.db.query_all(
            """
            SELECT d.id, d.server_id, s.name AS server_name, s.host,
                   d.engine, d.protocol, d.install_method, d.panel_scheme, d.panel_port,
                   d.panel_path, d.panel_username, d.encrypted_panel_password,
                   d.encrypted_api_token, d.proxy_port, d.reality_mode,
                   d.reality_dest, d.reality_sni, d.xui_inbound_id, d.status,
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
            self._attach_deployment_secrets(row, reveal=False)
        return rows

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
            """
            SELECT d.id, d.server_id, s.name AS server_name, s.host,
                   d.engine, d.protocol, d.install_method, d.panel_scheme, d.panel_port,
                   d.panel_path, d.panel_username, d.encrypted_panel_password,
                   d.encrypted_api_token, d.proxy_port, d.reality_mode,
                   d.reality_dest, d.reality_sni, d.xui_inbound_id, d.status,
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
        self._attach_deployment_secrets(row, reveal=reveal_secrets)
        return row

    def _default_share_link(self, deployment: dict[str, Any], client_uuid: str, name: str) -> str:
        tag = quote(name)
        return (
            f"vless://{client_uuid}@{url_host(deployment['host'])}:{deployment['proxy_port']}"
            f"?security=reality&type=tcp&flow=xtls-rprx-vision#{tag}"
        )

    def _expires_ms(self, expires_at: str) -> int:
        if not expires_at:
            return 0
        parsed = date.fromisoformat(expires_at)
        dt = datetime.combine(parsed, datetime_time.min, tzinfo=UTC)
        return int(dt.timestamp() * 1000)

    def render_deployment_subscription(
        self,
        deployment_id: str,
        output_format: str = "base64",
    ) -> str:
        deployment = self.get_deployment(deployment_id)
        if not deployment.get("subscription_url"):
            raise ValueError("subscription not found")
        rows = self.db.query_all(
            """
            SELECT c.share_link, sn.display_name
            FROM subscription_nodes sn
            JOIN clients c ON c.id = sn.node_client_id
            WHERE sn.subscription_id = ? AND c.enabled = 1
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
