import json
import ssl
import time
from http.cookiejar import CookieJar
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urljoin
from urllib.request import HTTPCookieProcessor, HTTPSHandler, Request, build_opener


class XuiApiError(RuntimeError):
    pass


class XuiApiClient:
    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        api_token: str = "",
        timeout: int = 20,
        verify_tls: bool = True,
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.username = username
        self.password = password
        self.api_token = api_token
        self.timeout = timeout
        self.cookie_jar = CookieJar()
        context = ssl.create_default_context()
        if not verify_tls:
            # Only use this while the connection itself is carried inside the
            # authenticated SSH tunnel to 127.0.0.1.
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.opener = build_opener(HTTPCookieProcessor(self.cookie_jar), HTTPSHandler(context=context))
        self._csrf_token = ""

    def wait_ready(self, seconds: int = 90) -> None:
        deadline = time.monotonic() + seconds
        last_error = ""
        while time.monotonic() < deadline:
            try:
                if self.api_token:
                    self.get_json("panel/api/server/status")
                else:
                    self.get_json("csrf-token")
                return
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                time.sleep(2)
        raise XuiApiError(f"3x-ui API did not become ready: {last_error}")

    def login(self) -> None:
        if self.api_token:
            return
        csrf = self.get_json("csrf-token")
        self._csrf_token = str(csrf.get("obj") or "")
        result = self.post_json(
            "login",
            {
                "username": self.username,
                "password": self.password,
                "twoFactorCode": "",
            },
            use_auth=False,
        )
        if not result.get("success"):
            raise XuiApiError(result.get("msg") or "3x-ui login failed")
        panel_csrf = self.get_json("panel/csrf-token")
        self._csrf_token = str(panel_csrf.get("obj") or self._csrf_token)

    def create_vless_reality_inbound(
        self,
        port: int,
        remark: str,
        target: str = "www.yahoo.com:443",
        server_names: list[str] | None = None,
    ) -> dict[str, Any]:
        keys = self.get_json("panel/api/server/getNewX25519Cert")["obj"]
        short_id = self._short_id()
        server_names = server_names or [target.split(":", 1)[0]]
        payload = {
            "enable": True,
            "remark": remark,
            "listen": "",
            "port": port,
            "protocol": "vless",
            "expiryTime": 0,
            "total": 0,
            "settings": {
                "clients": [],
                "decryption": "none",
                "encryption": "none",
                "fallbacks": [],
            },
            "streamSettings": {
                "network": "tcp",
                "tcpSettings": {"header": {"type": "none"}},
                "security": "reality",
                "realitySettings": {
                    "show": False,
                    "xver": 0,
                    "target": target,
                    "serverNames": server_names,
                    "privateKey": keys["privateKey"],
                    "minClientVer": "",
                    "maxClientVer": "",
                    "maxTimediff": 0,
                    "shortIds": [short_id],
                    "mldsa65Seed": "",
                    "settings": {
                        "publicKey": keys["publicKey"],
                        "fingerprint": "chrome",
                        "serverName": "",
                        "spiderX": "/",
                        "mldsa65Verify": "",
                    },
                },
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic", "fakedns"],
                "metadataOnly": False,
                "routeOnly": False,
                "ipsExcluded": [],
                "domainsExcluded": [],
            },
        }
        result = self.post_json("panel/api/inbounds/add", payload)
        inbound = result.get("obj")
        if not isinstance(inbound, dict) or not inbound.get("id"):
            raise XuiApiError("3x-ui did not return the created inbound id")
        return inbound

    def create_shadowsocks_inbound(
        self,
        port: int,
        remark: str,
        method: str,
        server_password: str,
    ) -> dict[str, Any]:
        payload = {
            "enable": True,
            "remark": remark,
            "listen": "",
            "port": port,
            "protocol": "shadowsocks",
            "expiryTime": 0,
            "total": 0,
            "settings": {
                "method": method,
                "password": server_password,
                "network": "tcp,udp",
                "clients": [],
            },
            "streamSettings": {
                "network": "tcp",
            },
            "sniffing": {
                "enabled": True,
                "destOverride": ["http", "tls", "quic", "fakedns"],
                "metadataOnly": False,
                "routeOnly": False,
                "ipsExcluded": [],
                "domainsExcluded": [],
            },
        }
        result = self.post_json("panel/api/inbounds/add", payload)
        inbound = result.get("obj")
        if not isinstance(inbound, dict) or not inbound.get("id"):
            raise XuiApiError("3x-ui did not return the created inbound id")
        return inbound

    def create_ss_client(
        self,
        inbound_id: int,
        email: str,
        password: str,
        sub_id: str,
        quota_bytes: int,
        expires_ms: int,
        reset_days: int,
    ) -> list[str]:
        payload = {
            "client": {
                "password": password,
                "email": email,
                "limitIp": 0,
                "totalGB": quota_bytes,
                "expiryTime": expires_ms,
                "enable": True,
                "tgId": 0,
                "subId": sub_id,
                "comment": "",
                "reset": reset_days,
            },
            "inboundIds": [inbound_id],
        }
        self.post_json("panel/api/clients/add", payload)
        links = self.get_json(f"panel/api/clients/links/{quote(email, safe='')}").get("obj") or []
        if not isinstance(links, list):
            return []
        return [str(link) for link in links]

    def create_client(
        self,
        inbound_id: int,
        email: str,
        client_uuid: str,
        sub_id: str,
        quota_bytes: int,
        expires_ms: int,
        reset_days: int,
    ) -> list[str]:
        payload = {
            "client": {
                "id": client_uuid,
                "email": email,
                "flow": "xtls-rprx-vision",
                "limitIp": 0,
                "totalGB": quota_bytes,
                "expiryTime": expires_ms,
                "enable": True,
                "tgId": 0,
                "subId": sub_id,
                "comment": "",
                "reset": reset_days,
            },
            "inboundIds": [inbound_id],
        }
        self.post_json("panel/api/clients/add", payload)
        links = self.get_json(f"panel/api/clients/links/{quote(email, safe='')}").get("obj") or []
        if not isinstance(links, list):
            return []
        return [str(link) for link in links]

    def get_client(self, email: str) -> dict[str, Any]:
        result = self.get_json(f"panel/api/clients/get/{quote(email, safe='')}")
        client = result.get("obj")
        if not isinstance(client, dict):
            raise XuiApiError("3x-ui did not return client details")
        return client

    def update_client(self, email: str, client: dict[str, Any]) -> None:
        self.post_json(f"panel/api/clients/update/{quote(email, safe='')}", client)

    def reset_client_traffic(self, inbound_id: int, email: str) -> None:
        self.post_json(
            f"panel/api/inbounds/{inbound_id}/resetClientTraffic/{quote(email, safe='')}",
            {},
        )

    def client_links(self, email: str) -> list[str]:
        links = self.get_json(f"panel/api/clients/links/{quote(email, safe='')}").get("obj") or []
        if not isinstance(links, list):
            return []
        return [str(link) for link in links]

    def delete_inbound(self, inbound_id: int) -> None:
        self.post_json(f"panel/api/inbounds/del/{inbound_id}", {})

    def restart_xray(self) -> None:
        self.post_json("panel/api/server/restartXrayService", {})

    def get_json(self, path: str) -> dict[str, Any]:
        return self._request("GET", path, None)

    def post_json(self, path: str, payload: dict[str, Any], use_auth: bool = True) -> dict[str, Any]:
        return self._request("POST", path, payload, use_auth=use_auth)

    def _request(
        self,
        method: str,
        path: str,
        payload: dict[str, Any] | None,
        use_auth: bool = True,
    ) -> dict[str, Any]:
        body = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-Requested-With": "XMLHttpRequest",
        }
        if use_auth and self.api_token:
            headers["Authorization"] = f"Bearer {self.api_token}"
        if method not in {"GET", "HEAD"} and self._csrf_token:
            headers["X-CSRF-Token"] = self._csrf_token

        req = Request(urljoin(self.base_url, path), data=body, headers=headers, method=method)
        try:
            with self.opener.open(req, timeout=self.timeout) as response:
                raw = response.read().decode("utf-8", errors="replace")
        except HTTPError as exc:
            detail = exc.read().decode("utf-8", errors="replace")
            raise XuiApiError(f"3x-ui HTTP {exc.code}: {detail}") from exc
        except URLError as exc:
            raise XuiApiError(f"3x-ui API request failed: {exc.reason}") from exc

        try:
            data = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise XuiApiError(f"3x-ui returned non-JSON response: {raw[:200]}") from exc
        if isinstance(data, dict) and data.get("success") is False:
            raise XuiApiError(str(data.get("msg") or "3x-ui API returned success=false"))
        if not isinstance(data, dict):
            raise XuiApiError("3x-ui returned unexpected JSON shape")
        return data

    def _short_id(self) -> str:
        return f"{int(time.time() * 1000) & 0xffffffff:08x}"
