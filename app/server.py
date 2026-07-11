import json
import logging
import mimetypes
import re
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .auth import AuthManager
from .config import ConfigError, load_settings
from .database import Database
from .security import SecretBox
from .services import AppServices


class RequestHandler(BaseHTTPRequestHandler):
    auth: AuthManager
    services: AppServices
    static_dir: Path
    cookie_secure: bool = False
    max_body_bytes: int = 1024 * 1024
    trust_x_forwarded_for: bool = False

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            self.send_json({"ok": True})
            return
        if path == "/login":
            if self.is_authenticated():
                self.redirect("/")
                return
            self.serve_static(path)
            return
        if not self.require_auth(path):
            return
        if path == "/api/auth/session":
            self.send_json({"authenticated": True, "username": self.auth.admin_username})
            return
        if path == "/api/summary":
            self.send_json(self.services.summary())
            return
        if path == "/api/servers":
            self.send_json({"servers": self.services.list_servers()})
            return
        if path == "/api/deployments":
            self.send_json({"deployments": self.services.list_deployments()})
            return
        if path == "/api/clients":
            self.send_json({"clients": self.services.list_clients()})
            return
        if path == "/api/subscriptions":
            self.send_json({"subscriptions": self.services.list_subscriptions()})
            return
        if path == "/api/chains":
            self.send_json({"chains": self.services.list_proxy_chains()})
            return

        match = re.fullmatch(r"/api/subscriptions/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.get_managed_subscription_config(match.group(1)))
            return

        match = re.fullmatch(r"/api/deployments/([^/]+)/subscription", path)
        if match:
            self.handle_value(lambda: self.services.get_subscription_config(match.group(1)))
            return

        match = re.fullmatch(r"/sub/links/([^/]+)", path)
        if match:
            self.handle_text(lambda: self.services.render_managed_subscription(match.group(1)))
            return

        match = re.fullmatch(r"/sub/deployments/([^/]+)", path)
        if match:
            self.handle_text(lambda: self.services.render_deployment_subscription(match.group(1)))
            return

        match = re.fullmatch(r"/sub/chains/([^/]+)", path)
        if match:
            self.handle_text(lambda: self.services.render_proxy_chain_subscription(match.group(1)))
            return

        match = re.fullmatch(r"/api/jobs/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.get_job(match.group(1)))
            return

        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/auth/login":
            self.handle_login()
            return
        if not self.require_auth(path):
            return
        self.log_audit()
        if path == "/api/auth/logout":
            self.send_json({"ok": True}, headers=[("Set-Cookie", self.clear_session_cookie())])
            return

        try:
            body = self.read_json()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return

        if path == "/api/servers":
            self.handle_value(lambda: self.services.create_server(body), status=201)
            return
        if path == "/api/subscriptions":
            self.handle_value(lambda: self.services.create_subscription(body), status=201)
            return
        if path == "/api/chains":
            self.handle_value(lambda: self.services.create_proxy_chain(body), status=201)
            return

        match = re.fullmatch(r"/api/chains/([^/]+)/deploy", path)
        if match:
            self.handle_value(lambda: self.services.start_proxy_chain_deployment(match.group(1)), status=201)
            return

        match = re.fullmatch(r"/api/servers/([^/]+)/test", path)
        if match:
            self.handle_value(lambda: self.services.test_server(match.group(1)))
            return

        match = re.fullmatch(r"/api/servers/([^/]+)/deploy", path)
        if match:
            self.handle_value(lambda: self.services.start_deployment(match.group(1), body), status=201)
            return

        match = re.fullmatch(r"/api/deployments/([^/]+)/clients", path)
        if match:
            self.handle_value(lambda: self.services.create_client(match.group(1), body), status=201)
            return

        match = re.fullmatch(r"/api/clients/([^/]+)/reset", path)
        if match:
            self.handle_value(lambda: self.services.reset_client(match.group(1)))
            return

        self.send_json({"error": "not found"}, status=404)

    def do_PATCH(self) -> None:
        path = urlparse(self.path).path
        if not self.require_auth(path):
            return
        self.log_audit()
        try:
            body = self.read_json()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return

        match = re.fullmatch(r"/api/clients/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.update_client(match.group(1), body))
            return

        match = re.fullmatch(r"/api/subscriptions/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.update_managed_subscription(match.group(1), body))
            return

        match = re.fullmatch(r"/api/deployments/([^/]+)/subscription", path)
        if match:
            self.handle_value(lambda: self.services.update_subscription_config(match.group(1), body))
            return

        self.send_json({"error": "not found"}, status=404)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if not self.require_auth(path):
            return
        self.log_audit()

        match = re.fullmatch(r"/api/servers/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.delete_server(match.group(1)))
            return

        match = re.fullmatch(r"/api/deployments/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.delete_deployment(match.group(1)))
            return

        match = re.fullmatch(r"/api/subscriptions/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.delete_subscription(match.group(1)))
            return

        match = re.fullmatch(r"/api/chains/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.delete_proxy_chain(match.group(1)))
            return

        self.send_json({"error": "not found"}, status=404)

    def handle_value(self, func, status: int = 200) -> None:
        try:
            self.send_json(func(), status=status)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:  # noqa: BLE001
            self.report_internal_error(exc)

    def handle_text(self, func, status: int = 200) -> None:
        try:
            self.send_text(func(), status=status)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:  # noqa: BLE001
            self.report_internal_error(exc)

    def report_internal_error(self, exc: Exception) -> None:
        # Log full detail server-side, return a generic message to the client so
        # internal paths, SQL, and stack details are not leaked.
        logging.getLogger("myn").exception("Unhandled request error: %s", exc)
        self.send_json({"error": "internal server error"}, status=500)

    def client_key(self) -> str:
        if self.trust_x_forwarded_for:
            forwarded = self.headers.get("X-Forwarded-For", "")
            if forwarded:
                return forwarded.split(",")[0].strip() or "unknown"
        return self.client_address[0] if self.client_address else "unknown"

    def log_audit(self) -> None:
        path = urlparse(self.path).path
        logging.getLogger("myn.audit").info(
            "action user=%s ip=%s method=%s path=%s",
            self.auth.admin_username,
            self.client_key(),
            self.command,
            path,
        )

    def handle_login(self) -> None:
        client_key = self.client_key()
        audit = logging.getLogger("myn.audit")
        remaining = self.auth.lockout_remaining(client_key)
        if remaining > 0:
            audit.warning("login blocked (locked out) ip=%s", client_key)
            self.send_json(
                {"error": f"too many failed attempts, try again in {remaining}s"},
                status=429,
                headers=[("Retry-After", str(remaining))],
            )
            return
        try:
            payload = self.read_payload()
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
            return
        username = str(payload.get("username", ""))
        password = str(payload.get("password", ""))
        if not self.auth.verify_credentials(username, password):
            self.auth.register_failure(client_key)
            audit.warning("login failed ip=%s user=%s", client_key, username)
            self.send_json({"error": "invalid username or password"}, status=401)
            return
        self.auth.register_success(client_key)
        audit.info("login success ip=%s user=%s", client_key, username)
        token = self.auth.issue_session()
        self.send_json({"ok": True}, headers=[("Set-Cookie", self.session_cookie(token))])

    def require_auth(self, path: str) -> bool:
        if self.is_public_path(path):
            return True
        if self.is_authenticated():
            return True
        if path.startswith("/api/"):
            self.send_json({"error": "unauthorized"}, status=401)
        else:
            self.redirect("/login")
        return False

    def is_public_path(self, path: str) -> bool:
        return path == "/static/styles.css" or path.startswith("/sub/")

    def is_authenticated(self) -> bool:
        return self.auth.verify_session(self.session_token())

    def session_token(self) -> str:
        raw = self.headers.get("Cookie", "")
        if not raw:
            return ""
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except Exception:  # noqa: BLE001
            return ""
        morsel = cookie.get(self.auth.cookie_name)
        return morsel.value if morsel else ""

    def session_cookie(self, token: str) -> str:
        secure = "; Secure" if self.cookie_secure else ""
        return (
            f"{self.auth.cookie_name}={token}; Path=/; "
            f"Max-Age={self.auth.session_seconds}; HttpOnly; SameSite=Strict{secure}"
        )

    def clear_session_cookie(self) -> str:
        secure = "; Secure" if self.cookie_secure else ""
        return f"{self.auth.cookie_name}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict{secure}"

    def redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def read_payload(self) -> dict:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length > self.max_body_bytes:
            raise ValueError("request body too large")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid utf-8 payload") from exc
        content_type = self.headers.get("content-type", "")
        if content_type.startswith("application/x-www-form-urlencoded"):
            parsed = parse_qs(text, keep_blank_values=True)
            return {key: values[-1] if values else "" for key, values in parsed.items()}
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid json") from exc

    def read_json(self) -> dict:
        try:
            length = int(self.headers.get("content-length", "0"))
        except ValueError as exc:
            raise ValueError("invalid content length") from exc
        if length > self.max_body_bytes:
            raise ValueError("request body too large")
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("invalid utf-8 payload") from exc
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValueError("invalid json") from exc

    def send_json(
        self,
        data,
        status: int = 200,
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def send_text(
        self,
        data: str,
        status: int = 200,
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        raw = data.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(raw)

    def serve_static(self, path: str) -> None:
        if path == "/":
            file_path = self.static_dir / "index.html"
        elif path == "/login":
            file_path = self.static_dir / "login.html"
        elif path.startswith("/static/"):
            file_path = self.static_dir / path.removeprefix("/static/")
        else:
            file_path = self.static_dir / "index.html"

        try:
            resolved = file_path.resolve()
            resolved.relative_to(self.static_dir.resolve())
            if not resolved.is_file():
                raise FileNotFoundError
            raw = resolved.read_bytes()
        except (OSError, ValueError):
            self.send_response(404)
            self.end_headers()
            return

        content_type = mimetypes.guess_type(str(resolved))[0] or "application/octet-stream"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return


def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    try:
        settings = load_settings()
    except ConfigError as exc:
        print(f"Configuration error:\n{exc}", flush=True)
        raise SystemExit(1) from exc

    db = Database(settings.db_path)
    services = AppServices(db, SecretBox(settings.app_secret))
    recovered = services.recover_orphaned_jobs()
    if recovered:
        logging.getLogger("myn").warning(
            "Marked %d orphaned running job(s) as failed after restart", recovered
        )
    auth = AuthManager(
        settings.app_secret,
        settings.admin_username,
        settings.admin_password,
        settings.session_seconds,
    )
    handler = type(
        "ManageNodeRequestHandler",
        (RequestHandler,),
        {
            "auth": auth,
            "services": services,
            "static_dir": settings.static_dir,
            "cookie_secure": settings.cookie_secure,
            "max_body_bytes": settings.max_body_bytes,
            "trust_x_forwarded_for": settings.trust_x_forwarded_for,
        },
    )
    server = ThreadingHTTPServer((settings.host, settings.port), handler)
    if settings.allow_insecure:
        logging.getLogger("myn").warning(
            "Running in INSECURE mode (development). Do not expose this to the public internet."
        )
    print(f"Manage Your Node running at http://{settings.host}:{settings.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
