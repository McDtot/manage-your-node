import json
import mimetypes
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

from .config import load_settings
from .database import Database
from .security import SecretBox
from .services import AppServices


class RequestHandler(BaseHTTPRequestHandler):
    services: AppServices
    static_dir: Path

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/api/health":
            self.send_json({"ok": True})
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

        match = re.fullmatch(r"/api/jobs/([^/]+)", path)
        if match:
            self.handle_value(lambda: self.services.get_job(match.group(1)))
            return

        self.serve_static(path)

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        body = self.read_json()

        if path == "/api/servers":
            self.handle_value(lambda: self.services.create_server(body), status=201)
            return
        if path == "/api/subscriptions":
            self.handle_value(lambda: self.services.create_subscription(body), status=201)
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
        body = self.read_json()

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

        self.send_json({"error": "not found"}, status=404)

    def handle_value(self, func, status: int = 200) -> None:
        try:
            self.send_json(func(), status=status)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:  # noqa: BLE001
            self.send_json({"error": str(exc)}, status=500)

    def handle_text(self, func, status: int = 200) -> None:
        try:
            self.send_text(func(), status=status)
        except ValueError as exc:
            self.send_json({"error": str(exc)}, status=400)
        except Exception as exc:  # noqa: BLE001
            self.send_json({"error": str(exc)}, status=500)

    def read_json(self) -> dict:
        length = int(self.headers.get("content-length", "0"))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except json.JSONDecodeError as exc:
            raise ValueError("invalid json") from exc

    def send_json(self, data, status: int = 200) -> None:
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def send_text(self, data: str, status: int = 200) -> None:
        raw = data.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def serve_static(self, path: str) -> None:
        if path == "/":
            file_path = self.static_dir / "index.html"
        elif path.startswith("/static/"):
            file_path = self.static_dir / path.removeprefix("/static/")
        else:
            file_path = self.static_dir / "index.html"

        try:
            resolved = file_path.resolve()
            if not str(resolved).startswith(str(self.static_dir.resolve())):
                raise FileNotFoundError
            raw = resolved.read_bytes()
        except OSError:
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
    settings = load_settings()
    db = Database(settings.db_path)
    services = AppServices(db, SecretBox(settings.app_secret))
    handler = type(
        "ManageNodeRequestHandler",
        (RequestHandler,),
        {"services": services, "static_dir": settings.static_dir},
    )
    server = ThreadingHTTPServer((settings.host, settings.port), handler)
    print(f"Manage Your Node running at http://{settings.host}:{settings.port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
