import json
import logging
import threading
import time
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import uvicorn
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import (
    FileResponse,
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
)
from starlette.routing import Route

from .auth import AuthManager
from .config import ConfigError, Settings, load_settings
from .database import Database
from .security import SecretBox
from .services import AppServices
from .web_config import WebConfig

LOGGER = logging.getLogger("myn")
AUDIT_LOGGER = logging.getLogger("myn.audit")
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
SESSION_COOKIE_NAMES = ("__Host-myn_session", "myn_session")
CSRF_COOKIE_NAMES = ("__Host-myn_csrf", "myn_csrf")


def _cookie_value(cookies, names: tuple[str, ...]) -> str:  # noqa: ANN001
    for name in names:
        value = cookies.get(name, "")
        if value:
            return value
    return ""


def _request_is_loopback(request: Request) -> bool:
    return (request.url.hostname or "") in {"127.0.0.1", "localhost", "::1"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
            "form-action 'self'"
        )
        if request.app.state.web_config.cookie_secure and not _request_is_loopback(request):
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if (
            request.url.path.startswith("/api/")
            or request.url.path.startswith("/sub/")
            or request.url.path == "/login"
        ):
            response.headers["Cache-Control"] = "no-store"
        return response


class RuntimeTrustedHostMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        host = request.url.hostname or ""
        allowed_hosts = request.app.state.web_config.allowed_hosts()
        valid = any(
            pattern == "*"
            or host == pattern.strip("[]")
            or (pattern.startswith("*") and host.endswith(pattern[1:]))
            for pattern in allowed_hosts
        )
        if not valid:
            return PlainTextResponse("Invalid host header", status_code=400)
        return await call_next(request)


class AuditMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, db: Database, auth: AuthManager):  # noqa: ANN001
        super().__init__(app)
        self.db = db
        self.auth = auth

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        response = await call_next(request)
        if request.method in UNSAFE_METHODS and request.url.path.startswith("/api/"):
            token = _cookie_value(request.cookies, SESSION_COOKIE_NAMES)
            actor = self.auth.admin_username if self.auth.verify_session(token) else "anonymous"
            client_ip = request.client.host if request.client else "unknown"
            stamp = datetime.now(UTC).isoformat(timespec="seconds")
            try:
                await run_in_threadpool(
                    self.db.execute,
                    """
                    INSERT INTO audit_events (at, actor, client_ip, method, path, status)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (stamp, actor, client_ip, request.method, request.url.path, response.status_code),
                )
            except Exception:  # noqa: BLE001
                AUDIT_LOGGER.exception("Could not persist audit event")
            AUDIT_LOGGER.info(
                "action user=%s ip=%s method=%s path=%s status=%s",
                actor,
                client_ip,
                request.method,
                request.url.path,
                response.status_code,
            )
        return response


class ApiAuthenticationMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, auth: AuthManager):  # noqa: ANN001
        super().__init__(app)
        self.auth = auth

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        public = request.url.path in {
            "/api/health",
            "/api/health/live",
            "/api/health/ready",
            "/api/auth/login",
        }
        if request.url.path.startswith("/api/") and not public:
            token = _cookie_value(request.cookies, SESSION_COOKIE_NAMES)
            if not self.auth.verify_session(token):
                return JSONResponse({"error": "unauthorized"}, status_code=401)
        return await call_next(request)


class SubscriptionRateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, requests_per_minute: int):  # noqa: ANN001
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self._requests: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    async def dispatch(self, request: Request, call_next):  # noqa: ANN001
        if not request.url.path.startswith("/sub/"):
            return await call_next(request)
        now = time.monotonic()
        client_ip = request.client.host if request.client else "unknown"
        with self._lock:
            recent = [stamp for stamp in self._requests.get(client_ip, []) if stamp > now - 60]
            if len(recent) >= self.requests_per_minute:
                return JSONResponse(
                    {"error": "subscription rate limit exceeded"},
                    status_code=429,
                    headers={"Retry-After": "60"},
                )
            recent.append(now)
            self._requests[client_ip] = recent
            if len(self._requests) > 10_000:
                self._requests = {
                    key: values
                    for key, values in self._requests.items()
                    if any(stamp > now - 60 for stamp in values)
                }
        return await call_next(request)


def _session_token(request: Request) -> str:
    return _cookie_value(request.cookies, SESSION_COOKIE_NAMES)


def _csrf_cookie_token(request: Request) -> str:
    return _cookie_value(request.cookies, CSRF_COOKIE_NAMES)


def _request_origin(request: Request) -> str:
    return f"{request.url.scheme}://{request.headers.get('host', request.url.netloc)}"


def _origin_is_allowed(request: Request) -> bool:
    if request.headers.get("sec-fetch-site", "").lower() == "cross-site":
        return False
    web_config: WebConfig = request.app.state.web_config
    request_origin = _request_origin(request)
    flexible_origin = (
        request.app.state.settings.allow_insecure
        or web_config.public_access_warning
        or _request_is_loopback(request)
    )
    def allowed(value: str) -> bool:
        if flexible_origin:
            # Without a canonical HTTPS domain the same process may be reached
            # via its public, LAN, or loopback address. Always require the
            # browser Origin to match the validated request Host exactly.
            return value == request_origin
        return web_config.origin_is_allowed(value, request_origin)
    origin = request.headers.get("origin", "").rstrip("/")
    if origin:
        return allowed(origin)
    referer = request.headers.get("referer", "")
    if referer:
        parsed = urlparse(referer)
        return allowed(f"{parsed.scheme}://{parsed.netloc}")
    # Non-browser API clients may omit both. Browser requests are still covered
    # by the bound CSRF token, SameSite cookie, and Fetch Metadata check.
    return True


def _auth_guard(request: Request, require_csrf: bool = False) -> Response | None:
    auth: AuthManager = request.app.state.auth
    token = _session_token(request)
    if not auth.verify_session(token):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    if require_csrf:
        header_token = request.headers.get("x-csrf-token", "")
        cookie_token = _csrf_cookie_token(request)
        if (
            not _origin_is_allowed(request)
            or not header_token
            or not cookie_token
            or header_token != cookie_token
            or not auth.verify_csrf(token, header_token)
        ):
            return JSONResponse({"error": "csrf validation failed"}, status_code=403)
    return None


async def _read_payload(request: Request) -> dict:
    settings: Settings = request.app.state.settings
    raw_length = request.headers.get("content-length", "0")
    try:
        length = int(raw_length)
    except ValueError as exc:
        raise ValueError("invalid content length") from exc
    if length < 0 or length > settings.max_body_bytes:
        raise ValueError("request body too large")
    raw = await request.body()
    if len(raw) > settings.max_body_bytes:
        raise ValueError("request body too large")
    if not raw:
        return {}
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("invalid utf-8 payload") from exc
    if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded"):
        parsed = parse_qs(text, keep_blank_values=True)
        return {key: values[-1] if values else "" for key, values in parsed.items()}
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError("invalid json") from exc
    if not isinstance(payload, dict):
        raise ValueError("json body must be an object")
    return payload


async def _service_response(
    func,
    status_code: int = 200,
    text: bool = False,
    media_type: str | None = None,
) -> Response:  # noqa: ANN001
    try:
        value = await run_in_threadpool(func)
        if text:
            return PlainTextResponse(value, status_code=status_code, media_type=media_type)
        return JSONResponse(value, status_code=status_code)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        LOGGER.exception("Unhandled request error: %s", exc)
        return JSONResponse({"error": "internal server error"}, status_code=500)


async def health_live(_request: Request) -> Response:
    return JSONResponse({"ok": True})


async def health_ready(request: Request) -> Response:
    try:
        ready = await run_in_threadpool(request.app.state.db.ping)
    except Exception:  # noqa: BLE001
        ready = False
    return JSONResponse({"ok": ready}, status_code=200 if ready else 503)


async def login_page(request: Request) -> Response:
    if request.app.state.auth.verify_session(_session_token(request)):
        return RedirectResponse("/", status_code=303)
    return FileResponse(request.app.state.settings.static_dir / "login.html")


async def login(request: Request) -> Response:
    if not _origin_is_allowed(request):
        return JSONResponse({"error": "origin validation failed"}, status_code=403)
    auth: AuthManager = request.app.state.auth
    client_key = request.client.host if request.client else "unknown"
    remaining = await run_in_threadpool(auth.lockout_remaining, client_key)
    if remaining > 0:
        return JSONResponse(
            {"error": f"too many failed attempts, try again in {remaining}s"},
            status_code=429,
            headers={"Retry-After": str(remaining)},
        )
    try:
        payload = await _read_payload(request)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    username = str(payload.get("username", ""))
    password = str(payload.get("password", ""))
    if not auth.verify_credentials(username, password):
        await run_in_threadpool(auth.register_failure, client_key)
        return JSONResponse({"error": "invalid username or password"}, status_code=401)
    await run_in_threadpool(auth.register_success, client_key)
    token = auth.issue_session()
    csrf = auth.csrf_token(token)
    web_config: WebConfig = request.app.state.web_config
    cookie_secure = web_config.cookie_secure and not _request_is_loopback(request)
    cookie_prefix = "__Host-" if cookie_secure else ""
    session_cookie_name = f"{cookie_prefix}myn_session"
    csrf_cookie_name = f"{cookie_prefix}myn_csrf"
    response = JSONResponse({"ok": True})
    response.set_cookie(
        session_cookie_name,
        token,
        max_age=auth.session_seconds,
        path="/",
        secure=cookie_secure,
        httponly=True,
        samesite="strict",
    )
    response.set_cookie(
        csrf_cookie_name,
        csrf,
        max_age=auth.session_seconds,
        path="/",
        secure=cookie_secure,
        httponly=False,
        samesite="strict",
    )
    return response


async def logout(request: Request) -> Response:
    blocked = _auth_guard(request, require_csrf=True)
    if blocked:
        return blocked
    response = JSONResponse({"ok": True})
    for cookie_name in SESSION_COOKIE_NAMES:
        response.delete_cookie(
            cookie_name,
            path="/",
            secure=cookie_name.startswith("__Host-"),
            httponly=True,
            samesite="strict",
        )
    for cookie_name in CSRF_COOKIE_NAMES:
        response.delete_cookie(
            cookie_name,
            path="/",
            secure=cookie_name.startswith("__Host-"),
            httponly=False,
            samesite="strict",
        )
    return response


async def auth_session(request: Request) -> Response:
    blocked = _auth_guard(request)
    if blocked:
        return blocked
    auth: AuthManager = request.app.state.auth
    csrf = auth.csrf_token(_session_token(request))
    response = JSONResponse(
        {
            "authenticated": True,
            "username": auth.admin_username,
            "csrfToken": csrf,
            "securityWarning": (
                "当前管理面板没有配置 HTTPS 域名，正在通过公网地址直接访问。"
                "登录信息和提交的 SSH 凭据可能被链路监听，请尽快配置域名与 HTTPS。"
                if request.app.state.web_config.public_access_warning
                else ""
            ),
        }
    )
    web_config: WebConfig = request.app.state.web_config
    cookie_secure = web_config.cookie_secure and not _request_is_loopback(request)
    cookie_prefix = "__Host-" if cookie_secure else ""
    response.set_cookie(
        f"{cookie_prefix}myn_csrf",
        csrf,
        max_age=auth.session_seconds,
        path="/",
        secure=cookie_secure,
        httponly=False,
        samesite="strict",
    )
    return response


def _get_service(request: Request) -> AppServices:
    return request.app.state.services


def _subscription_output_format(request: Request) -> str:
    requested = request.query_params.get("format", "").strip().lower()
    if requested:
        return requested
    user_agent = request.headers.get("user-agent", "").lower()
    if "mihomo" in user_agent or "clash" in user_agent:
        return "mihomo"
    return "base64"


def _subscription_media_type(output_format: str) -> str:
    return "application/yaml" if output_format in {"clash", "mihomo", "yaml"} else "text/plain"


async def summary(request: Request) -> Response:
    return await _service_response(_get_service(request).summary)


async def get_web_settings(request: Request) -> Response:
    return JSONResponse(request.app.state.web_config.as_dict(_request_origin(request)))


async def update_web_settings(request: Request) -> Response:
    blocked = _auth_guard(request, require_csrf=True)
    if blocked:
        return blocked
    try:
        body = await _read_payload(request)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return await _service_response(
        lambda: request.app.state.web_config.update_public_origin(
            body.get("publicOrigin", ""),
            current_origin=request.headers.get("origin", "") or _request_origin(request),
        )
    )


async def list_servers(request: Request) -> Response:
    return await _service_response(lambda: {"servers": _get_service(request).list_servers()})


async def list_deployments(request: Request) -> Response:
    return await _service_response(lambda: {"deployments": _get_service(request).list_deployments()})


async def list_clients(request: Request) -> Response:
    return await _service_response(lambda: {"clients": _get_service(request).list_clients()})


async def list_subscriptions(request: Request) -> Response:
    return await _service_response(lambda: {"subscriptions": _get_service(request).list_subscriptions()})


async def list_chains(request: Request) -> Response:
    return await _service_response(lambda: {"chains": _get_service(request).list_proxy_chains()})


async def list_audit(request: Request) -> Response:
    try:
        limit = int(request.query_params.get("limit", "100"))
    except ValueError:
        return JSONResponse({"error": "limit must be a number"}, status_code=400)
    return await _service_response(
        lambda: {"events": _get_service(request).list_audit_events(limit)}
    )


async def get_subscription(request: Request) -> Response:
    item_id = request.path_params["item_id"]
    return await _service_response(lambda: _get_service(request).get_managed_subscription_config(item_id))


async def get_deployment_subscription(request: Request) -> Response:
    item_id = request.path_params["item_id"]
    return await _service_response(lambda: _get_service(request).get_subscription_config(item_id))


async def get_job(request: Request) -> Response:
    item_id = request.path_params["item_id"]
    raw_after = request.query_params.get("after", "0")
    try:
        after_seq = int(raw_after)
    except ValueError:
        return JSONResponse({"error": "after must be a number"}, status_code=400)
    if after_seq < 0:
        return JSONResponse({"error": "after must be zero or greater"}, status_code=400)
    return await _service_response(
        lambda: _get_service(request).get_job(item_id, after_seq=after_seq)
    )


async def render_subscription(request: Request) -> Response:
    token = request.path_params["token"]
    output_format = _subscription_output_format(request)
    return await _service_response(
        lambda: _get_service(request).render_managed_subscription(token, output_format),
        text=True,
        media_type=_subscription_media_type(output_format),
    )


async def render_deployment_subscription(request: Request) -> Response:
    token = request.path_params["token"]
    output_format = _subscription_output_format(request)
    return await _service_response(
        lambda: _get_service(request).render_deployment_subscription(token, output_format),
        text=True,
        media_type=_subscription_media_type(output_format),
    )


async def render_chain_subscription(request: Request) -> Response:
    token = request.path_params["token"]
    output_format = _subscription_output_format(request)
    return await _service_response(
        lambda: _get_service(request).render_proxy_chain_subscription(token, output_format),
        text=True,
        media_type=_subscription_media_type(output_format),
    )


async def mutate(request: Request) -> Response:
    blocked = _auth_guard(request, require_csrf=True)
    if blocked:
        return blocked
    services = _get_service(request)
    item_id = request.path_params.get("item_id", "")
    action = request.path_params.get("action", "")
    try:
        body = await _read_payload(request) if request.method != "DELETE" else {}
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)

    route_key = (request.method, action)
    handlers = {
        ("POST", "create_server"): (lambda: services.create_server(body), 201),
        ("POST", "create_subscription"): (lambda: services.create_subscription(body), 201),
        ("POST", "create_chain"): (lambda: services.create_proxy_chain(body), 201),
        ("POST", "deploy_chain"): (lambda: services.start_proxy_chain_deployment(item_id), 201),
        ("POST", "test_server"): (lambda: services.test_server(item_id), 200),
        ("POST", "approve_host_key"): (lambda: services.approve_server_host_key(item_id), 200),
        ("POST", "reset_host_key"): (lambda: services.reset_server_host_key(item_id), 200),
        ("POST", "deploy_server"): (lambda: services.start_deployment(item_id, body), 201),
        ("POST", "create_client"): (lambda: services.create_client(item_id, body), 201),
        ("POST", "reset_client"): (lambda: services.reset_client(item_id), 200),
        ("POST", "rotate_subscription_token"): (
            lambda: services.rotate_subscription_token(item_id),
            200,
        ),
        ("POST", "rotate_chain_token"): (lambda: services.rotate_proxy_chain_token(item_id), 200),
        ("PATCH", "update_client"): (lambda: services.update_client(item_id, body), 200),
        ("PATCH", "update_subscription"): (
            lambda: services.update_managed_subscription(item_id, body),
            200,
        ),
        ("PATCH", "update_deployment_subscription"): (
            lambda: services.update_subscription_config(item_id, body),
            200,
        ),
        ("DELETE", "delete_server"): (lambda: services.delete_server(item_id), 200),
        ("DELETE", "delete_deployment"): (lambda: services.delete_deployment(item_id), 200),
        ("DELETE", "delete_subscription"): (lambda: services.delete_subscription(item_id), 200),
        ("DELETE", "delete_chain"): (lambda: services.delete_proxy_chain(item_id), 200),
    }
    selected = handlers.get(route_key)
    if not selected:
        return JSONResponse({"error": "not found"}, status_code=404)
    func, status_code = selected
    return await _service_response(func, status_code=status_code)


def mutation_endpoint(action: str):
    async def endpoint(request: Request) -> Response:
        request.path_params["action"] = action
        return await mutate(request)

    endpoint.__name__ = f"mutate_{action}"
    return endpoint


async def static_file(request: Request) -> Response:
    static_dir: Path = request.app.state.settings.static_dir
    requested = static_dir / request.path_params["path"]
    try:
        resolved = requested.resolve()
        resolved.relative_to(static_dir.resolve())
        if not resolved.is_file():
            raise FileNotFoundError
    except (OSError, ValueError):
        return Response(status_code=404)
    return FileResponse(resolved)


async def spa(request: Request) -> Response:
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": "not found"}, status_code=404)
    blocked = _auth_guard(request)
    if blocked:
        next_path = request.url.path if request.url.path.startswith("/") else "/"
        return RedirectResponse(f"/login?next={next_path}", status_code=303)
    return FileResponse(request.app.state.settings.static_dir / "index.html")


def create_app(
    settings: Settings | None = None,
    db: Database | None = None,
    services: AppServices | None = None,
) -> Starlette:
    settings = settings or load_settings()
    db = db or Database(settings.db_path)
    services = services or AppServices(db, SecretBox(settings.app_secret))
    web_config = WebConfig(settings, db)
    recovered = services.recover_orphaned_jobs()
    if recovered:
        LOGGER.warning("Marked %d orphaned running job(s) as failed after restart", recovered)
    auth = AuthManager(
        settings.app_secret,
        settings.admin_username,
        settings.admin_password,
        settings.session_seconds,
        db=db,
        cookie_name="myn_session",
    )

    @asynccontextmanager
    async def lifespan(_application: Starlette):
        yield
        finished = await run_in_threadpool(services.wait_for_workers, 25.0)
        if not finished:
            LOGGER.warning(
                "Background jobs did not finish during graceful shutdown; startup recovery will mark them failed"
            )

    routes = [
        Route("/api/health", health_live, methods=["GET"]),
        Route("/api/health/live", health_live, methods=["GET"]),
        Route("/api/health/ready", health_ready, methods=["GET"]),
        Route("/login", login_page, methods=["GET"]),
        Route("/api/auth/login", login, methods=["POST"]),
        Route("/api/auth/logout", logout, methods=["POST"]),
        Route("/api/auth/session", auth_session, methods=["GET"]),
        Route("/api/summary", summary, methods=["GET"]),
        Route("/api/settings", get_web_settings, methods=["GET"]),
        Route("/api/servers", list_servers, methods=["GET"]),
        Route("/api/deployments", list_deployments, methods=["GET"]),
        Route("/api/clients", list_clients, methods=["GET"]),
        Route("/api/subscriptions", list_subscriptions, methods=["GET"]),
        Route("/api/chains", list_chains, methods=["GET"]),
        Route("/api/audit", list_audit, methods=["GET"]),
        Route("/api/subscriptions/{item_id}", get_subscription, methods=["GET"]),
        Route("/api/deployments/{item_id}/subscription", get_deployment_subscription, methods=["GET"]),
        Route("/api/jobs/{item_id}", get_job, methods=["GET"]),
        Route("/sub/links/{token}", render_subscription, methods=["GET"]),
        Route("/sub/deployments/{token}", render_deployment_subscription, methods=["GET"]),
        Route("/sub/chains/{token}", render_chain_subscription, methods=["GET"]),
        Route("/api/servers", mutation_endpoint("create_server"), methods=["POST"]),
        Route("/api/subscriptions", mutation_endpoint("create_subscription"), methods=["POST"]),
        Route("/api/chains", mutation_endpoint("create_chain"), methods=["POST"]),
        Route("/api/chains/{item_id}/deploy", mutation_endpoint("deploy_chain"), methods=["POST"]),
        Route("/api/settings", update_web_settings, methods=["PATCH"]),
        Route("/api/servers/{item_id}/test", mutation_endpoint("test_server"), methods=["POST"]),
        Route(
            "/api/servers/{item_id}/host-key/approve",
            mutation_endpoint("approve_host_key"),
            methods=["POST"],
        ),
        Route(
            "/api/servers/{item_id}/host-key/reset",
            mutation_endpoint("reset_host_key"),
            methods=["POST"],
        ),
        Route("/api/servers/{item_id}/deploy", mutation_endpoint("deploy_server"), methods=["POST"]),
        Route("/api/deployments/{item_id}/clients", mutation_endpoint("create_client"), methods=["POST"]),
        Route("/api/clients/{item_id}/reset", mutation_endpoint("reset_client"), methods=["POST"]),
        Route(
            "/api/subscriptions/{item_id}/rotate-token",
            mutation_endpoint("rotate_subscription_token"),
            methods=["POST"],
        ),
        Route(
            "/api/chains/{item_id}/rotate-token",
            mutation_endpoint("rotate_chain_token"),
            methods=["POST"],
        ),
        Route("/api/clients/{item_id}", mutation_endpoint("update_client"), methods=["PATCH"]),
        Route("/api/subscriptions/{item_id}", mutation_endpoint("update_subscription"), methods=["PATCH"]),
        Route(
            "/api/deployments/{item_id}/subscription",
            mutation_endpoint("update_deployment_subscription"),
            methods=["PATCH"],
        ),
        Route("/api/servers/{item_id}", mutation_endpoint("delete_server"), methods=["DELETE"]),
        Route(
            "/api/deployments/{item_id}",
            mutation_endpoint("delete_deployment"),
            methods=["DELETE"],
        ),
        Route(
            "/api/subscriptions/{item_id}",
            mutation_endpoint("delete_subscription"),
            methods=["DELETE"],
        ),
        Route("/api/chains/{item_id}", mutation_endpoint("delete_chain"), methods=["DELETE"]),
        Route("/static/{path:path}", static_file, methods=["GET"]),
        Route("/{path:path}", spa, methods=["GET"]),
    ]
    middleware = [
        Middleware(RuntimeTrustedHostMiddleware),
        Middleware(SecurityHeadersMiddleware),
        Middleware(
            SubscriptionRateLimitMiddleware,
            requests_per_minute=settings.subscription_requests_per_minute,
        ),
        Middleware(ApiAuthenticationMiddleware, auth=auth),
        Middleware(AuditMiddleware, db=db, auth=auth),
    ]
    application = Starlette(routes=routes, middleware=middleware, lifespan=lifespan)
    application.state.settings = settings
    application.state.db = db
    application.state.services = services
    application.state.auth = auth
    application.state.web_config = web_config
    return application


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    try:
        settings = load_settings()
        application = create_app(settings)
    except (ConfigError, RuntimeError) as exc:
        print(f"Configuration error:\n{exc}", flush=True)
        raise SystemExit(1) from exc

    if settings.allow_insecure:
        LOGGER.warning("Running in INSECURE mode (development). Do not expose this to the public internet.")
    if settings.public_access_warning:
        LOGGER.warning(
            "The Web UI is publicly bound without a canonical HTTPS domain; an in-app warning is enabled."
        )
    print(f"Manage Your Node running at http://{settings.host}:{settings.port}", flush=True)
    uvicorn.run(
        application,
        host=settings.host,
        port=settings.port,
        proxy_headers=settings.trust_x_forwarded_for,
        forwarded_allow_ips=settings.trusted_proxy_ips if settings.trust_x_forwarded_for else "",
        server_header=False,
        timeout_keep_alive=5,
        access_log=False,
        timeout_graceful_shutdown=30,
    )


if __name__ == "__main__":
    main()
