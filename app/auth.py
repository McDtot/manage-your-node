import base64
import binascii
import hashlib
import hmac
import json
import secrets
import threading
import time


class AuthManager:
    cookie_name = "myn_session"

    def __init__(
        self,
        app_secret: str,
        admin_username: str,
        admin_password: str,
        session_seconds: int,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
    ):
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.session_seconds = session_seconds
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self._key = hashlib.sha256(f"auth:{app_secret}".encode("utf-8")).digest()
        self._failures: dict[str, list[float]] = {}
        self._lock = threading.Lock()

    def lockout_remaining(self, client_key: str) -> int:
        """Return seconds the client must wait, or 0 if not currently locked."""
        now = time.monotonic()
        with self._lock:
            attempts = self._recent(client_key, now)
            if len(attempts) < self.max_attempts:
                return 0
            unlock_at = attempts[-1] + self.lockout_seconds
            return max(0, int(unlock_at - now))

    def register_failure(self, client_key: str) -> None:
        now = time.monotonic()
        with self._lock:
            attempts = self._recent(client_key, now)
            attempts.append(now)
            self._failures[client_key] = attempts

    def register_success(self, client_key: str) -> None:
        with self._lock:
            self._failures.pop(client_key, None)

    def _recent(self, client_key: str, now: float) -> list[float]:
        window_start = now - self.window_seconds
        return [ts for ts in self._failures.get(client_key, []) if ts >= window_start]

    def verify_credentials(self, username: str, password: str) -> bool:
        return self._constant_time_equal(username, self.admin_username) and self._constant_time_equal(
            password,
            self.admin_password,
        )

    def issue_session(self) -> str:
        payload = {
            "u": self.admin_username,
            "exp": int(time.time()) + self.session_seconds,
            "n": secrets.token_urlsafe(16),
        }
        raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        encoded = self._b64(raw)
        signature = self._sign(encoded)
        return f"{encoded}.{signature}"

    def verify_session(self, token: str | None) -> bool:
        if not token or "." not in token:
            return False
        encoded, signature = token.rsplit(".", 1)
        try:
            expected = self._sign(encoded)
            signature_bytes = signature.encode("ascii")
            expected_bytes = expected.encode("ascii")
        except UnicodeEncodeError:
            return False
        if not hmac.compare_digest(signature_bytes, expected_bytes):
            return False
        try:
            payload = json.loads(self._unb64(encoded).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return False
        try:
            expires_at = int(payload.get("exp") or 0)
        except (TypeError, ValueError):
            return False
        return payload.get("u") == self.admin_username and expires_at > int(time.time())

    def _constant_time_equal(self, left: str, right: str) -> bool:
        return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))

    def _sign(self, encoded_payload: str) -> str:
        digest = hmac.new(self._key, encoded_payload.encode("ascii"), hashlib.sha256).digest()
        return self._b64(digest)

    def _b64(self, value: bytes) -> str:
        return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")

    def _unb64(self, value: str) -> bytes:
        padding = "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode((value + padding).encode("ascii"))
