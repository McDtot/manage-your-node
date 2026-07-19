import base64
import binascii
import hashlib
import hmac
import json
import secrets
import threading
import time
from datetime import UTC, datetime
from typing import Any


class AuthManager:

    def __init__(
        self,
        app_secret: str,
        admin_username: str,
        admin_password: str,
        session_seconds: int,
        max_attempts: int = 5,
        window_seconds: int = 300,
        lockout_seconds: int = 900,
        db: Any = None,
        cookie_name: str = "myn_session",
    ):
        self.admin_username = admin_username
        self.admin_password = admin_password
        self.session_seconds = session_seconds
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self.lockout_seconds = lockout_seconds
        self.db = db
        self.cookie_name = cookie_name
        self._key = hashlib.sha256(f"auth:{app_secret}".encode()).digest()
        self._csrf_key = hashlib.sha256(f"csrf:{app_secret}".encode()).digest()
        self._failures: dict[str, list[float]] = {}
        self._locked_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def lockout_remaining(self, client_key: str) -> int:
        """Return seconds the client must wait, or 0 if not currently locked."""
        now = self._now()
        if self.db is not None:
            row = self.db.query_one(
                "SELECT locked_until FROM login_rate_limits WHERE client_key = ?",
                (client_key,),
            )
            if not row:
                return 0
            remaining = max(0, int(float(row["locked_until"]) - now))
            if remaining == 0:
                self.db.execute("DELETE FROM login_rate_limits WHERE client_key = ?", (client_key,))
            return remaining
        with self._lock:
            unlock_at = self._locked_until.get(client_key, 0)
            if unlock_at <= now:
                self._locked_until.pop(client_key, None)
                return 0
            return max(0, int(unlock_at - now))

    def register_failure(self, client_key: str) -> None:
        now = self._now()
        if self.db is not None:
            with self.db.transaction():
                row = self.db.query_one(
                    "SELECT failures, locked_until FROM login_rate_limits WHERE client_key = ?",
                    (client_key,),
                )
                attempts = self._decode_failures(row.get("failures") if row else None)
                attempts = [ts for ts in attempts if ts >= now - self.window_seconds]
                attempts.append(now)
                locked_until = float(row.get("locked_until") or 0) if row else 0
                if len(attempts) >= self.max_attempts:
                    locked_until = max(locked_until, now + self.lockout_seconds)
                self.db.execute(
                    """
                    INSERT INTO login_rate_limits (client_key, failures, locked_until, updated_at)
                    VALUES (?, ?, ?, ?)
                    ON CONFLICT(client_key) DO UPDATE SET
                        failures = excluded.failures,
                        locked_until = excluded.locked_until,
                        updated_at = excluded.updated_at
                    """,
                    (
                        client_key,
                        json.dumps(attempts),
                        locked_until,
                        datetime.now(UTC).isoformat(timespec="seconds"),
                    ),
                )
            return
        with self._lock:
            attempts = self._recent(client_key, now)
            attempts.append(now)
            self._failures[client_key] = attempts
            if len(attempts) >= self.max_attempts:
                self._locked_until[client_key] = now + self.lockout_seconds

    def register_success(self, client_key: str) -> None:
        if self.db is not None:
            self.db.execute("DELETE FROM login_rate_limits WHERE client_key = ?", (client_key,))
            return
        with self._lock:
            self._failures.pop(client_key, None)
            self._locked_until.pop(client_key, None)

    def _recent(self, client_key: str, now: float) -> list[float]:
        window_start = now - self.window_seconds
        return [ts for ts in self._failures.get(client_key, []) if ts >= window_start]

    def _now(self) -> float:
        return time.time() if self.db is not None else time.monotonic()

    def _decode_failures(self, raw: str | None) -> list[float]:
        try:
            values = json.loads(raw or "[]")
            return [float(value) for value in values]
        except (TypeError, ValueError, json.JSONDecodeError):
            return []

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
        return self.session_payload(token) is not None

    def session_payload(self, token: str | None) -> dict[str, Any] | None:
        if not token or "." not in token:
            return None
        encoded, signature = token.rsplit(".", 1)
        try:
            expected = self._sign(encoded)
            signature_bytes = signature.encode("ascii")
            expected_bytes = expected.encode("ascii")
        except UnicodeEncodeError:
            return None
        if not hmac.compare_digest(signature_bytes, expected_bytes):
            return None
        try:
            payload = json.loads(self._unb64(encoded).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError, ValueError):
            return None
        try:
            expires_at = int(payload.get("exp") or 0)
        except (TypeError, ValueError):
            return None
        if payload.get("u") != self.admin_username or expires_at <= int(time.time()):
            return None
        return payload

    def csrf_token(self, session_token: str) -> str:
        if not self.verify_session(session_token):
            return ""
        digest = hmac.new(self._csrf_key, session_token.encode("ascii"), hashlib.sha256).digest()
        return self._b64(digest)

    def verify_csrf(self, session_token: str, csrf_token: str | None) -> bool:
        expected = self.csrf_token(session_token)
        if not expected or not csrf_token:
            return False
        try:
            return hmac.compare_digest(expected.encode("ascii"), csrf_token.encode("ascii"))
        except UnicodeEncodeError:
            return False

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
