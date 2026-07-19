import base64
import hashlib
import io
import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

import paramiko

from .security import SecretBox


def _build_host_key_classes() -> dict[str, type]:
    mapping: dict[str, str] = {
        "ssh-ed25519": "Ed25519Key",
        "ssh-rsa": "RSAKey",
        "rsa-sha2-256": "RSAKey",
        "rsa-sha2-512": "RSAKey",
        "ecdsa-sha2-nistp256": "ECDSAKey",
        "ecdsa-sha2-nistp384": "ECDSAKey",
        "ecdsa-sha2-nistp521": "ECDSAKey",
        "ssh-dss": "DSSKey",
    }
    classes: dict[str, type] = {}
    for key_type, attr in mapping.items():
        cls = getattr(paramiko, attr, None)
        if cls is not None:
            classes[key_type] = cls
    return classes


_HOST_KEY_CLASSES = _build_host_key_classes()


def _private_key_classes() -> tuple[type[paramiko.PKey], ...]:
    names = ("Ed25519Key", "RSAKey", "ECDSAKey", "DSSKey")
    return tuple(getattr(paramiko, name) for name in names if getattr(paramiko, name, None))


def _fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


class SshError(RuntimeError):
    pass


class _HostKeyApprovalRequired(RuntimeError):
    def __init__(self, key: paramiko.PKey):
        super().__init__("SSH host key approval required")
        self.key = key


class _CaptureHostKeyPolicy(paramiko.MissingHostKeyPolicy):
    """Trust-on-first-use policy that records the presented key for later storage.

    We only persist the key after the connection (including authentication)
    fully succeeds, so a failed handshake never pins an attacker's key.
    """

    def __init__(self) -> None:
        self.captured: paramiko.PKey | None = None

    def missing_host_key(self, client, hostname, key):  # noqa: ANN001
        self.captured = key
        raise _HostKeyApprovalRequired(key)


class SshRunner:
    def __init__(self, secret_box: SecretBox, db: Any = None):
        self.secret_box = secret_box
        self.db = db

    def probe(self, server: dict[str, Any]) -> tuple[bool, str]:
        try:
            output = self.run_command(server, "printf 'os='; uname -s; printf 'arch='; uname -m", 15)
            return True, output.strip()
        except Exception as exc:  # noqa: BLE001
            return False, str(exc)

    def run_script(
        self,
        server: dict[str, Any],
        script: str,
        log: Callable[[str], None],
        timeout: int = 900,
    ) -> list[str]:
        return self._run(server, ["bash", "-s"], script, log, timeout)

    def run_command(self, server: dict[str, Any], command: str, timeout: int = 30) -> str:
        lines = self._run(server, [command], None, lambda _: None, timeout)
        return "\n".join(lines)

    def connect(self, server: dict[str, Any]) -> paramiko.SSHClient:
        """Public entry point so callers (e.g. SSH tunnels) can reuse a client."""
        return self._connect(server)

    def _run(
        self,
        server: dict[str, Any],
        remote_args: list[str],
        stdin: str | None,
        log: Callable[[str], None],
        timeout: int,
    ) -> list[str]:
        command = " ".join(remote_args)
        client = self._connect(server)
        try:
            transport = client.get_transport()
            if transport is None:
                raise SshError("SSH connection lost before the command could start")
            channel = transport.open_session()
            channel.settimeout(1.0)
            channel.exec_command(f"{command} 2>&1")
            if stdin is not None:
                channel.sendall(stdin.encode("utf-8"))
                channel.shutdown_write()

            return self._read_channel(channel, log, timeout)
        finally:
            client.close()

    def _server_id(self, server: dict[str, Any]) -> str:
        return str(server.get("id") or server.get("server_id") or "")

    def _hostkey_name(self, hostname: str, port: int) -> str:
        return hostname if port == 22 else f"[{hostname}]:{port}"

    def _load_host_key(self, server_id: str) -> dict[str, Any] | None:
        if not self.db or not server_id:
            return None
        return self.db.query_one(
            "SELECT key_type, key_base64, fingerprint, trusted FROM ssh_host_keys WHERE server_id = ?",
            (server_id,),
        )

    def _store_host_key(self, server_id: str, key: paramiko.PKey, trusted: bool = False) -> None:
        if not self.db or not server_id:
            return
        self.db.execute(
            """
            INSERT OR REPLACE INTO ssh_host_keys (
                server_id, key_type, key_base64, fingerprint, trusted, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                server_id,
                key.get_name(),
                key.get_base64(),
                _fingerprint(key),
                1 if trusted else 0,
                datetime.now(UTC).isoformat(timespec="seconds"),
            ),
        )

    def _connect(self, server: dict[str, Any]) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        hostname = server["host"]
        port = int(server["ssh_port"])
        server_id = self._server_id(server)
        stored = self._load_host_key(server_id)

        capture: _CaptureHostKeyPolicy | None = None
        if stored:
            if not bool(stored.get("trusted")):
                raise SshError(
                    "SSH host key is awaiting approval: "
                    f"{stored['fingerprint']}. Verify it out of band, then approve it in the panel."
                )
            entry_name = self._hostkey_name(hostname, port)
            try:
                key_cls = _HOST_KEY_CLASSES.get(stored["key_type"])
                if not key_cls:
                    raise SshError(f"Unsupported stored host key type: {stored['key_type']}")
                key_obj = key_cls(data=base64.b64decode(stored["key_base64"]))
                client.get_host_keys().add(entry_name, stored["key_type"], key_obj)
            except SshError:
                raise
            except Exception as exc:  # noqa: BLE001
                raise SshError(f"Could not load stored host key: {exc}") from exc
            client.set_missing_host_key_policy(paramiko.RejectPolicy())
        elif self.db and server_id:
            capture = _CaptureHostKeyPolicy()
            client.set_missing_host_key_policy(capture)
        else:
            raise SshError(
                "SSH host-key verification requires a database-backed server record."
            )

        auth_type = str(server.get("auth_type") or "key")
        secret = self.secret_box.open(server.get("encrypted_secret") or "").strip()
        connect_kwargs: dict[str, Any] = {
            "hostname": hostname,
            "port": port,
            "username": server["ssh_user"],
            "timeout": 10,
            "banner_timeout": 15,
            "auth_timeout": 20,
        }

        if auth_type == "password":
            if not secret:
                raise SshError("Password auth selected but password is empty.")
            connect_kwargs.update(
                {
                    "password": secret,
                    "look_for_keys": False,
                    "allow_agent": False,
                }
            )
        elif auth_type == "agent":
            connect_kwargs.update({"look_for_keys": True, "allow_agent": True})
        else:
            pkey = self._parse_private_key(secret) if secret else None
            connect_kwargs.update(
                {
                    "pkey": pkey,
                    "look_for_keys": pkey is None,
                    "allow_agent": True,
                }
            )

        try:
            client.connect(**connect_kwargs)
        except _HostKeyApprovalRequired as exc:
            client.close()
            self._store_host_key(server_id, exc.key, trusted=False)
            raise SshError(
                "New SSH host key requires approval: "
                f"{_fingerprint(exc.key)}. Verify this fingerprint through your VPS provider "
                "before approving it in the panel."
            ) from exc
        except paramiko.BadHostKeyException as exc:
            client.close()
            expected_fp = _fingerprint(exc.expected_key)
            got_fp = _fingerprint(exc.key)
            raise SshError(
                "SSH host key verification failed: the server presented a key that does not "
                f"match the pinned one for this host (expected {expected_fp}, got {got_fp}). "
                "This may indicate a man-in-the-middle attack. If the host was legitimately "
                "reinstalled, remove its stored host key and re-test the connection."
            ) from exc
        except (TimeoutError, paramiko.AuthenticationException, paramiko.BadAuthenticationType, paramiko.SSHException, OSError) as exc:
            client.close()
            raise SshError(f"SSH connection failed: {exc}") from exc

        return client

    def _parse_private_key(self, secret: str) -> paramiko.PKey:
        key_file = io.StringIO(secret)
        errors: list[str] = []
        for key_class in _private_key_classes():
            key_file.seek(0)
            try:
                return key_class.from_private_key(key_file)
            except Exception as exc:  # noqa: BLE001
                errors.append(str(exc))
        raise SshError("Could not parse SSH private key. Encrypted keys are not supported yet.")

    def _read_channel(
        self,
        channel: paramiko.Channel,
        log: Callable[[str], None],
        timeout: int,
    ) -> list[str]:
        deadline = time.monotonic() + timeout
        buffer = ""
        lines: list[str] = []

        while True:
            if time.monotonic() > deadline:
                channel.close()
                raise SshError(f"SSH command timed out after {timeout}s")

            if channel.recv_ready():
                chunk = channel.recv(4096).decode("utf-8", errors="replace")
                buffer += chunk
                buffer = self._drain_lines(buffer, lines, log)

            if channel.exit_status_ready():
                while channel.recv_ready():
                    chunk = channel.recv(4096).decode("utf-8", errors="replace")
                    buffer += chunk
                    buffer = self._drain_lines(buffer, lines, log)
                break

            time.sleep(0.1)

        if buffer:
            clean = buffer.rstrip()
            if clean:
                lines.append(clean)
                log(clean)

        code = channel.recv_exit_status()
        if code != 0:
            tail = "\n".join(lines[-12:])
            raise SshError(f"SSH command failed with exit code {code}\n{tail}")
        return lines

    def _drain_lines(
        self,
        buffer: str,
        lines: list[str],
        log: Callable[[str], None],
    ) -> str:
        while "\n" in buffer:
            line, buffer = buffer.split("\n", 1)
            clean = line.rstrip()
            lines.append(clean)
            if clean:
                log(clean)
        return buffer
