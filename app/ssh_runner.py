import io
import socket
import time
from collections.abc import Callable
from typing import Any

import paramiko

from .security import SecretBox


class SshError(RuntimeError):
    pass


class SshRunner:
    def __init__(self, secret_box: SecretBox):
        self.secret_box = secret_box

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
            channel = client.get_transport().open_session()
            channel.settimeout(1.0)
            channel.exec_command(f"{command} 2>&1")
            if stdin is not None:
                channel.sendall(stdin)
                channel.shutdown_write()

            return self._read_channel(channel, log, timeout)
        finally:
            client.close()

    def _connect(self, server: dict[str, Any]) -> paramiko.SSHClient:
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        auth_type = str(server.get("auth_type") or "key")
        secret = self.secret_box.open(server.get("encrypted_secret") or "").strip()
        connect_kwargs: dict[str, Any] = {
            "hostname": server["host"],
            "port": int(server["ssh_port"]),
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
            return client
        except (
            paramiko.AuthenticationException,
            paramiko.BadAuthenticationType,
            paramiko.SSHException,
            socket.timeout,
            OSError,
        ) as exc:
            client.close()
            raise SshError(f"SSH connection failed: {exc}") from exc

    def _parse_private_key(self, secret: str) -> paramiko.PKey:
        key_file = io.StringIO(secret)
        errors: list[str] = []
        for key_class in (
            paramiko.Ed25519Key,
            paramiko.RSAKey,
            paramiko.ECDSAKey,
            paramiko.DSSKey,
        ):
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
