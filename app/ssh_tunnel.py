import select
import threading
from socketserver import BaseRequestHandler, ThreadingTCPServer
from typing import Any

import paramiko


class _ForwardServer(ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_handler(transport: paramiko.Transport, remote_host: str, remote_port: int):
    class Handler(BaseRequestHandler):
        def handle(self) -> None:
            try:
                channel = transport.open_channel(
                    "direct-tcpip",
                    (remote_host, remote_port),
                    self.request.getpeername(),
                )
            except Exception:  # noqa: BLE001
                return
            if channel is None:
                return
            try:
                while True:
                    readable, _, _ = select.select([self.request, channel], [], [])
                    if self.request in readable:
                        data = self.request.recv(4096)
                        if not data:
                            break
                        channel.sendall(data)
                    if channel in readable:
                        data = channel.recv(4096)
                        if not data:
                            break
                        self.request.sendall(data)
            finally:
                channel.close()
                self.request.close()

    return Handler


class SshTunnel:
    """Local port forward over an SSH transport.

    Opens ``127.0.0.1:<local_port>`` and forwards every connection to
    ``remote_host:remote_port`` as seen from the SSH server, so panel/API
    traffic stays inside the encrypted SSH channel instead of crossing the
    public network in plaintext.
    """

    def __init__(
        self,
        ssh_runner: Any,
        server: dict[str, Any],
        remote_host: str,
        remote_port: int,
    ):
        self._ssh_runner = ssh_runner
        self._server = server
        self._remote_host = remote_host
        self._remote_port = int(remote_port)
        self._client: paramiko.SSHClient | None = None
        self._forward: _ForwardServer | None = None
        self._thread: threading.Thread | None = None

    def __enter__(self) -> int:
        self._client = self._ssh_runner.connect(self._server)
        transport = self._client.get_transport()
        if transport is None:
            self._client.close()
            raise RuntimeError("SSH transport unavailable for tunnel")
        handler = _make_handler(transport, self._remote_host, self._remote_port)
        self._forward = _ForwardServer(("127.0.0.1", 0), handler)
        self._thread = threading.Thread(target=self._forward.serve_forever, daemon=True)
        self._thread.start()
        return self._forward.server_address[1]

    def __exit__(self, *_exc: object) -> None:
        if self._forward is not None:
            self._forward.shutdown()
            self._forward.server_close()
            self._forward = None
        if self._client is not None:
            self._client.close()
            self._client = None
