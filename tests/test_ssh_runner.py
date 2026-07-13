import pytest

from app.security import SecretBox
from app.ssh_runner import SshError, SshRunner


def test_runner_without_database_cannot_bypass_host_key_verification():
    runner = SshRunner(SecretBox("a-sufficiently-long-test-secret"))
    server = {
        "id": "server-1",
        "host": "192.0.2.10",
        "ssh_port": 22,
        "ssh_user": "deploy",
        "auth_type": "agent",
        "encrypted_secret": "",
    }

    with pytest.raises(SshError, match="database-backed server record"):
        runner.connect(server)
