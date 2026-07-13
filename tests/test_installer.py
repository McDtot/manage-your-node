from pathlib import Path


ROOT = Path(__file__).parents[1]


def test_installer_has_safe_idempotent_defaults():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")

    assert "set -Eeuo pipefail" in script
    assert "umask 077" in script
    assert "if [[ ! -s secrets/app_secret.txt ]]" in script
    assert "if [[ ! -s secrets/admin_password.txt ]]" in script
    assert "if [[ ! -f .env ]]" in script
    assert '"${COMPOSE[@]}" up --build -d' in script
    assert "api/health/ready" in script
    assert "docker compose down -v" not in script
    assert "rm -rf" not in script


def test_installer_does_not_accept_password_on_command_line():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")

    assert "--admin-password-file" in script
    assert "--admin-password " not in script
