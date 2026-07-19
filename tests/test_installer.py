from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_installer_has_safe_idempotent_defaults():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")

    assert "set -Eeuo pipefail" in script
    assert "umask 077" in script
    assert "if [[ ! -s secrets/app_secret.txt ]]" in script
    assert "if [[ ! -s secrets/admin_password.txt ]]" in script
    assert "chmod 700 secrets" in script
    assert "chmod 0444 secrets/app_secret.txt secrets/admin_password.txt" in script
    assert "if [[ ! -f .env ]]" in script
    assert "existing_data_volumes()" in script
    assert "label=com.docker.compose.volume=manage-node-data" in script
    assert '"${COMPOSE[@]}" build' in script
    assert "python -m app.maintenance check" in script
    assert '"${COMPOSE[@]}" up -d' in script
    assert "api/health/ready" in script
    assert 'logs --no-color --tail=100 manage-your-node' in script
    assert "docker compose down -v" not in script
    assert "rm -rf" not in script

    build_at = script.index('"${COMPOSE[@]}" build')
    check_at = script.index("python -m app.maintenance check")
    start_at = script.index('"${COMPOSE[@]}" up -d')
    assert build_at < check_at < start_at


def test_installer_does_not_accept_password_on_command_line():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")

    assert "--admin-password-file" in script
    assert "--admin-password " not in script


def test_installer_prompts_for_and_confirms_new_admin_password_securely():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")

    assert "prompt_admin_password()" in script
    assert "请设置管理员密码" in script
    assert "请再次输入管理员密码" in script
    assert script.count("IFS= read -r -s") == 2
    assert "[[ -t 0" in script
    assert "< /dev/tty" in script
    assert 'PASSWORD_SOURCE="prompted"' in script
    assert "未检测到交互式终端，将生成随机管理员密码" in script


def test_installer_uses_official_docker_repositories():
    script = (ROOT / "install.sh").read_text(encoding="utf-8")

    assert 'if ! command -v docker >/dev/null 2>&1' in script
    assert 'ubuntu|debian)' in script
    assert 'fedora|centos|rhel)' in script
    assert "https://download.docker.com/linux/$distro/gpg" in script
    assert "docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin" in script
    assert "systemctl enable --now docker" in script
    assert "https://get.docker.com" not in script
