from app.provisioning import (
    SINGBOX_SHA256,
    SINGBOX_VERSION,
    XUI_INSTALL_REF,
    XUI_INSTALL_SHA256,
    XUI_RELEASE_SHA256,
    XUI_RELEASE_VERSION,
    anytls_service_name,
    native_3xui_script,
    native_singbox_script,
    singbox_config_push_script,
    singbox_uninstall_script,
)


def test_native_installer_is_pinned_verified_and_loopback_only():
    script = native_3xui_script(32000, "/panel", "user", "password", "192.0.2.10")
    assert XUI_INSTALL_REF in script
    assert XUI_RELEASE_VERSION in script
    assert XUI_INSTALL_SHA256 in script
    assert XUI_RELEASE_SHA256["amd64"] in script
    assert "/master/install.sh" not in script
    assert "sha256sum --check" in script
    assert "setting -listenIP 127.0.0.1" in script
    assert "XUI_API_TOKEN" in script


def _sample_anytls_config(port: int = 443) -> dict:
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "anytls",
                "tag": "anytls-in",
                "listen": "::",
                "listen_port": port,
                "users": [],
                "tls": {
                    "enabled": True,
                    "certificate_path": "/opt/manage-node/singbox/svc/cert.pem",
                    "key_path": "/opt/manage-node/singbox/svc/key.pem",
                },
            }
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
    }


def test_anytls_service_name_is_deterministic():
    assert anytls_service_name("dep_abc") == "myn-anytls-dep_abc"


def test_native_singbox_installer_is_pinned_and_verified():
    service = anytls_service_name("dep_test")
    script = native_singbox_script(
        service_name=service,
        config=_sample_anytls_config(),
        proxy_port=443,
        server_host="192.0.2.10",
        self_signed=True,
    )
    assert SINGBOX_VERSION in script
    assert SINGBOX_SHA256["amd64"] in script
    assert "releases/download/v$SB_VERSION" in script
    assert "sha256sum --check" in script
    assert "sing-box check" in script
    assert "openssl req -x509" in script
    assert f"/etc/systemd/system/{service}.service" in script


def test_native_singbox_installer_acme_skips_self_signed():
    script = native_singbox_script(
        service_name=anytls_service_name("dep_acme"),
        config=_sample_anytls_config(),
        proxy_port=443,
        server_host="192.0.2.10",
        self_signed=False,
    )
    assert "openssl req -x509" not in script
    assert "sha256sum --check" in script


def test_singbox_config_push_script_validates_and_restarts():
    service = anytls_service_name("dep_push")
    script = singbox_config_push_script(service, _sample_anytls_config())
    assert "sing-box check" in script
    assert f"systemctl restart {service}" in script


def test_singbox_uninstall_script_removes_unit_and_dir():
    service = anytls_service_name("dep_rm")
    script = singbox_uninstall_script(service)
    assert f"SERVICE_NAME={service}" in script
    assert f"/opt/manage-node/singbox/{service}" in script
    assert 'rm -f "$UNIT_FILE"' in script
