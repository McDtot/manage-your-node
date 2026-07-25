import pytest

from app.provisioning import (
    SINGBOX_SHA256,
    SINGBOX_VERSION,
    TLS_CERT_SHA256_MARKER,
    chain_service_name,
    node_service_name,
    singbox_config_push_script,
    singbox_install_script,
    singbox_uninstall_script,
    tls_cert_sha256_from_output,
)


def _sample_config(port: int = 443) -> dict:
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
                "type": "anytls",
                "tag": "node-in",
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
        "route": {"final": "direct"},
    }


def test_node_and_chain_service_names_are_deterministic():
    assert node_service_name("dep_abc") == "myn-node-dep_abc"
    assert chain_service_name("chn_abc", 2) == "myn-chain-chn_abc-2"


def test_singbox_installer_is_pinned_and_verified():
    service = node_service_name("dep_test")
    script = singbox_install_script(
        service_name=service,
        config=_sample_config(),
        proxy_port=443,
        server_host="192.0.2.10",
        self_signed_cert=True,
    )
    assert SINGBOX_VERSION in script
    assert SINGBOX_SHA256["amd64"] in script
    assert "releases/download/v$SB_VERSION" in script
    assert "sha256sum --check" in script
    assert "sing-box check" in script
    assert "openssl req -x509" in script
    assert "openssl x509" in script
    assert TLS_CERT_SHA256_MARKER in script
    assert f"/etc/systemd/system/{service}.service" in script


def test_tls_certificate_fingerprint_is_parsed_and_validated():
    fingerprint = ":".join(["A1"] * 32)
    assert tls_cert_sha256_from_output(
        ["installing", f"{TLS_CERT_SHA256_MARKER}{fingerprint}", "ready"]
    ) == fingerprint
    assert tls_cert_sha256_from_output(["installing", "ready"]) == ""

    with pytest.raises(ValueError, match="invalid TLS certificate fingerprint"):
        tls_cert_sha256_from_output([f"{TLS_CERT_SHA256_MARKER}not-a-fingerprint"])


def test_singbox_installer_acme_skips_self_signed_and_opens_http():
    script = singbox_install_script(
        service_name=node_service_name("dep_acme"),
        config=_sample_config(),
        proxy_port=443,
        server_host="192.0.2.10",
        self_signed_cert=False,
        acme_http_port=80,
    )
    assert "openssl req -x509" not in script
    assert "ufw allow 80/tcp" in script


def test_singbox_installer_can_allow_udp_for_shadowsocks():
    script = singbox_install_script(
        service_name=node_service_name("dep_ss"),
        config=_sample_config(8388),
        proxy_port=8388,
        server_host="192.0.2.10",
        allow_udp=True,
    )
    assert "ufw allow 8388/udp" in script


def test_singbox_config_push_script_validates_and_restarts():
    service = node_service_name("dep_push")
    script = singbox_config_push_script(service, _sample_config())
    assert "sing-box check" in script
    assert f"systemctl restart {service}" in script


def test_singbox_uninstall_script_removes_unit_and_dir():
    service = node_service_name("dep_rm")
    script = singbox_uninstall_script(service)
    assert f"SERVICE_NAME={service}" in script or f"SERVICE_NAME='{service}'" in script
    assert f"/opt/manage-node/singbox/{service}" in script
    assert 'rm -f "$UNIT_FILE"' in script
