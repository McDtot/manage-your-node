from app.provisioning import (
    XUI_INSTALL_REF,
    XUI_INSTALL_SHA256,
    XUI_RELEASE_SHA256,
    XUI_RELEASE_VERSION,
    native_3xui_script,
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
