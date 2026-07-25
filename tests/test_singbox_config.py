import base64

import pytest

from app.provisioning import node_service_name, singbox_acme_dir, singbox_cert_paths
from app.services.singbox import (
    build_chain_config,
    build_node_config,
    chain_inbound,
    chain_outbound,
    new_reality_keypair,
    new_short_id,
)


def _decode_raw_key(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _vless_deployment(**overrides):
    deployment = {
        "id": "dep_vless",
        "protocol": "VLESS + REALITY",
        "proxy_port": 443,
        "reality_dest": "www.apple.com:443",
        "reality_sni": "www.apple.com",
        "reality_private_key": "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
        "reality_short_id": "a1b2c3d4",
    }
    deployment.update(overrides)
    return deployment


def _ss_deployment(**overrides):
    deployment = {
        "id": "dep_ss",
        "protocol": "Shadowsocks 2022",
        "proxy_port": 8443,
        "ss_method": "2022-blake3-aes-256-gcm",
        "ss_password": "c2VydmVyLXBzay1iYXNlNjQtdmFsdWUtaGVyZQ==",
    }
    deployment.update(overrides)
    return deployment


def _anytls_deployment(**overrides):
    deployment = {
        "id": "dep_anytls",
        "protocol": "AnyTLS",
        "proxy_port": 443,
        "anytls_domain": "",
    }
    deployment.update(overrides)
    return deployment


def test_reality_keypair_is_raw_url_base64_x25519():
    private_key, public_key = new_reality_keypair()

    assert private_key != public_key
    assert "=" not in private_key and "=" not in public_key
    assert len(_decode_raw_key(private_key)) == 32
    assert len(_decode_raw_key(public_key)) == 32
    assert new_reality_keypair()[0] != private_key


def test_short_id_is_eight_hex_digits():
    short_id = new_short_id()

    assert len(short_id) == 8
    int(short_id, 16)


def test_vless_reality_node_config_carries_handshake_and_flow():
    config = build_node_config(
        _vless_deployment(),
        [{"name": "alice", "uuid": "bf000d23-0752-40b4-affe-68f7707a9661"}],
    )

    inbound = config["inbounds"][0]
    assert inbound["type"] == "vless"
    assert inbound["listen_port"] == 443
    assert inbound["users"] == [
        {
            "name": "alice",
            "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
            "flow": "xtls-rprx-vision",
        }
    ]
    tls = inbound["tls"]
    assert tls["server_name"] == "www.apple.com"
    assert tls["reality"]["handshake"] == {
        "server": "www.apple.com",
        "server_port": 443,
    }
    assert tls["reality"]["short_id"] == ["a1b2c3d4"]
    assert config["route"]["final"] == "direct"


def test_vless_reality_requires_persisted_keys():
    with pytest.raises(ValueError, match="private key"):
        build_node_config(_vless_deployment(reality_private_key=""), [])
    with pytest.raises(ValueError, match="short id"):
        build_node_config(_vless_deployment(reality_short_id=""), [])


def test_shadowsocks_node_config_uses_multi_user_layout():
    config = build_node_config(
        _ss_deployment(),
        [{"name": "alice", "password": "dXNlci1wc2s="}],
    )

    inbound = config["inbounds"][0]
    assert inbound["type"] == "shadowsocks"
    assert inbound["method"] == "2022-blake3-aes-256-gcm"
    assert inbound["password"] == "c2VydmVyLXBzay1iYXNlNjQtdmFsdWUtaGVyZQ=="
    assert inbound["users"] == [{"name": "alice", "password": "dXNlci1wc2s="}]


def test_shadowsocks_requires_server_password():
    with pytest.raises(ValueError, match="server password"):
        build_node_config(_ss_deployment(ss_password=""), [])


def test_anytls_self_signed_config_points_at_local_certificate():
    deployment = _anytls_deployment()
    config = build_node_config(deployment, [{"name": "alice", "password": "pw"}])

    tls = config["inbounds"][0]["tls"]
    certificate_path, key_path = singbox_cert_paths(node_service_name("dep_anytls"))
    assert tls["certificate_path"] == certificate_path
    assert tls["key_path"] == key_path
    assert "acme" not in tls


def test_anytls_domain_switches_to_acme():
    config = build_node_config(
        _anytls_deployment(anytls_domain="vpn.example.com"),
        [{"name": "alice", "password": "pw"}],
    )

    tls = config["inbounds"][0]["tls"]
    assert tls["server_name"] == "vpn.example.com"
    assert tls["acme"] == {
        "domain": ["vpn.example.com"],
        "data_directory": singbox_acme_dir(node_service_name("dep_anytls")),
    }
    assert "certificate_path" not in tls


def test_unsupported_protocol_is_rejected():
    with pytest.raises(ValueError, match="unsupported deployment protocol"):
        build_node_config({"id": "dep_x", "protocol": "Trojan", "proxy_port": 443}, [])


def _chain_node(position, protocol, **overrides):
    node = {
        "position": position,
        "server_name": f"node-{position}",
        "host": f"10.0.0.{position + 1}",
        "inbound_protocol": protocol,
        "inbound_port": 40000 + position,
        "node_client_uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
        "private_key": "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc",
        "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
        "short_id": "0123abcd",
        "ss_method": "2022-blake3-aes-256-gcm",
        "ss_password": "Y2hhaW4tcHNr",
        "reality_dest": "www.apple.com:443",
        "reality_sni": "www.apple.com",
    }
    node.update(overrides)
    return node


def test_chain_reality_inbound_and_outbound_pair_up():
    entry = _chain_node(0, "vless_reality")
    relay = _chain_node(1, "vless_reality")

    inbound = chain_inbound(entry)
    outbound = chain_outbound(relay)

    assert inbound["type"] == "vless"
    assert inbound["users"][0]["name"] == "myn-chain-0"
    assert inbound["tls"]["reality"]["private_key"] == entry["private_key"]
    assert outbound["type"] == "vless"
    assert outbound["server"] == relay["host"]
    assert outbound["server_port"] == relay["inbound_port"]
    assert outbound["tls"]["reality"]["public_key"] == relay["public_key"]
    assert outbound["tls"]["reality"]["short_id"] == relay["short_id"]
    assert outbound["tls"]["utls"] == {"enabled": True, "fingerprint": "chrome"}


def test_chain_shadowsocks_hop_uses_single_password():
    node = _chain_node(1, "shadowsocks_2022")

    inbound = chain_inbound(node)
    outbound = chain_outbound(node)

    assert inbound["type"] == "shadowsocks"
    assert inbound["password"] == "Y2hhaW4tcHNr"
    assert "users" not in inbound
    assert outbound["type"] == "shadowsocks"
    assert outbound["password"] == "Y2hhaW4tcHNr"


def test_chain_exit_node_routes_to_direct():
    config = build_chain_config(_chain_node(2, "vless_reality"), None)

    assert config["outbounds"] == [{"type": "direct", "tag": "direct"}]
    assert config["route"]["final"] == "direct"


def test_chain_relay_routes_to_next_hop():
    config = build_chain_config(
        _chain_node(0, "vless_reality"),
        _chain_node(1, "shadowsocks_2022"),
    )

    assert config["route"]["final"] == "myn-chain-next"
    assert config["outbounds"][0]["tag"] == "myn-chain-next"


def test_chain_rejects_unknown_protocol():
    with pytest.raises(ValueError, match="unsupported chain protocol"):
        chain_inbound(_chain_node(0, "trojan"))
    with pytest.raises(ValueError, match="unsupported chain protocol"):
        chain_outbound(_chain_node(1, "tuic"))


def test_hysteria2_node_config_uses_obfs_and_tls():
    deployment = {
        "id": "dep_hy2",
        "protocol": "Hysteria2",
        "proxy_port": 443,
        "anytls_domain": "",
        "hy2_obfs_password": "obfs-secret",
    }
    config = build_node_config(
        deployment,
        [{"name": "alice", "password": "user-pass"}],
    )
    inbound = config["inbounds"][0]
    assert inbound["type"] == "hysteria2"
    assert inbound["users"] == [{"name": "alice", "password": "user-pass"}]
    assert inbound["obfs"] == {"type": "salamander", "password": "obfs-secret"}
    assert inbound["tls"]["alpn"] == ["h3"]
    assert "certificate_path" in inbound["tls"]


def test_vmess_node_config_uses_tls_and_alter_id_zero():
    deployment = {
        "id": "dep_vmess",
        "protocol": "VMess",
        "proxy_port": 443,
        "anytls_domain": "vpn.example.com",
    }
    config = build_node_config(
        deployment,
        [{"name": "alice", "uuid": "bf000d23-0752-40b4-affe-68f7707a9661"}],
    )
    inbound = config["inbounds"][0]
    assert inbound["type"] == "vmess"
    assert inbound["users"] == [
        {
            "name": "alice",
            "uuid": "bf000d23-0752-40b4-affe-68f7707a9661",
            "alterId": 0,
        }
    ]
    assert inbound["tls"]["server_name"] == "vpn.example.com"
    assert "acme" in inbound["tls"]


def test_chain_hysteria2_hop_uses_self_signed_tls():
    node = _chain_node(
        1,
        "hysteria2",
        hy2_password="hop-pass",
        remote_service_name="myn-chain-test-1",
    )
    inbound = chain_inbound(node)
    outbound = chain_outbound(node)

    assert inbound["type"] == "hysteria2"
    assert inbound["users"][0]["password"] == "hop-pass"
    assert inbound["tls"]["alpn"] == ["h3"]
    assert inbound["tls"]["certificate_path"].endswith("cert.pem")
    assert outbound["type"] == "hysteria2"
    assert outbound["password"] == "hop-pass"
    assert outbound["tls"]["insecure"] is True


def test_chain_vmess_hop_uses_uuid_without_tls():
    node = _chain_node(1, "vmess")
    inbound = chain_inbound(node)
    outbound = chain_outbound(node)

    assert inbound["type"] == "vmess"
    assert inbound["users"][0]["uuid"] == node["node_client_uuid"]
    assert inbound["users"][0]["alterId"] == 0
    assert "tls" not in inbound
    assert outbound["type"] == "vmess"
    assert outbound["uuid"] == node["node_client_uuid"]
    assert outbound["alter_id"] == 0
    assert "tls" not in outbound
