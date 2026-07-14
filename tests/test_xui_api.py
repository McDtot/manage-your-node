from app.xui_api import XuiApiClient


def test_create_client_sends_traffic_reset_period(monkeypatch):
    client = XuiApiClient(
        base_url="https://127.0.0.1:32000/panel-path/",
        username="admin",
        password="password",
    )
    payloads = []

    def fake_post_json(path, payload, use_auth=True):
        payloads.append((path, payload, use_auth))
        return {"success": True}

    monkeypatch.setattr(client, "post_json", fake_post_json)
    monkeypatch.setattr(
        client,
        "get_json",
        lambda _path: {"success": True, "obj": []},
    )

    client.create_client(
        inbound_id=42,
        email="periodic-user",
        client_uuid="client-uuid",
        sub_id="subscription-id",
        quota_bytes=100 * 1024**3,
        expires_ms=1_900_000_000_000,
        reset_days=30,
    )

    assert payloads[0][0] == "panel/api/clients/add"
    assert payloads[0][1]["client"]["reset"] == 30


def test_reset_client_traffic_uses_inbound_api_route(monkeypatch):
    client = XuiApiClient(
        base_url="https://127.0.0.1:32000/panel-path/",
        username="admin",
        password="password",
    )
    calls = []

    def fake_post_json(path, payload, use_auth=True):
        calls.append((path, payload, use_auth))
        return {"success": True}

    monkeypatch.setattr(client, "post_json", fake_post_json)

    client.reset_client_traffic(42, "alice+reset@example.com")

    assert calls == [
        (
            "panel/api/inbounds/42/resetClientTraffic/alice%2Breset%40example.com",
            {},
            True,
        )
    ]
