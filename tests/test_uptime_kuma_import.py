from app.api import uptime_kuma_import_plan


def test_uptime_kuma_plan_deduplicates_and_skips_groups(monkeypatch):
    monkeypatch.setattr("app.api.get_devices", lambda *args: [{"ip": "192.168.1.10"}])
    payload = {
        "version": "1.23.16",
        "notificationList": [{"password": "must-not-leak"}],
        "monitorList": [
            {"type": "group", "name": "Servers"},
            {
                "type": "ping",
                "name": "Core server",
                "hostname": "192.168.1.10",
                "interval": 30,
                "tags": [{"name": "Servers", "color": "#2563EB"}],
            },
            {
                "type": "port",
                "name": "Core server port",
                "hostname": "192.168.1.10",
                "tags": [{"name": "Production", "color": "#059669"}],
            },
            {"type": "ping", "name": "Camera", "hostname": "192.168.1.20", "tags": []},
            {"type": "http", "name": "Website", "hostname": "example.com"},
        ],
    }

    plan = uptime_kuma_import_plan(payload)

    assert plan["summary"] == {
        "monitors": 5,
        "unique_devices": 2,
        "new_devices": 1,
        "existing_devices": 1,
        "duplicates": 1,
        "invalid_hosts": 0,
        "skipped_monitors": 2,
    }
    existing = next(device for device in plan["devices"] if device["ip"] == "192.168.1.10")
    assert existing["existing"] is True
    assert existing["category"] == "Servers"
    assert existing["tags"] == ["Production"]
    assert "notificationList" not in plan
    assert "password" not in str(plan)


def test_uptime_kuma_plan_rejects_unrelated_json():
    try:
        uptime_kuma_import_plan({"settings": {}})
    except ValueError as error:
        assert str(error) == "invalid_uptime_kuma_backup"
    else:
        raise AssertionError("unrelated JSON must not be accepted as a Kuma backup")
