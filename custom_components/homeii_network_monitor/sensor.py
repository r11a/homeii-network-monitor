from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from homeassistant.components.sensor import SensorDeviceClass, SensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_URL
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

SUMMARY_SENSORS = [
    {"key": "total", "name": "Total devices", "icon": "mdi:counter"},
    {"key": "online", "name": "Connected devices", "icon": "mdi:lan-connect"},
    {"key": "offline", "name": "Disconnected devices", "icon": "mdi:lan-disconnect"},
    {"key": "unstable", "name": "Unstable devices", "icon": "mdi:lan-pending"},
    {"key": "new", "name": "New devices", "icon": "mdi:new-box"},
    {"key": "critical", "name": "Critical devices", "icon": "mdi:alert"},
    {"key": "pinned", "name": "Pinned devices", "icon": "mdi:pin"},
    {"key": "manual", "name": "Manual devices", "icon": "mdi:form-textbox"},
    {"key": "open_alerts", "name": "Open alerts", "icon": "mdi:alert-circle-outline"},
    {"key": "networks", "name": "Monitored networks", "icon": "mdi:graph-outline"},
    {
        "key": "scan_mode",
        "name": "Scan mode",
        "icon": "mdi:radar",
    },
    {
        "key": "last_scan_started",
        "name": "Last scan started",
        "icon": "mdi:clock-start",
        "device_class": SensorDeviceClass.TIMESTAMP,
    },
    {
        "key": "last_scan_finished",
        "name": "Last scan finished",
        "icon": "mdi:clock-check-outline",
        "device_class": SensorDeviceClass.TIMESTAMP,
    },
]

DETAIL_SENSORS = [
    {
        "key": "all_devices_details",
        "name": "All devices details",
        "icon": "mdi:devices",
        "kind": "devices",
        "filter": "all",
    },
    {
        "key": "online_details",
        "name": "Connected devices details",
        "icon": "mdi:lan-connect",
        "kind": "devices",
        "filter": "online",
    },
    {
        "key": "offline_details",
        "name": "Disconnected devices details",
        "icon": "mdi:lan-disconnect",
        "kind": "devices",
        "filter": "offline",
    },
    {
        "key": "unstable_details",
        "name": "Unstable devices details",
        "icon": "mdi:lan-pending",
        "kind": "devices",
        "filter": "unstable",
    },
    {
        "key": "new_details",
        "name": "New devices details",
        "icon": "mdi:new-box",
        "kind": "devices",
        "filter": "new",
    },
    {
        "key": "critical_details",
        "name": "Critical devices details",
        "icon": "mdi:alert",
        "kind": "devices",
        "filter": "critical",
    },
    {
        "key": "pinned_details",
        "name": "Pinned devices details",
        "icon": "mdi:pin",
        "kind": "devices",
        "filter": "pinned",
    },
    {
        "key": "open_alerts_details",
        "name": "Open alerts details",
        "icon": "mdi:alert-circle-outline",
        "kind": "alerts",
    },
    {
        "key": "category_summary",
        "name": "Category summary",
        "icon": "mdi:shape-outline",
        "kind": "categories",
    },
    {
        "key": "network_summary",
        "name": "Network summary",
        "icon": "mdi:ip-network-outline",
        "kind": "networks",
    },
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    async_add_entities(
        HomeiiSummarySensor(coordinator, entry, spec)
        for spec in SUMMARY_SENSORS
    )
    async_add_entities(
        HomeiiCollectionSensor(coordinator, entry, spec)
        for spec in DETAIL_SENSORS
    )


class HomeiiSummarySensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, spec: dict[str, Any]) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._key = spec["key"]
        self._attr_name = spec["name"]
        self._attr_icon = spec.get("icon")
        self._attr_device_class = spec.get("device_class")
        self._attr_unique_id = f"{entry.entry_id}_{self._key}"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name="HOMEii Network Monitor",
            manufacturer="HOMEii",
            model="Network Monitor",
            configuration_url=self._entry.data.get(CONF_URL),
        )

    @property
    def native_value(self) -> Any:
        status = self.coordinator.data.get("status", {})
        scan = status.get("scan", {})
        if self._key == "open_alerts":
            return len(
                [alert for alert in self.coordinator.data.get("alerts", []) if alert.get("status") == "open"]
            )
        if self._key == "networks":
            return len(status.get("networks", []))
        if self._key == "scan_mode":
            return scan.get("last_mode", "idle")
        if self._key == "last_scan_started":
            ts = scan.get("last_started")
            return datetime.fromtimestamp(ts, tz=timezone.utc) if ts else None
        if self._key == "last_scan_finished":
            ts = scan.get("last_finished")
            return datetime.fromtimestamp(ts, tz=timezone.utc) if ts else None
        return status.get(self._key, 0)

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        status = self.coordinator.data.get("status", {})
        return {
            "scan_mode": status.get("scan", {}).get("last_mode"),
            "scan_running": status.get("scan", {}).get("running"),
            "networks": status.get("networks", []),
        }


class HomeiiCollectionSensor(CoordinatorEntity, SensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, spec: dict[str, Any]) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._spec = spec
        self._attr_name = spec["name"]
        self._attr_icon = spec.get("icon")
        self._attr_unique_id = f"{entry.entry_id}_{spec['key']}"

    @property
    def device_info(self) -> DeviceInfo:
        return DeviceInfo(
            identifiers={(DOMAIN, self._entry.entry_id)},
            name="HOMEii Network Monitor",
            manufacturer="HOMEii",
            model="Network Monitor",
            configuration_url=self._entry.data.get(CONF_URL),
        )

    def _device_items(self) -> list[dict[str, Any]]:
        devices = self.coordinator.data.get("devices", [])
        filter_key = self._spec.get("filter")
        if filter_key == "all":
            selected = list(devices)
        elif filter_key == "critical":
            selected = [device for device in devices if device.get("critical")]
        elif filter_key == "pinned":
            selected = [device for device in devices if device.get("pinned")]
        else:
            selected = [device for device in devices if device.get("status") == filter_key]
        return [
            {
                "name": device.get("display_name") or device.get("name") or device.get("hostname") or device.get("ip"),
                "ip": device.get("ip"),
                "status": device.get("status"),
                "vendor": device.get("vendor"),
                "category": device.get("category"),
                "network": device.get("assigned_network"),
                "last_seen": device.get("last_seen"),
                "critical": bool(device.get("critical")),
                "pinned": bool(device.get("pinned")),
                "approved": bool(device.get("approved")),
            }
            for device in selected
        ]

    def _alert_items(self) -> list[dict[str, Any]]:
        return [
            {
                "id": alert.get("id"),
                "title": alert.get("title"),
                "message": alert.get("message"),
                "severity": alert.get("severity"),
                "ip": alert.get("ip"),
                "created_at": alert.get("created_at"),
                "status": alert.get("status"),
            }
            for alert in self.coordinator.data.get("alerts", [])
            if alert.get("status") == "open"
        ]

    def _category_items(self) -> list[dict[str, Any]]:
        grouped: dict[str, dict[str, Any]] = {}
        for device in self.coordinator.data.get("devices", []):
            key = (device.get("category") or "").strip() or "Uncategorized"
            row = grouped.setdefault(
                key,
                {
                    "category": key,
                    "total": 0,
                    "online": 0,
                    "offline": 0,
                    "unstable": 0,
                    "new": 0,
                    "critical": 0,
                    "pinned": 0,
                },
            )
            row["total"] += 1
            row[device.get("status") or "new"] = row.get(device.get("status") or "new", 0) + 1
            row["critical"] += 1 if device.get("critical") else 0
            row["pinned"] += 1 if device.get("pinned") else 0
        return sorted(grouped.values(), key=lambda item: (-item["total"], item["category"].lower()))

    def _network_items(self) -> list[dict[str, Any]]:
        status = self.coordinator.data.get("status", {})
        rows = []
        for item in status.get("network_stats", []):
            rows.append(
                {
                    "label": item.get("label") or item.get("cidr"),
                    "cidr": item.get("cidr"),
                    "devices": item.get("devices", 0),
                    "online": item.get("online", 0),
                    "offline": item.get("offline", 0),
                    "critical": item.get("critical", 0),
                    "hosts": item.get("hosts", 0),
                }
            )
        return rows

    def _items(self) -> list[dict[str, Any]]:
        kind = self._spec["kind"]
        if kind == "devices":
            return self._device_items()
        if kind == "alerts":
            return self._alert_items()
        if kind == "categories":
            return self._category_items()
        if kind == "networks":
            return self._network_items()
        return []

    @property
    def native_value(self) -> Any:
        return len(self._items())

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        items = self._items()
        names = [item.get("name") or item.get("title") or item.get("category") or item.get("label") for item in items]
        ips = [item.get("ip") for item in items if item.get("ip")]
        return {
            "count": len(items),
            "items": items,
            "names": names,
            "ips": ips,
            "summary": ", ".join(name for name in names[:10] if name),
        }
