from __future__ import annotations

from typing import Any

from homeassistant.components.binary_sensor import BinarySensorDeviceClass, BinarySensorEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers.device_registry import CONNECTION_NETWORK_MAC, format_mac
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

DEVICE_BINARY_SENSORS = [
    {
        "key": "availability",
        "suffix": "availability",
        "icon": "mdi:lan-connect",
        "device_class": BinarySensorDeviceClass.CONNECTIVITY,
    },
    {
        "key": "unstable",
        "suffix": "unstable",
        "icon": "mdi:lan-pending",
        "device_class": BinarySensorDeviceClass.PROBLEM,
    },
    {
        "key": "new",
        "suffix": "new",
        "icon": "mdi:new-box",
    },
    {
        "key": "critical",
        "suffix": "critical",
        "icon": "mdi:alert",
        "device_class": BinarySensorDeviceClass.PROBLEM,
    },
    {
        "key": "pinned",
        "suffix": "pinned",
        "icon": "mdi:pin",
    },
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    known_entities: set[tuple[str, str]] = set()

    @callback
    def async_sync_entities() -> None:
        new_entities = []
        for device in coordinator.data.get("devices", []):
            ip = device.get("ip")
            if not ip:
                continue
            for spec in DEVICE_BINARY_SENSORS:
                entity_key = (ip, spec["key"])
                if entity_key in known_entities:
                    continue
                known_entities.add(entity_key)
                new_entities.append(HomeiiDeviceBinarySensor(coordinator, entry, ip, spec))
        if new_entities:
            async_add_entities(new_entities)

    async_sync_entities()
    entry.async_on_unload(coordinator.async_add_listener(async_sync_entities))


class HomeiiDeviceBinarySensor(CoordinatorEntity, BinarySensorEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, entry: ConfigEntry, ip: str, spec: dict[str, Any]) -> None:
        super().__init__(coordinator)
        self._entry = entry
        self._ip = ip
        self._spec = spec
        self._attr_unique_id = f"{entry.entry_id}_{ip}_{spec['key']}"
        self._attr_device_class = spec.get("device_class")
        self._attr_icon = spec.get("icon")

    def _device(self) -> dict[str, Any]:
        for device in self.coordinator.data.get("devices", []):
            if device.get("ip") == self._ip:
                return device
        return {"ip": self._ip, "display_name": self._ip, "status": "unknown", "mac": ""}

    @property
    def name(self) -> str:
        return f"{self._device().get('display_name') or self._ip} {self._spec['suffix']}"

    @property
    def is_on(self) -> bool:
        device = self._device()
        status = device.get("status")
        key = self._spec["key"]
        if key == "availability":
            return status in ("online", "unstable")
        if key == "unstable":
            return status == "unstable"
        if key == "new":
            return status == "new"
        if key == "critical":
            return bool(device.get("critical"))
        if key == "pinned":
            return bool(device.get("pinned"))
        return False

    @property
    def device_info(self) -> DeviceInfo:
        device = self._device()
        identifiers = {(DOMAIN, device.get("mac") or self._ip)}
        connections = set()
        mac = device.get("mac")
        if mac:
            connections.add((CONNECTION_NETWORK_MAC, format_mac(mac)))
        return DeviceInfo(
            identifiers=identifiers,
            connections=connections,
            manufacturer=device.get("vendor") or None,
            model=device.get("category") or None,
            name=device.get("display_name") or self._ip,
        )

    @property
    def extra_state_attributes(self) -> dict[str, Any]:
        device = self._device()
        return {
            "ip": device.get("ip"),
            "mac": device.get("mac"),
            "vendor": device.get("vendor"),
            "category": device.get("category"),
            "network": device.get("assigned_network"),
            "last_seen": device.get("last_seen"),
            "status": device.get("status"),
            "approved": bool(device.get("approved")),
            "critical": bool(device.get("critical")),
            "pinned": bool(device.get("pinned")),
        }
