from __future__ import annotations

from typing import Any

from homeassistant.components.button import ButtonEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_URL
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from .const import DOMAIN

BUTTONS = [
    {
        "key": "scan_now",
        "name": "Scan now",
        "icon": "mdi:radar",
    },
    {
        "key": "refresh_data",
        "name": "Refresh data",
        "icon": "mdi:refresh",
    },
    {
        "key": "accept_all_new",
        "name": "Accept all new devices",
        "icon": "mdi:check-decagram-outline",
    },
]


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    coordinator = hass.data[DOMAIN][entry.entry_id]["coordinator"]
    client = hass.data[DOMAIN][entry.entry_id]["client"]
    async_add_entities(HomeiiActionButton(coordinator, client, entry, spec) for spec in BUTTONS)


class HomeiiActionButton(CoordinatorEntity, ButtonEntity):
    _attr_has_entity_name = True

    def __init__(self, coordinator, client, entry: ConfigEntry, spec: dict[str, Any]) -> None:
        super().__init__(coordinator)
        self._client = client
        self._entry = entry
        self._key = spec["key"]
        self._attr_name = spec["name"]
        self._attr_icon = spec.get("icon")
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

    async def async_press(self) -> None:
        if self._key == "scan_now":
            await self._client.async_scan_now("manual")
        elif self._key == "refresh_data":
            await self.coordinator.async_request_refresh()
            return
        elif self._key == "accept_all_new":
            await self._client.async_accept_all_new()
        await self.coordinator.async_request_refresh()
