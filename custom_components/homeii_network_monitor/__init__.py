from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_URL
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import HomeiiApiClient
from .const import (
    CONF_SCAN_INTERVAL,
    DEFAULT_SCAN_INTERVAL,
    DOMAIN,
    PLATFORMS,
    SERVICE_ACCEPT_ALL_NEW,
    SERVICE_ACCEPT_DEVICE,
    SERVICE_IGNORE_DEVICE,
    SERVICE_REFRESH_DATA,
    SERVICE_SCAN_NOW,
    SERVICE_TOGGLE_CRITICAL,
    SERVICE_TOGGLE_PINNED,
)
from .coordinator import HomeiiDataUpdateCoordinator


async def async_setup(hass: HomeAssistant, config: dict) -> bool:
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN].setdefault("logger", logging.getLogger(__package__))
    hass.data[DOMAIN].setdefault("services_registered", False)
    await _async_register_services(hass)
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    hass.data.setdefault(DOMAIN, {})
    hass.data[DOMAIN].setdefault("logger", logging.getLogger(__package__))
    client = HomeiiApiClient(
        entry.data[CONF_URL],
        async_get_clientsession(hass),
    )
    coordinator = HomeiiDataUpdateCoordinator(
        hass,
        client,
        int(entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)),
    )
    await coordinator.async_config_entry_first_refresh()
    hass.data[DOMAIN][entry.entry_id] = {
        "client": client,
        "coordinator": coordinator,
    }
    await hass.config_entries.async_forward_entry_setups(entry, PLATFORMS)
    return True


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    unload_ok = await hass.config_entries.async_unload_platforms(entry, PLATFORMS)
    if unload_ok:
        hass.data[DOMAIN].pop(entry.entry_id, None)
        remaining_entries = [key for key in hass.data[DOMAIN].keys() if key not in {"logger", "services_registered"}]
        if not remaining_entries:
            for service in (
                SERVICE_SCAN_NOW,
                SERVICE_REFRESH_DATA,
                SERVICE_ACCEPT_ALL_NEW,
                SERVICE_ACCEPT_DEVICE,
                SERVICE_IGNORE_DEVICE,
                SERVICE_TOGGLE_PINNED,
                SERVICE_TOGGLE_CRITICAL,
            ):
                hass.services.async_remove(DOMAIN, service)
            hass.data[DOMAIN]["services_registered"] = False
    return unload_ok


def _first_runtime(hass: HomeAssistant) -> dict[str, Any]:
    domain_data = hass.data.get(DOMAIN, {})
    for key, value in domain_data.items():
        if key in {"logger", "services_registered"}:
            continue
        if isinstance(value, dict) and "client" in value and "coordinator" in value:
            return value
    raise ValueError("HOMEii integration is not configured")


async def _async_register_services(hass: HomeAssistant) -> None:
    if hass.data[DOMAIN].get("services_registered"):
        return

    async def _with_runtime(handler):
        runtime = _first_runtime(hass)
        coordinator = runtime["coordinator"]
        client = runtime["client"]
        await handler(client, coordinator)
        await coordinator.async_request_refresh()

    async def handle_scan_now(service_call) -> None:
        mode = str(service_call.data.get("mode", "manual")).strip() or "manual"
        await _with_runtime(lambda client, coordinator: client.async_scan_now(mode))

    async def handle_refresh_data(service_call) -> None:
        runtime = _first_runtime(hass)
        await runtime["coordinator"].async_request_refresh()

    async def handle_accept_all(service_call) -> None:
        await _with_runtime(lambda client, coordinator: client.async_accept_all_new())

    async def handle_accept_device(service_call) -> None:
        ip = str(service_call.data["ip"]).strip()
        await _with_runtime(lambda client, coordinator: client.async_accept_device(ip))

    async def handle_ignore_device(service_call) -> None:
        ip = str(service_call.data["ip"]).strip()
        await _with_runtime(lambda client, coordinator: client.async_ignore_device(ip))

    async def handle_toggle_pinned(service_call) -> None:
        ip = str(service_call.data["ip"]).strip()
        await _with_runtime(lambda client, coordinator: client.async_toggle_pinned(ip))

    async def handle_toggle_critical(service_call) -> None:
        ip = str(service_call.data["ip"]).strip()
        await _with_runtime(lambda client, coordinator: client.async_toggle_critical(ip))

    hass.services.async_register(
        DOMAIN,
        SERVICE_SCAN_NOW,
        handle_scan_now,
        schema=vol.Schema({vol.Optional("mode", default="manual"): vol.In(["manual", "auto"])}),
    )
    hass.services.async_register(DOMAIN, SERVICE_REFRESH_DATA, handle_refresh_data)
    hass.services.async_register(DOMAIN, SERVICE_ACCEPT_ALL_NEW, handle_accept_all)
    ip_schema = vol.Schema({vol.Required("ip"): str})
    hass.services.async_register(DOMAIN, SERVICE_ACCEPT_DEVICE, handle_accept_device, schema=ip_schema)
    hass.services.async_register(DOMAIN, SERVICE_IGNORE_DEVICE, handle_ignore_device, schema=ip_schema)
    hass.services.async_register(DOMAIN, SERVICE_TOGGLE_PINNED, handle_toggle_pinned, schema=ip_schema)
    hass.services.async_register(DOMAIN, SERVICE_TOGGLE_CRITICAL, handle_toggle_critical, schema=ip_schema)
    hass.data[DOMAIN]["services_registered"] = True
