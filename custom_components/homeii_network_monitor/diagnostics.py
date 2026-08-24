from __future__ import annotations

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.redact import async_redact_data

from .const import DOMAIN


async def async_get_config_entry_diagnostics(
    hass: HomeAssistant,
    entry: ConfigEntry,
):
    client = hass.data[DOMAIN][entry.entry_id]["client"]
    payload = await client.async_fetch_diagnostics()
    return async_redact_data(
        payload,
        {"url", "ip", "mac", "hostname", "name", "display_name", "message", "notes"},
    )
