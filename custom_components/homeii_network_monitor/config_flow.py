from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_URL
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import HomeiiApiClient, HomeiiApiClientError
from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DEFAULT_URL, DOMAIN


class HomeiiNetworkMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 1

    async def async_step_user(self, user_input=None):
        errors = {}

        if user_input is not None:
            await self.async_set_unique_id(DOMAIN)
            self._abort_if_unique_id_configured()

            client = HomeiiApiClient(
                user_input[CONF_URL],
                async_get_clientsession(self.hass),
            )
            try:
                status = await client.async_fetch_status()
            except HomeiiApiClientError:
                errors["base"] = "cannot_connect"
            else:
                title = status.get("version", "HOMEii Network Monitor")
                return self.async_create_entry(
                    title=f"HOMEii Network Monitor {title}",
                    data={
                        CONF_URL: user_input[CONF_URL].rstrip("/"),
                        CONF_SCAN_INTERVAL: user_input[CONF_SCAN_INTERVAL],
                    },
                )

        schema = vol.Schema(
            {
                vol.Required(CONF_URL, default=DEFAULT_URL): str,
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=DEFAULT_SCAN_INTERVAL,
                ): vol.All(vol.Coerce(int), vol.Range(min=5, max=300)),
            }
        )
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)
