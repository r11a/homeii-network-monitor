from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_URL
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import HomeiiApiClient, HomeiiApiClientError
from .const import CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DEFAULT_URL, DOMAIN


class HomeiiNetworkMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 2

    @staticmethod
    def _schema(default_url: str, default_interval: int) -> vol.Schema:
        return vol.Schema(
            {
                vol.Required(CONF_URL, default=default_url): str,
                vol.Required(
                    CONF_SCAN_INTERVAL,
                    default=default_interval,
                ): vol.All(vol.Coerce(int), vol.Range(min=5, max=300)),
            }
        )

    async def _validate(self, user_input):
        client = HomeiiApiClient(
            user_input[CONF_URL],
            async_get_clientsession(self.hass),
        )
        return await client.async_fetch_status()

    async def async_step_user(self, user_input=None):
        errors = {}

        if user_input is not None:
            await self.async_set_unique_id(DOMAIN)
            self._abort_if_unique_id_configured()

            try:
                status = await self._validate(user_input)
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

        schema = self._schema(DEFAULT_URL, DEFAULT_SCAN_INTERVAL)
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_reconfigure(self, user_input=None):
        entry = self._get_reconfigure_entry()
        errors = {}
        if user_input is not None:
            try:
                await self._validate(user_input)
            except HomeiiApiClientError:
                errors["base"] = "cannot_connect"
            else:
                return self.async_update_reload_and_abort(
                    entry,
                    data_updates={
                        CONF_URL: user_input[CONF_URL].rstrip("/"),
                        CONF_SCAN_INTERVAL: user_input[CONF_SCAN_INTERVAL],
                    },
                )
        return self.async_show_form(
            step_id="reconfigure",
            data_schema=self._schema(
                entry.data.get(CONF_URL, DEFAULT_URL),
                int(entry.data.get(CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL)),
            ),
            errors=errors,
        )
