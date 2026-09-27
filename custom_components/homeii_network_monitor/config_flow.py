from __future__ import annotations

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_URL
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import HomeiiApiClient, HomeiiApiClientError
from .const import CONF_DEVICE_ENTITIES, CONF_SCAN_INTERVAL, DEFAULT_SCAN_INTERVAL, DEFAULT_URL, DOMAIN


class HomeiiNetworkMonitorConfigFlow(config_entries.ConfigFlow, domain=DOMAIN):
    VERSION = 3

    def __init__(self) -> None:
        self._pending_data = None
        self._pending_dashboard = None

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
        return await client.async_fetch_dashboard()

    async def async_step_user(self, user_input=None):
        errors = {}

        if user_input is not None:
            try:
                dashboard = await self._validate(user_input)
            except HomeiiApiClientError:
                errors["base"] = "cannot_connect"
            else:
                await self.async_set_unique_id(DOMAIN)
                self._abort_if_unique_id_configured()
                self._pending_data = {
                    CONF_URL: user_input[CONF_URL].rstrip("/"),
                    CONF_SCAN_INTERVAL: user_input[CONF_SCAN_INTERVAL],
                }
                self._pending_dashboard = dashboard
                return await self.async_step_devices()

        schema = self._schema(DEFAULT_URL, DEFAULT_SCAN_INTERVAL)
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    async def async_step_devices(self, user_input=None):
        if self._pending_data is None or self._pending_dashboard is None:
            return await self.async_step_user()
        devices = self._pending_dashboard.get("devices", [])
        choices = {
            str(device.get("ip")): (
                f"{device.get('display_name') or device.get('name') or device.get('hostname') or device.get('ip')}"
                f" ({device.get('ip')})"
            )
            for device in devices
            if device.get("ip")
        }
        if user_input is not None:
            selected = list(user_input.get(CONF_DEVICE_ENTITIES, []))
            status = self._pending_dashboard.get("status", {})
            return self.async_create_entry(
                title=f"HOMEii Network Monitor {status.get('version', '')}".strip(),
                data={**self._pending_data, CONF_DEVICE_ENTITIES: selected},
            )
        return self.async_show_form(
            step_id="devices",
            data_schema=vol.Schema(
                {vol.Optional(CONF_DEVICE_ENTITIES, default=[]): cv.multi_select(choices)}
            ),
        )

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
