from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from homeassistant.core import HomeAssistant
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .api import HomeiiApiClient, HomeiiApiClientError
from .const import DOMAIN


class HomeiiDataUpdateCoordinator(DataUpdateCoordinator[dict[str, Any]]):
    def __init__(
        self,
        hass: HomeAssistant,
        client: HomeiiApiClient,
        scan_interval: int,
    ) -> None:
        super().__init__(
            hass,
            logger=logging.getLogger(__package__),
            name="HOMEii Network Monitor",
            update_interval=timedelta(seconds=scan_interval),
        )
        self.client = client

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            dashboard = await self.client.async_fetch_dashboard()
        except HomeiiApiClientError as err:
            raise UpdateFailed(str(err)) from err
        return {
            "status": dashboard.get("status", {}),
            "devices": dashboard.get("devices", []),
            "alerts": dashboard.get("alerts", []),
            "availability": dashboard.get("availability", {}),
        }
