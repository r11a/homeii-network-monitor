from __future__ import annotations

import asyncio
from typing import Any
from urllib.parse import quote

from aiohttp import ClientError, ClientSession


class HomeiiApiClientError(Exception):
    """Raised when the HOMEii API cannot be reached."""


class HomeiiApiClient:
    def __init__(self, base_url: str, session: ClientSession) -> None:
        self._base_url = base_url.rstrip("/")
        self._session = session

    async def _async_get_json(self, path: str) -> dict[str, Any]:
        url = f"{self._base_url}{path}"
        try:
            async with self._session.get(url, timeout=10) as response:
                response.raise_for_status()
                data = await response.json()
        except (ClientError, asyncio.TimeoutError, ValueError) as err:
            raise HomeiiApiClientError(f"Failed to fetch {url}") from err
        if not isinstance(data, dict):
            raise HomeiiApiClientError(f"Unexpected payload from {url}")
        return data

    async def async_fetch_status(self) -> dict[str, Any]:
        return await self._async_get_json("/api/status")

    async def async_fetch_devices(self) -> dict[str, Any]:
        return await self._async_get_json("/api/devices")

    async def async_fetch_alerts(self) -> dict[str, Any]:
        return await self._async_get_json("/api/alerts?limit=200")

    async def async_fetch_diagnostics(self) -> dict[str, Any]:
        return await self._async_get_json("/api/ha/diagnostics")

    async def async_scan_now(self, mode: str = "manual") -> dict[str, Any]:
        return await self._async_get_json(f"/api/scan?mode={quote(mode, safe='')}")

    async def async_accept_all_new(self) -> dict[str, Any]:
        return await self._async_get_json("/api/accept_all")

    async def async_accept_device(self, ip: str) -> dict[str, Any]:
        return await self._async_get_json(f"/api/accept/{quote(ip, safe='')}")

    async def async_ignore_device(self, ip: str) -> dict[str, Any]:
        return await self._async_get_json(f"/api/ignore/{quote(ip, safe='')}")

    async def async_toggle_pinned(self, ip: str) -> dict[str, Any]:
        return await self._async_get_json(f"/api/toggle_pinned/{quote(ip, safe='')}")

    async def async_toggle_critical(self, ip: str) -> dict[str, Any]:
        return await self._async_get_json(f"/api/toggle_critical/{quote(ip, safe='')}")
