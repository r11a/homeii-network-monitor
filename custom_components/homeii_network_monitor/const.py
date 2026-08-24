from __future__ import annotations

from homeassistant.const import Platform

DOMAIN = "homeii_network_monitor"
DEFAULT_SCAN_INTERVAL = 30
DEFAULT_URL = "http://homeassistant.local:8383"
CONF_SCAN_INTERVAL = "scan_interval"
PLATFORMS = [Platform.SENSOR, Platform.BINARY_SENSOR, Platform.BUTTON]

SERVICE_SCAN_NOW = "scan_now"
SERVICE_REFRESH_DATA = "refresh_data"
SERVICE_ACCEPT_ALL_NEW = "accept_all_new"
SERVICE_ACCEPT_DEVICE = "accept_device"
SERVICE_IGNORE_DEVICE = "ignore_device"
SERVICE_TOGGLE_PINNED = "toggle_pinned"
SERVICE_TOGGLE_CRITICAL = "toggle_critical"
