"""Application configuration and monitoring policy constants."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict

APP_VERSION = "6.7.0"
BASE_DIR = Path(os.environ.get("HOMEII_DATA_DIR", "/data/homeii"))
DB_PATH = BASE_DIR / "homeii.db"
LEGACY_DEVICES = Path("/data/devices.json")
LEGACY_IGNORED = Path("/data/ignored_devices.json")
LEGACY_EVENTS = Path("/data/events.json")

THREADS = 40
PING_INTERVAL = 30
TRAFFIC_SAMPLE_INTERVAL = 120
FAIL_THRESHOLD = 2
CRITICAL_FAIL_THRESHOLD = 1
RECOVER_THRESHOLD = 1
UNSTABLE_WINDOW = 1800
UNSTABLE_CHANGE_THRESHOLD = 6
UNSTABLE_OFFLINE_THRESHOLD = 3
UNSTABLE_RECOVERY_THRESHOLD = 3
MAX_EVENTS = 300
SCAN_RESCHEDULE_SECONDS = 180
SESSION_TTL_SECONDS = 60 * 60 * 24 * 14

KNOWN_PROTOCOLS = ["ping", "arp", "dns", "special", "vendor"]
ALERT_PROFILE_CONFIGS = {
    "quiet": {"fail": 1, "window": 1200, "changes": 2, "offline": 1, "recovery": 1},
    "normal": {"fail": 0, "window": 0, "changes": 0, "offline": 0, "recovery": 0},
    "aggressive": {"fail": -1, "window": -600, "changes": -1, "offline": -1, "recovery": -1},
}
DEVICE_PROFILE_CONFIGS = {
    "generic": {"fail": 0, "window": 0, "changes": 0, "offline": 0, "recovery": 0},
    "phone": {"fail": 1, "window": 1800, "changes": 2, "offline": 1, "recovery": 1},
    "iot": {"fail": 1, "window": 2400, "changes": 3, "offline": 1, "recovery": 1},
    "camera": {"fail": 0, "window": -300, "changes": -1, "offline": 0, "recovery": 0},
    "server": {"fail": -1, "window": -600, "changes": -2, "offline": -1, "recovery": -1},
    "network": {"fail": -1, "window": -900, "changes": -2, "offline": -1, "recovery": -1},
    "printer": {"fail": 1, "window": 900, "changes": 1, "offline": 0, "recovery": 0},
}

ALERT_TITLE_NEW = "New device detected"
ALERT_TITLE_OFFLINE = "Device offline"
ALERT_TITLE_BACK_ONLINE = "Device back online"
ALERT_TITLE_UNSTABLE = "Device unstable"

PORT_NAME_MAP = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
    123: "NTP", 135: "RPC", 139: "NetBIOS", 143: "IMAP", 161: "SNMP",
    389: "LDAP", 443: "HTTPS", 445: "SMB", 554: "RTSP", 587: "SMTP TLS",
    631: "IPP", 1883: "MQTT", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 8000: "HTTP Alt", 8080: "HTTP Proxy",
    8123: "Home Assistant", 8443: "HTTPS Alt", 8883: "MQTT TLS",
}

NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}


def load_options() -> Dict[str, Any]:
    try:
        with open("/data/options.json", "r", encoding="utf-8") as options_file:
            options = json.load(options_file)
            return options if isinstance(options, dict) else {}
    except Exception:
        return {}


OPTIONS = load_options()
HOMEII_NETWORKS = OPTIONS.get("networks", ["192.168.1.0/24"])
