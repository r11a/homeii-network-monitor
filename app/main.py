import csv
import ipaddress
import io
import json
import os
import shlex
import shutil
import re
import socket
import sqlite3
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import unquote
from zoneinfo import ZoneInfo

from fastapi import FastAPI, File, Query, Request, UploadFile
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response

try:
    from app.vendor_lookup import lookup_vendor
except ModuleNotFoundError:
    from vendor_lookup import lookup_vendor

APP_VERSION = "5.0.0"
BASE_DIR = Path("/data/homeii")
DB_PATH = BASE_DIR / "homeii.db"
LEGACY_DEVICES = Path("/data/devices.json")
LEGACY_IGNORED = Path("/data/ignored_devices.json")
LEGACY_EVENTS = Path("/data/events.json")

THREADS = 40
PING_INTERVAL = 30
FAIL_THRESHOLD = 2
CRITICAL_FAIL_THRESHOLD = 1
RECOVER_THRESHOLD = 1
UNSTABLE_WINDOW = 1800
UNSTABLE_CHANGE_THRESHOLD = 6
UNSTABLE_OFFLINE_THRESHOLD = 3
UNSTABLE_RECOVERY_THRESHOLD = 3
MAX_EVENTS = 300
SCAN_RESCHEDULE_SECONDS = 180
KNOWN_PROTOCOLS = ["ping", "arp", "dns", "special", "vendor"]
ALERT_TITLE_NEW = "New device detected"
ALERT_TITLE_OFFLINE = "Device offline"
ALERT_TITLE_BACK_ONLINE = "Device back online"
ALERT_TITLE_UNSTABLE = "Device unstable"
PORT_NAME_MAP = {
    20: "FTP-Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    139: "NetBIOS",
    143: "IMAP",
    161: "SNMP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    554: "RTSP",
    587: "SMTP TLS",
    631: "IPP",
    1883: "MQTT",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8000: "HTTP Alt",
    8080: "HTTP Proxy",
    8123: "Home Assistant",
    8443: "HTTPS Alt",
    8883: "MQTT TLS",
}


def load_options() -> Dict[str, Any]:
    try:
        with open("/data/options.json", "r", encoding="utf-8") as f:
            opts = json.load(f)
            return opts if isinstance(opts, dict) else {}
    except Exception:
        return {}


OPTIONS = load_options()
HOMEII_NETWORKS = OPTIONS.get("networks", ["192.168.1.0/24"])

NO_CACHE_HEADERS = {
    "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
    "Pragma": "no-cache",
    "Expires": "0",
}

app = FastAPI(title="HOMEii Network Monitor", version=APP_VERSION)
_db_lock = threading.RLock()
_worker_lock = threading.Lock()
_worker_threads: Dict[str, threading.Thread] = {}
scan_state = {
    "running": False,
    "last_started": 0,
    "last_finished": 0,
    "last_mode": "idle",
    "last_error": "",
    "target_count": 0,
    "target_networks": [],
}
worker_state = {
    "monitor": {"last_started": 0, "last_finished": 0, "last_cycle": 0, "last_error": "", "cycle_count": 0, "interval": PING_INTERVAL},
    "critical_monitor": {"last_started": 0, "last_finished": 0, "last_cycle": 0, "last_error": "", "cycle_count": 0, "interval": max(5, int(PING_INTERVAL / 1.5))},
    "rescan": {"last_started": 0, "last_finished": 0, "last_cycle": 0, "last_error": "", "cycle_count": 0, "interval": 30},
}
_dns_cache: Dict[str, str] = {}
_traffic_cache: Dict[str, tuple[int, int, float]] = {}

def try_command_output(cmd: list[str], timeout: int = 2) -> str:
    try:
        return subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=timeout).decode("utf-8", "ignore")
    except Exception:
        return ""


def resolve_hostname_enriched(ip: str) -> str:
    # Reverse DNS
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host = short_hostname(host)
        if host:
            return host
    except Exception:
        pass

    # nslookup
    out = try_command_output(["nslookup", ip], timeout=2)
    for line in out.splitlines():
        if "name =" in line:
            host = short_hostname(line.split("name =", 1)[1].strip().rstrip("."))
            if host:
                return host

    # getent hosts
    out = try_command_output(["getent", "hosts", ip], timeout=2)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            host = short_hostname(parts[1])
            if host:
                return host

    # avahi / mDNS
    out = try_command_output(["avahi-resolve-address", ip], timeout=2)
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2:
            host = short_hostname(parts[-1])
            if host:
                return host

    # NetBIOS (BusyBox image may not have it, harmless fallback)
    out = try_command_output(["nmblookup", "-A", ip], timeout=2)
    for line in out.splitlines():
        if "<00>" in line and "GROUP" not in line:
            host = short_hostname(line.strip().split()[0])
            if host:
                return host

    return ""


def arp_identity_for_ip(ip: str) -> dict[str, str]:
    for item in arp_scan_networks() + read_proc_arp():
        if item.get("ip") == ip:
            mac = normalize_mac(item.get("mac", ""))
            return {"mac": mac, "vendor": vendor_from_mac(mac) if mac else ""}
    return {"mac": "", "vendor": ""}


def managed_row(row: sqlite3.Row | None) -> bool:
    if not row:
        return False
    return bool(row["approved"]) or bool(row["manual"])


def mark_device_recovered(ip: str, name: str, prev_state: str) -> None:
    log_event("success", f"{name or ip} is online", "device_online", ip)
    resolve_alerts_for_ip(ip, ALERT_TITLE_OFFLINE)
    resolve_alerts_for_ip(ip, ALERT_TITLE_UNSTABLE)
    if prev_state == "offline":
        create_alert(ip, "info", ALERT_TITLE_BACK_ONLINE, f"{name or ip} is back online")
    elif prev_state == "unstable":
        log_event("success", f"{name or ip} is stable again", "device_stable", ip)


def alerts_enabled_for_device(device: Dict[str, Any]) -> bool:
    return not bool(device.get("maintenance")) and not bool(device.get("mute_alerts"))


def create_alert_for_device(device: Dict[str, Any], severity: str, title: str, message: str) -> None:
    if alerts_enabled_for_device(device):
        create_alert(device.get("ip", ""), severity, title, message)


def mark_device_recovered_with_policy(device: Dict[str, Any], prev_state: str) -> None:
    ip = device.get("ip", "")
    name = device.get("name") or ip
    log_event("success", f"{name} is online", "device_online", ip)
    resolve_alerts_for_ip(ip, ALERT_TITLE_OFFLINE)
    resolve_alerts_for_ip(ip, ALERT_TITLE_UNSTABLE)
    if prev_state == "offline":
        create_alert_for_device(device, "info", ALERT_TITLE_BACK_ONLINE, f"{name} is back online")
    elif prev_state == "unstable":
        log_event("success", f"{name} is stable again", "device_stable", ip)


def probe_device(ip: str) -> tuple[bool, str, dict[str, str]]:
    ok = ping(ip)
    ident = arp_identity_for_ip(ip)
    return ok, ("ping" if ok else ""), ident


def interval_from_settings(default_value: int = PING_INTERVAL) -> int:
    try:
        value = int(str(get_setting("scan_interval", str(default_value)) or default_value).strip())
    except Exception:
        value = default_value
    return max(5, min(value, 3600))


def critical_interval_seconds() -> int:
    return max(5, int(round(interval_from_settings() / 1.5)))


def set_worker_status(name: str, **kwargs: Any) -> None:
    state = worker_state.setdefault(name, {"last_started": 0, "last_finished": 0, "last_cycle": 0, "last_error": "", "cycle_count": 0, "interval": 0})
    state.update(kwargs)


def background_worker_payload() -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    with _worker_lock:
        for name, state in worker_state.items():
            thread = _worker_threads.get(name)
            payload[name] = {
                **state,
                "alive": bool(thread and thread.is_alive()),
            }
    return payload


def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout = 30000")
    return conn


def ensure_dirs() -> None:
    BASE_DIR.mkdir(parents=True, exist_ok=True)


SCHEMA = """
CREATE TABLE IF NOT EXISTS devices (
  ip TEXT PRIMARY KEY,
  name TEXT DEFAULT '',
  hostname TEXT DEFAULT '',
  category TEXT DEFAULT '',
  vendor TEXT DEFAULT '',
  mac TEXT DEFAULT '',
  status TEXT DEFAULT 'unknown',
  last_seen INTEGER DEFAULT 0,
  critical INTEGER DEFAULT 0,
  pinned INTEGER DEFAULT 0,
  manual INTEGER DEFAULT 0,
  ignored INTEGER DEFAULT 0,
  fail_count INTEGER DEFAULT 0,
  success_count INTEGER DEFAULT 0,
  state_changes_today INTEGER DEFAULT 0,
  first_seen INTEGER DEFAULT 0,
  updated_at INTEGER DEFAULT 0,
  source TEXT DEFAULT 'ping',
  notes TEXT DEFAULT '',
  assigned_network TEXT DEFAULT '',
  maintenance INTEGER DEFAULT 0,
  mute_alerts INTEGER DEFAULT 0,
  scan_profile TEXT DEFAULT 'normal',
  tags_json TEXT DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS device_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT NOT NULL,
  ts INTEGER NOT NULL,
  old_status TEXT DEFAULT '',
  new_status TEXT DEFAULT '',
  kind TEXT DEFAULT 'status'
);

CREATE TABLE IF NOT EXISTS alerts (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ip TEXT DEFAULT '',
  severity TEXT DEFAULT 'info',
  title TEXT DEFAULT '',
  message TEXT DEFAULT '',
  status TEXT DEFAULT 'open',
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  level TEXT DEFAULT 'info',
  event_type TEXT DEFAULT 'info',
  ip TEXT DEFAULT '',
  message TEXT DEFAULT ''
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""

DEFAULT_SETTINGS = {
    "theme": "light",
    "language": "he",
    "scan_interval": str(PING_INTERVAL),
    "auto_refresh": "30",
    "default_view": "table",
    "dashboard_style": "advanced",
    "status_animation": "blink",
    "networks_json": json.dumps(HOMEII_NETWORKS),
    "network_names_json": json.dumps({}),
    "discovery_mode": "auto_manual",
    "discovery_protocols_json": json.dumps(KNOWN_PROTOCOLS),
}



def ensure_column(conn: sqlite3.Connection, table: str, name: str, ddl: str) -> None:
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if name not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")


def init_db() -> None:
    ensure_dirs()
    with _db_lock:
        conn = db()
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.executescript(SCHEMA)
            ensure_column(conn, "devices", "approved", "approved INTEGER DEFAULT 0")
            ensure_column(conn, "devices", "assigned_network", "assigned_network TEXT DEFAULT ''")
            ensure_column(conn, "devices", "maintenance", "maintenance INTEGER DEFAULT 0")
            ensure_column(conn, "devices", "mute_alerts", "mute_alerts INTEGER DEFAULT 0")
            ensure_column(conn, "devices", "scan_profile", "scan_profile TEXT DEFAULT 'normal'")
            for k, v in DEFAULT_SETTINGS.items():
                conn.execute(
                    "INSERT OR IGNORE INTO settings(key,value) VALUES(?,?)", (k, v)
                )
            existing_networks = conn.execute("SELECT value FROM settings WHERE key='networks_json'").fetchone()
            if not existing_networks or not (existing_networks[0] or '').strip():
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                    ("networks_json", json.dumps(HOMEII_NETWORKS)),
                )
            conn.commit()
        finally:
            conn.close()
    migrate_legacy_files()



def table_has_rows(table: str) -> bool:
    conn = db()
    try:
        row = conn.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()
        return bool(row and row[0])
    finally:
        conn.close()



def migrate_legacy_files() -> None:
    devices_exists = table_has_rows("devices")
    if not devices_exists and LEGACY_DEVICES.exists():
        try:
            legacy_devices = json.loads(LEGACY_DEVICES.read_text(encoding="utf-8"))
            now = int(time.time())
            conn = db()
            try:
                for ip, item in legacy_devices.items():
                    tags = item.get("tags", []) if isinstance(item, dict) else []
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO devices(
                          ip,name,hostname,category,status,last_seen,critical,pinned,manual,approved,
                          fail_count,success_count,state_changes_today,first_seen,updated_at,source,tags_json
                        ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            ip,
                            item.get("name", ""),
                            item.get("hostname", ""),
                            item.get("category", ""),
                            item.get("status", "unknown"),
                            int(item.get("last_seen", 0) or 0),
                            1 if item.get("critical") else 0,
                            1 if item.get("pinned") else 0,
                            1 if item.get("manual") else 0,
                            1,
                            int(item.get("fail_count", 0) or 0),
                            int(item.get("success_count", 0) or 0),
                            int(item.get("state_changes_today", 0) or 0),
                            int(item.get("last_seen", 0) or now),
                            now,
                            "legacy",
                            json.dumps(tags),
                        ),
                    )
                    for hist in item.get("history", []) or []:
                        conn.execute(
                            "INSERT INTO device_history(ip,ts,old_status,new_status,kind) VALUES(?,?,?,?,?)",
                            (
                                ip,
                                int(hist.get("ts", now)),
                                hist.get("from", ""),
                                hist.get("to", ""),
                                "status",
                            ),
                        )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass
    if not table_has_rows("events") and LEGACY_EVENTS.exists():
        try:
            legacy_events = json.loads(LEGACY_EVENTS.read_text(encoding="utf-8"))
            conn = db()
            try:
                for e in legacy_events[-MAX_EVENTS:]:
                    conn.execute(
                        "INSERT INTO events(ts,level,event_type,ip,message) VALUES(?,?,?,?,?)",
                        (
                            int(e.get("ts", time.time())),
                            e.get("level", "info"),
                            e.get("type", "info"),
                            e.get("ip", ""),
                            e.get("message", ""),
                        ),
                    )
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass
    if LEGACY_IGNORED.exists():
        try:
            ignored = json.loads(LEGACY_IGNORED.read_text(encoding="utf-8"))
            conn = db()
            try:
                for ip in ignored:
                    conn.execute(
                        "INSERT OR IGNORE INTO devices(ip,ignored,updated_at,first_seen,source) VALUES(?,1,?,?,?)",
                        (ip, int(time.time()), int(time.time()), "ignored"),
                    )
                    conn.execute("UPDATE devices SET ignored=1, updated_at=? WHERE ip=?", (int(time.time()), ip))
                conn.commit()
            finally:
                conn.close()
        except Exception:
            pass



def looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address((value or "").strip())
        return True
    except Exception:
        return False



def short_hostname(hostname: str) -> str:
    host = (hostname or "").strip().rstrip(".")
    if not host:
        return ""
    first = host.split(".")[0].strip()
    if not first or looks_like_ip(first) or first.isdigit():
        return ""
    return first



def is_local_admin_mac(mac: str) -> bool:
    mac = normalize_mac(mac)
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False



def choose_display_name(name: str, hostname: str, vendor: str, ip: str) -> str:
    raw_name = (name or "").strip()
    raw_host = short_hostname(hostname or "")
    raw_vendor = (vendor or "").strip()
    if raw_name and not raw_name.isdigit() and not looks_like_ip(raw_name):
        return raw_name
    if raw_host:
        return raw_host
    if raw_vendor:
        try:
            suffix = str(ip).split('.')[-1]
        except Exception:
            suffix = ""
        if raw_vendor == "Private / Randomized":
            return f"Device {suffix}".strip() or "Device"
        return f"{raw_vendor} {suffix}".strip()
    return (ip or raw_name or raw_host or raw_vendor or "").strip()



def reverse_dns(ip: str) -> str:
    if ip in _dns_cache:
        return _dns_cache[ip]
    host = resolve_hostname_enriched(ip)
    _dns_cache[ip] = host
    return host



def normalize_mac(mac: str) -> str:
    mac = (mac or "").strip().lower().replace("-", ":")
    parts = [p.zfill(2) for p in mac.split(":") if p]
    return ":".join(parts[:6]) if parts else ""



def vendor_from_mac(mac: str) -> str:
    return lookup_vendor(normalize_mac(mac))



def auto_category(name: str, vendor: str = "") -> str:
    n = f"{name or ''} {vendor or ''}".lower()
    mapping = [
        ("iphone", "mobile"), ("ipad", "tablet"), ("android", "mobile"),
        ("galaxy", "mobile"), ("pixel", "mobile"),
        ("lg", "tv"), ("samsung", "tv"), ("bravia", "tv"), ("tv", "tv"),
        ("hik", "camera"), ("cam", "camera"), ("reolink", "camera"), ("axis", "camera"),
        ("esp", "iot"), ("shelly", "iot"), ("sonoff", "iot"),
        ("router", "network"), ("gateway", "network"), ("switch", "network"), ("ubiquiti", "network"),
        ("nas", "server"), ("nuc", "server"), ("server", "server"), ("proxmox", "server"),
        ("printer", "printer"),
    ]
    for key, cat in mapping:
        if key in n:
            return cat
    return ""



def now_ts() -> int:
    return int(time.time())



def row_to_device(row: sqlite3.Row) -> Dict[str, Any]:
    tags = []
    try:
        tags = json.loads(row["tags_json"] or "[]")
    except Exception:
        tags = []
    return {
        "ip": row["ip"],
        "name": row["name"] or "",
        "hostname": row["hostname"] or "",
        "category": row["category"] or "",
        "vendor": row["vendor"] or "",
        "mac": row["mac"] or "",
        "status": row["status"] or "unknown",
        "last_seen": int(row["last_seen"] or 0),
        "critical": bool(row["critical"]),
        "pinned": bool(row["pinned"]),
        "manual": bool(row["manual"]),
        "ignored": bool(row["ignored"]),
        "approved": bool(row["approved"]) if "approved" in row.keys() else False,
        "fail_count": int(row["fail_count"] or 0),
        "success_count": int(row["success_count"] or 0),
        "state_changes_today": int(row["state_changes_today"] or 0),
        "first_seen": int(row["first_seen"] or 0),
        "updated_at": int(row["updated_at"] or 0),
        "source": row["source"] or "",
        "notes": row["notes"] or "",
        "assigned_network": row["assigned_network"] if "assigned_network" in row.keys() else "",
        "maintenance": bool(row["maintenance"]) if "maintenance" in row.keys() else False,
        "mute_alerts": bool(row["mute_alerts"]) if "mute_alerts" in row.keys() else False,
        "scan_profile": row["scan_profile"] if "scan_profile" in row.keys() and (row["scan_profile"] or "").strip() in ("slow", "normal", "fast") else "normal",
        "tags": tags,
        "last_seen_relative": last_seen_relative(int(row["last_seen"] or 0)),
        "display_name": choose_display_name(row["name"] or "", row["hostname"] or "", row["vendor"] or "", row["ip"]),
        "subtitle": short_hostname(row["hostname"] or "") or (row["vendor"] or ""),
    }



def last_seen_relative(ts: int) -> str:
    if not ts:
        return "-"
    delta = max(0, now_ts() - int(ts))
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"



def log_event(level: str, message: str, event_type: str, ip: str = "") -> None:
    with _db_lock:
        conn = db()
        try:
            conn.execute(
                "INSERT INTO events(ts,level,event_type,ip,message) VALUES(?,?,?,?,?)",
                (now_ts(), level, event_type, ip, message),
            )
            conn.execute(
                "DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT ?)",
                (MAX_EVENTS,),
            )
            conn.commit()
        finally:
            conn.close()





def log_system_event(level: str, message: str, event_type: str) -> None:
    log_event(level, message, event_type, "")

def db_status_payload() -> dict:
    try:
        exists = DB_PATH.exists()
        size = DB_PATH.stat().st_size if exists else 0
        return {"exists": exists, "size": size, "path": str(DB_PATH)}
    except Exception:
        return {"exists": False, "size": 0, "path": str(DB_PATH)}

def create_alert(ip: str, severity: str, title: str, message: str) -> None:
    with _db_lock:
        conn = db()
        try:
            current = conn.execute(
                "SELECT id, status FROM alerts WHERE ip=? AND title=? AND status='open' ORDER BY id DESC LIMIT 1",
                (ip, title),
            ).fetchone()
            ts = now_ts()
            if current:
                conn.execute(
                    "UPDATE alerts SET message=?, severity=?, updated_at=? WHERE id=?",
                    (message, severity, ts, current["id"]),
                )
            else:
                conn.execute(
                    "INSERT INTO alerts(ip,severity,title,message,status,created_at,updated_at) VALUES(?,?,?,?,?,?,?)",
                    (ip, severity, title, message, "open", ts, ts),
                )
            conn.commit()
        finally:
            conn.close()



def resolve_alerts_for_ip(ip: str, title: str | None = None) -> None:
    with _db_lock:
        conn = db()
        try:
            if title:
                conn.execute(
                    "UPDATE alerts SET status='resolved', updated_at=? WHERE ip=? AND title=? AND status='open'",
                    (now_ts(), ip, title),
                )
            else:
                conn.execute(
                    "UPDATE alerts SET status='resolved', updated_at=? WHERE ip=? AND status='open'",
                    (now_ts(), ip),
                )
            conn.commit()
        finally:
            conn.close()



def get_setting(key: str, default: str = "") -> str:
    conn = db()
    try:
        row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return row[0] if row else default
    finally:
        conn.close()



def set_setting(key: str, value: str) -> None:
    with _db_lock:
        conn = db()
        try:
            conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()


def normalize_networks(values: list[str] | str | None) -> list[str]:
    if values is None:
        return []
    if isinstance(values, str):
        text = values.strip()
        if text.startswith("[") and text.endswith("]"):
            try:
                decoded = json.loads(text)
                if isinstance(decoded, list):
                    raw = decoded
                else:
                    raw = re.split(r"[\n,;]+", values)
            except Exception:
                raw = re.split(r"[\n,;]+", values)
        else:
            raw = re.split(r"[\n,;]+", values)
    else:
        raw = list(values)
    out: list[str] = []
    seen: set[str] = set()
    for item in raw:
        item = (item or "").strip()
        if not item:
            continue
        try:
            net = str(ipaddress.ip_network(item, strict=False))
        except Exception:
            continue
        if net not in seen:
            seen.add(net)
            out.append(net)
    return out


def get_networks() -> list[str]:
    try:
        stored = get_setting("networks_json", "")
        if stored:
            data = json.loads(stored)
            if isinstance(data, list):
                nets = normalize_networks(data)
                if nets:
                    return nets
    except Exception:
        pass
    return normalize_networks(HOMEII_NETWORKS) or ["192.168.1.0/24"]


def get_network_names() -> Dict[str, str]:
    try:
        stored = get_setting("network_names_json", "{}")
        data = json.loads(stored)
        if isinstance(data, dict):
            return {str(k): str(v) for k, v in data.items()}
    except Exception:
        pass
    return {}


def normalize_network_name_map(raw: Any, allowed_networks: list[str] | None = None) -> Dict[str, str]:
    allowed = set(allowed_networks or [])
    if not isinstance(raw, dict):
        return {}
    normalized: Dict[str, str] = {}
    for key, value in raw.items():
        alias = str(value or "").strip()
        if not alias:
            continue
        try:
            cidr = str(ipaddress.ip_network(str(key).strip(), strict=False))
        except Exception:
            continue
        if allowed and cidr not in allowed:
            continue
        normalized[cidr] = alias
    return normalized


def parse_network_input(raw: Any) -> list[str] | str:
    if raw is None:
        return ""
    if isinstance(raw, list):
        return [str(item).strip() for item in raw if str(item).strip()]
    if isinstance(raw, str):
        text = raw.strip()
        if not text:
            return ""
        try:
            decoded = json.loads(text)
            if isinstance(decoded, list):
                return [str(item).strip() for item in decoded if str(item).strip()]
        except Exception:
            pass
        return text
    return str(raw)


def estimated_hosts_for_network(cidr: str) -> int:
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return 0
    if network.version != 4:
        return 0
    if network.num_addresses <= 2:
        return int(network.num_addresses)
    return max(0, int(network.num_addresses) - 2)


def network_stats_payload(devices: list[Dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rows = devices if devices is not None else get_devices()
    names = get_network_names()
    stats: dict[str, dict[str, Any]] = {}
    for cidr in get_networks():
        stats[cidr] = {
            "cidr": cidr,
            "label": names.get(cidr, "").strip() or cidr,
            "hosts": estimated_hosts_for_network(cidr),
            "devices": 0,
            "online": 0,
            "offline": 0,
            "new": 0,
            "critical": 0,
        }
    for device in rows:
        cidr = (device.get("assigned_network") or "").strip()
        if not cidr:
            continue
        item = stats.setdefault(
            cidr,
            {
                "cidr": cidr,
                "label": names.get(cidr, "").strip() or cidr,
                "hosts": estimated_hosts_for_network(cidr),
                "devices": 0,
                "online": 0,
                "offline": 0,
                "new": 0,
                "critical": 0,
            },
        )
        item["devices"] += 1
        if device.get("status") == "online":
            item["online"] += 1
        if device.get("status") == "offline":
            item["offline"] += 1
        if device.get("status") == "new":
            item["new"] += 1
        if device.get("critical"):
            item["critical"] += 1
    return sorted(stats.values(), key=lambda item: item["cidr"])

def get_discovery_mode() -> str:
    mode = (get_setting("discovery_mode", "auto_manual") or "auto_manual").strip()
    return mode if mode in ("auto_manual", "manual_only", "auto_only") else "auto_manual"


def get_discovery_protocols() -> list[str]:
    try:
        stored = get_setting("discovery_protocols_json", "")
        if stored:
            data = json.loads(stored)
            if isinstance(data, list):
                prots = [str(x).strip() for x in data if str(x).strip() in KNOWN_PROTOCOLS]
                if prots:
                    return sorted(set(prots), key=KNOWN_PROTOCOLS.index)
    except Exception:
        pass
    return KNOWN_PROTOCOLS.copy()


def set_discovery_protocols(protocols: list[str] | str | None) -> list[str]:
    if protocols is None:
        prots = KNOWN_PROTOCOLS.copy()
    elif isinstance(protocols, str):
        raw = re.split(r"[\n,;]+", protocols)
        prots = [p.strip() for p in raw if p.strip() in KNOWN_PROTOCOLS]
    else:
        prots = [str(p).strip() for p in protocols if str(p).strip() in KNOWN_PROTOCOLS]
    prots = sorted(set(prots), key=KNOWN_PROTOCOLS.index)
    if not prots:
        prots = ["ping"]
    set_setting("discovery_protocols_json", json.dumps(prots))
    return prots


def infer_assigned_network(ip: str) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return ""
    for net in get_networks():
        try:
            if ip_obj in ipaddress.ip_network(net, strict=False):
                return net
        except Exception:
            continue
    return ""


def infer_assigned_network_for_list(ip: str, networks: list[str] | None = None) -> str:
    try:
        ip_obj = ipaddress.ip_address(ip)
    except Exception:
        return ""
    for net in (networks or get_networks()):
        try:
            if ip_obj in ipaddress.ip_network(net, strict=False):
                return net
        except Exception:
            continue
    return ""


def refresh_assigned_networks(networks: list[str] | None = None) -> int:
    monitored = list(networks or get_networks())
    monitored_set = set(monitored)
    conn = db()
    try:
        rows = conn.execute("SELECT ip, assigned_network FROM devices").fetchall()
        changed = 0
        for row in rows:
            current = (row["assigned_network"] or "").strip()
            inferred = infer_assigned_network_for_list(row["ip"], monitored)
            should_update = (
                current != inferred
                and (
                    not current
                    or current not in monitored_set
                )
            )
            if not should_update:
                continue
            conn.execute("UPDATE devices SET assigned_network=? WHERE ip=?", (inferred, row["ip"]))
            changed += 1
        if changed:
            conn.commit()
        return changed
    finally:
        conn.close()


def save_networks(raw: list[str] | str) -> list[str]:
    nets = normalize_networks(raw)
    if not nets:
        nets = normalize_networks(HOMEII_NETWORKS) or ["192.168.1.0/24"]
    set_setting("networks_json", json.dumps(nets))
    log_system_event("info", f"Saved {len(nets)} monitored network(s): {', '.join(nets)}", "networks_saved")
    return nets



def recent_history_count(conn: sqlite3.Connection, ip: str) -> int:
    cutoff = now_ts() - UNSTABLE_WINDOW
    row = conn.execute(
        "SELECT COUNT(*) c FROM device_history WHERE ip=? AND ts>=? AND kind='status'",
        (ip, cutoff),
    ).fetchone()
    return int(row[0] if row else 0)


def normalize_scan_profile(value: Any) -> str:
    profile = str(value or "").strip().lower()
    return profile if profile in ("slow", "normal", "fast") else "normal"


def failure_threshold_for_device(device: Dict[str, Any]) -> int:
    if device.get("critical"):
        return CRITICAL_FAIL_THRESHOLD
    profile = normalize_scan_profile(device.get("scan_profile"))
    if profile == "fast":
        return 1
    if profile == "slow":
        return 3
    return FAIL_THRESHOLD


def unstable_thresholds_for_device(device: Dict[str, Any]) -> tuple[int, int, int, int]:
    profile = normalize_scan_profile(device.get("scan_profile"))
    if device.get("critical") or profile == "fast":
        return (1200, 5, 2, 2)
    if profile == "slow":
        return (3600, 8, 4, 4)
    return (
        UNSTABLE_WINDOW,
        UNSTABLE_CHANGE_THRESHOLD,
        UNSTABLE_OFFLINE_THRESHOLD,
        UNSTABLE_RECOVERY_THRESHOLD,
    )


def should_mark_unstable(conn: sqlite3.Connection, ip: str, device: Dict[str, Any]) -> bool:
    unstable_window, change_threshold, offline_threshold, recovery_threshold = unstable_thresholds_for_device(device)
    cutoff = now_ts() - unstable_window
    rows = conn.execute(
        "SELECT old_status, new_status FROM device_history WHERE ip=? AND ts>=? AND kind='status' ORDER BY ts ASC",
        (ip, cutoff),
    ).fetchall()
    if not rows:
        return False
    total_changes = len(rows)
    offline_changes = sum(1 for row in rows if (row["new_status"] or "") == "offline")
    recovery_changes = sum(1 for row in rows if (row["new_status"] or "") == "online")
    return (
        total_changes >= change_threshold
        and offline_changes >= offline_threshold
        and recovery_changes >= recovery_threshold
    )



def upsert_device(ip: str, fields: Dict[str, Any]) -> None:
    conn = db()
    try:
        current = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        base = row_to_device(current) if current else {
            "ip": ip, "name": "", "hostname": "", "category": "", "vendor": "", "mac": "",
            "status": "unknown", "last_seen": 0, "critical": False, "pinned": False, "manual": False,
            "ignored": False, "approved": False, "fail_count": 0, "success_count": 0, "state_changes_today": 0,
            "first_seen": now_ts(), "updated_at": now_ts(), "source": "", "notes": "", "assigned_network": "", "maintenance": False, "mute_alerts": False, "scan_profile": "normal", "tags": []
        }
        base.update(fields)
        base["scan_profile"] = normalize_scan_profile(base.get("scan_profile"))
        conn.execute(
            """
            INSERT INTO devices(
              ip,name,hostname,category,vendor,mac,status,last_seen,critical,pinned,manual,ignored,approved,
              fail_count,success_count,state_changes_today,first_seen,updated_at,source,notes,assigned_network,maintenance,mute_alerts,scan_profile,tags_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
              name=excluded.name, hostname=excluded.hostname, category=excluded.category, vendor=excluded.vendor,
              mac=excluded.mac, status=excluded.status, last_seen=excluded.last_seen, critical=excluded.critical,
              pinned=excluded.pinned, manual=excluded.manual, ignored=excluded.ignored, approved=excluded.approved,
              fail_count=excluded.fail_count, success_count=excluded.success_count,
              state_changes_today=excluded.state_changes_today, first_seen=excluded.first_seen,
              updated_at=excluded.updated_at, source=excluded.source, notes=excluded.notes, assigned_network=excluded.assigned_network,
              maintenance=excluded.maintenance, mute_alerts=excluded.mute_alerts, scan_profile=excluded.scan_profile, tags_json=excluded.tags_json
            """,
            (
                ip,
                base["name"], base["hostname"], base["category"], base["vendor"], base["mac"],
                base["status"], int(base["last_seen"] or 0), 1 if base["critical"] else 0,
                1 if base["pinned"] else 0, 1 if base["manual"] else 0, 1 if base["ignored"] else 0, 1 if base.get("approved") else 0,
                int(base["fail_count"] or 0), int(base["success_count"] or 0), int(base["state_changes_today"] or 0),
                int(base["first_seen"] or now_ts()), int(base["updated_at"] or now_ts()), base["source"],
                base["notes"], base.get("assigned_network", ""), 1 if base.get("maintenance") else 0, 1 if base.get("mute_alerts") else 0, base["scan_profile"], json.dumps(base["tags"]),
            ),
        )
        conn.commit()
    finally:
        conn.close()



def ping(ip: str) -> bool:
    try:
        return subprocess.run(
            ["ping", "-c", "1", "-W", "1", ip],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        ).returncode == 0
    except Exception:
        return False


def run_command_capture(cmd: list[str], timeout: int = 10) -> tuple[bool, str]:
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            text=True,
            encoding="utf-8",
            errors="ignore",
        )
        return result.returncode == 0, (result.stdout or "").strip()
    except Exception as exc:
        return False, str(exc)


def parse_ports(value: Any) -> list[int]:
    if isinstance(value, list):
        raw_items = value
    else:
        raw_items = re.split(r"[\s,;]+", str(value or "").strip())
    if any(str(item).strip() == "0" for item in raw_items):
        return list(range(1, 65536))
    ports: list[int] = []
    for item in raw_items:
        text = str(item).strip()
        if not text:
            continue
        if "-" in text:
            try:
                start_s, end_s = text.split("-", 1)
                start_i = max(1, min(65535, int(start_s)))
                end_i = max(1, min(65535, int(end_s)))
                if end_i < start_i:
                    start_i, end_i = end_i, start_i
                ports.extend(range(start_i, min(end_i, start_i + 32) + 1))
            except Exception:
                continue
            continue
        try:
            port = int(text)
        except Exception:
            continue
        if 1 <= port <= 65535:
            ports.append(port)
    deduped: list[int] = []
    seen: set[int] = set()
    for port in ports:
        if port not in seen:
            seen.add(port)
            deduped.append(port)
    return deduped[:64]


def port_name(port: int) -> str:
    return PORT_NAME_MAP.get(port, "Custom")


def ping_diagnostics(ip: str, count: int = 4) -> dict[str, Any]:
    count = max(1, min(int(count), 8))
    ok, output = run_command_capture(["ping", "-c", str(count), "-W", "1", ip], timeout=max(4, count * 2))
    transmitted = received = 0
    loss_pct = 100
    latency_min = latency_avg = latency_max = None
    for line in output.splitlines():
        lower = line.lower()
        if "packets transmitted" in lower and "received" in lower:
            match = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received.*?(\d+)%\s+packet loss", lower)
            if match:
                transmitted = int(match.group(1))
                received = int(match.group(2))
                loss_pct = int(match.group(3))
        if "min/avg/max" in lower:
            match = re.search(r"=\s*([\d.]+)/([\d.]+)/([\d.]+)", line)
            if match:
                latency_min = float(match.group(1))
                latency_avg = float(match.group(2))
                latency_max = float(match.group(3))
    status = "down"
    if received and loss_pct == 0:
        status = "healthy" if (latency_avg or 0) < 80 else "degraded"
    elif received:
        status = "degraded"
    return {
        "ok": ok,
        "target": ip,
        "status": status,
        "transmitted": transmitted,
        "received": received,
        "loss_pct": loss_pct,
        "latency_min_ms": latency_min,
        "latency_avg_ms": latency_avg,
        "latency_max_ms": latency_max,
        "output": output,
    }


def trace_diagnostics(ip: str, max_hops: int = 12) -> dict[str, Any]:
    max_hops = max(4, min(int(max_hops), 24))
    commands: list[list[str]] = []
    if shutil.which("traceroute"):
        commands.append(["traceroute", "-n", "-w", "1", "-q", "1", "-m", str(max_hops), ip])
    if shutil.which("tracepath"):
        commands.append(["tracepath", "-n", ip])
    if shutil.which("busybox"):
        commands.append(["busybox", "traceroute", "-n", "-w", "1", "-q", "1", "-m", str(max_hops), ip])

    output = ""
    ok = False
    command_name = ""
    for cmd in commands:
        current_ok, current_output = run_command_capture(cmd, timeout=max_hops + 6)
        output = current_output
        ok = current_ok
        command_name = Path(cmd[0]).name
        if current_output:
            break

    hops: list[dict[str, Any]] = []
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line or line.lower().startswith("traceroute") or line.lower().startswith("tracepath"):
            continue
        match = re.match(r"(\d+)\s+(.*)", line)
        if not match:
            continue
        hop_num = int(match.group(1))
        rest = match.group(2).strip()
        ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", rest)
        latency_matches = re.findall(r"([\d.]+)\s*ms", rest)
        hops.append(
            {
                "hop": hop_num,
                "address": ip_match.group(1) if ip_match else "*",
                "latency_ms": float(latency_matches[0]) if latency_matches else None,
                "raw": rest,
            }
        )
    status = "healthy" if ok and hops else ("degraded" if hops else "down")
    return {
        "ok": ok,
        "target": ip,
        "status": status,
        "command": command_name or "traceroute",
        "hops": hops,
        "hop_count": len(hops),
        "output": output,
    }


def port_scan_diagnostics(ip: str, ports: list[int]) -> dict[str, Any]:
    checked: list[dict[str, Any]] = []

    def probe_port(port: int) -> dict[str, Any]:
        started = time.perf_counter()
        is_open = False
        error = ""
        try:
            with socket.create_connection((ip, port), timeout=0.45):
                is_open = True
        except Exception as exc:
            error = str(exc)
        latency = round((time.perf_counter() - started) * 1000, 1)
        return {
            "port": port,
            "service": port_name(port),
            "open": is_open,
            "latency_ms": latency,
            "error": error,
        }

    max_workers = min(128, max(8, len(ports)))
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        checked = list(executor.map(probe_port, ports))

    open_ports = sum(1 for item in checked if item["open"])
    checked.sort(key=lambda item: (not item["open"], item["port"]))
    status = "healthy" if open_ports else "down"
    if 0 < open_ports < len(ports):
        status = "degraded"
    return {
        "ok": True,
        "target": ip,
        "status": status,
        "open_ports": open_ports,
        "checked_ports": len(ports),
        "ports": checked,
    }


def dns_diagnostics(target: str) -> dict[str, Any]:
    reverse_host = ""
    try:
        reverse_host = socket.gethostbyaddr(target)[0]
    except Exception:
        reverse_host = ""
    addresses: list[str] = []
    try:
        info = socket.gethostbyname_ex(target)
        addresses = info[2] or []
    except Exception:
        pass
    nslookup_ok, nslookup_output = run_command_capture(["nslookup", target], timeout=4) if shutil.which("nslookup") else (False, "")
    status = "healthy" if (reverse_host or addresses or nslookup_ok) else "down"
    return {
        "ok": bool(reverse_host or addresses or nslookup_ok),
        "target": target,
        "status": status,
        "reverse_host": reverse_host,
        "addresses": addresses,
        "output": nslookup_output,
    }


def speedtest_diagnostics() -> dict[str, Any]:
    commands = []
    if shutil.which("speedtest"):
        commands.append(["speedtest", "--accept-license", "--accept-gdpr", "--format=json"])
    if shutil.which("speedtest-cli"):
        commands.append(["speedtest-cli", "--json"])
    commands.append([sys.executable, "-m", "speedtest", "--json"])
    if shutil.which("fast"):
        commands.append(["fast", "--json"])
    seen: set[tuple[str, ...]] = set()
    last_error = "speedtest command not available"
    for cmd in commands:
        key = tuple(cmd)
        if key in seen:
            continue
        seen.add(key)
        ok, output = run_command_capture(cmd, timeout=90)
        if not output:
            if not ok:
                last_error = f"{Path(cmd[0]).name} returned no output"
            continue
        try:
            data = json.loads(output)
        except Exception:
            data = {}
            match = re.search(r"(\{.*\})", output, re.DOTALL)
            if match:
                try:
                    data = json.loads(match.group(1))
                except Exception:
                    data = {}
            if not data:
                last_error = output[:400] or f"{Path(cmd[0]).name} returned invalid output"
                continue
        try:
            if Path(cmd[0]).name == "speedtest":
                download = round(float((data.get("download") or {}).get("bandwidth", 0)) * 8 / 1_000_000, 2)
                upload = round(float((data.get("upload") or {}).get("bandwidth", 0)) * 8 / 1_000_000, 2)
                ping_ms = round(float((data.get("ping") or {}).get("latency", 0)), 1)
            elif "speedtest" in Path(cmd[0]).name or (len(cmd) >= 3 and cmd[1:3] == ["-m", "speedtest"]):
                download = round(float(data.get("download", 0)) / 1_000_000, 2)
                upload = round(float(data.get("upload", 0)) / 1_000_000, 2)
                ping_ms = round(float(data.get("ping", 0)), 1)
            else:
                download = round(float(data.get("downloadSpeed", 0)), 2)
                upload = round(float(data.get("uploadSpeed", 0)), 2)
                ping_ms = round(float(data.get("latency", 0)), 1)
        except Exception as exc:
            last_error = f"{Path(cmd[0]).name}: {exc}"
            continue
        if download <= 0 and upload <= 0:
            last_error = output[:400] or f"{Path(cmd[0]).name} returned no throughput"
            continue
        status = "healthy" if download > 0 else "down"
        return {
            "ok": ok,
            "status": status,
            "download_mbps": download,
            "upload_mbps": upload,
            "ping_ms": ping_ms,
            "command": " ".join(cmd[:3]) if len(cmd) > 1 else cmd[0],
            "output": output,
        }
    return {
        "ok": False,
        "status": "down",
        "error": last_error,
        "output": "",
    }


def free_ips_diagnostics(target: str = "") -> dict[str, Any]:
    cidr = infer_assigned_network(target) if target and looks_like_ip(target) else ""
    if not cidr:
        networks = get_networks()
        cidr = networks[0] if networks else ""
    if not cidr:
        return {"ok": False, "status": "down", "network": "", "available": 0, "checked": 0, "items": [], "error": "No monitored network available"}
    try:
        network = ipaddress.ip_network(cidr, strict=False)
    except Exception:
        return {"ok": False, "status": "down", "network": cidr, "available": 0, "checked": 0, "items": [], "error": "Invalid network"}

    used_ips: set[str] = set()
    for device in get_devices(include_ignored=True):
        ip = str(device.get("ip", "") or "").strip()
        if not ip:
            continue
        try:
            if ipaddress.ip_address(ip) in network:
                used_ips.add(ip)
        except Exception:
            continue
    for item in arp_scan_networks() + read_proc_arp():
        ip = str(item.get("ip", "") or "").strip()
        if not ip:
            continue
        try:
            if ipaddress.ip_address(ip) in network:
                used_ips.add(ip)
        except Exception:
            continue

    all_hosts = [str(host) for host in network.hosts()]
    free_hosts = [ip for ip in all_hosts if ip not in used_ips]
    max_items = 128
    return {
        "ok": True,
        "status": "healthy" if free_hosts else "degraded",
        "network": cidr,
        "available": len(free_hosts),
        "checked": len(all_hosts),
        "items": free_hosts[:max_items],
        "truncated": len(free_hosts) > max_items,
    }


def traffic_diagnostics() -> dict[str, Any]:
    now = time.time()
    interfaces: list[dict[str, Any]] = []
    try:
        with open("/proc/net/dev", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()[2:]
    except Exception as exc:
        return {"ok": False, "status": "down", "error": str(exc), "interfaces": []}
    for line in lines:
        if ":" not in line:
            continue
        name, rest = line.split(":", 1)
        iface = name.strip()
        if iface == "lo":
            continue
        parts = rest.split()
        if len(parts) < 16:
            continue
        rx_bytes = int(parts[0])
        tx_bytes = int(parts[8])
        prev = _traffic_cache.get(iface)
        rx_rate = tx_rate = 0.0
        if prev:
            prev_rx, prev_tx, prev_ts = prev
            delta_t = max(0.001, now - prev_ts)
            rx_rate = max(0.0, (rx_bytes - prev_rx) / delta_t)
            tx_rate = max(0.0, (tx_bytes - prev_tx) / delta_t)
        _traffic_cache[iface] = (rx_bytes, tx_bytes, now)
        interfaces.append(
            {
                "name": iface,
                "rx_bps": round(rx_rate, 2),
                "tx_bps": round(tx_rate, 2),
                "rx_mbps": round((rx_rate * 8) / 1_000_000, 3),
                "tx_mbps": round((tx_rate * 8) / 1_000_000, 3),
                "total_mbps": round(((rx_rate + tx_rate) * 8) / 1_000_000, 3),
            }
        )
    interfaces.sort(key=lambda item: item["total_mbps"], reverse=True)
    return {
        "ok": True,
        "status": "healthy" if interfaces else "down",
        "interfaces": interfaces,
        "sampled_at": int(now),
    }



def arp_scan_networks() -> List[Dict[str, str]]:
    results: List[Dict[str, str]] = []
    if shutil.which("ip"):
        try:
            out = subprocess.check_output(["ip", "neigh", "show"], timeout=5).decode("utf-8", "ignore")
            for line in out.splitlines():
                parts = line.split()
                if not parts:
                    continue
                ip = parts[0]
                if "lladdr" in parts:
                    mac = parts[parts.index("lladdr") + 1]
                else:
                    mac = ""
                state = parts[-1] if parts else ""
                if mac and ip.count(".") == 3 and state.upper() != "FAILED":
                    results.append({"ip": ip, "mac": normalize_mac(mac), "vendor": vendor_from_mac(mac)})
        except Exception:
            pass
    return results

def read_proc_arp() -> List[Dict[str, str]]:
    items: List[Dict[str, str]] = []
    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 4:
                    ip, _, _, mac = parts[:4]
                    mac = normalize_mac(mac)
                    if mac and mac != "00:00:00:00:00:00":
                        items.append({"ip": ip, "mac": mac, "vendor": vendor_from_mac(mac)})
    except Exception:
        pass
    return items



def get_local_ips() -> List[str]:
    ips: List[str] = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and ip.count(".") == 3 and not ip.startswith("127."):
            ips.append(ip)
    except Exception:
        pass
    if shutil.which("ip"):
        try:
            out = subprocess.check_output(["ip", "-4", "addr", "show"], timeout=3).decode("utf-8", "ignore")
            for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/", out):
                ip = m.group(1)
                if not ip.startswith("127."):
                    ips.append(ip)
        except Exception:
            pass
    return sorted(set(ips))


def get_default_gateway() -> str:
    if shutil.which("ip"):
        try:
            out = subprocess.check_output(["ip", "route", "show", "default"], timeout=3).decode("utf-8", "ignore")
            m = re.search(r"default via\s+(\d+\.\d+\.\d+\.\d+)", out)
            if m:
                return m.group(1)
        except Exception:
            pass
    return ""


def discover_special_hosts() -> None:
    if "special" not in set(get_discovery_protocols()):
        return
    candidates = set(get_local_ips())
    gw = get_default_gateway()
    if gw:
        candidates.add(gw)
    for ip in sorted(candidates):
        try:
            scan_candidate_ip(ip, "special")
            conn = db()
            try:
                row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
                if row:
                    d = row_to_device(row)
                    if ip == gw:
                        d["name"] = d["name"] or "Gateway"
                        d["category"] = d["category"] or "network"
                    else:
                        d["name"] = d["name"] or "Home Assistant Host"
                        d["category"] = d["category"] or "server"
                        d["manual"] = True
                        d["approved"] = True
                    d["updated_at"] = now_ts()
                    upsert_device(ip, d)
            finally:
                conn.close()
        except Exception:
            pass


def scan_candidate_ip(ip: str, source: str = "ping") -> None:
    with _db_lock:
        conn = db()
        try:
            row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        finally:
            conn.close()
    if row and row["ignored"]:
        return
    discovery_mode = get_discovery_mode()
    allow_new = discovery_mode != "manual_only"
    protocols = set(get_discovery_protocols())
    ok = True
    if "ping" in protocols:
        ok = ping(ip)
        if not ok:
            return
    elif row is None and not allow_new:
        return
    host = reverse_dns(ip) if "dns" in protocols else (row["hostname"] if row else "")
    vendor = row["vendor"] if row else ""
    mac = row["mac"] if row else ""
    if not mac or not vendor:
        ident = arp_identity_for_ip(ip)
        mac = mac or ident.get("mac", "")
        vendor = vendor or ident.get("vendor", "")

    with _db_lock:
        conn = db()
        try:
            current = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
            row = current or row
            if row and row["ignored"]:
                return
            name = choose_display_name(row["name"] if row else "", host, vendor, ip)
            category = row["category"] if row and row["category"] else auto_category(f"{name} {host}", vendor)
            is_new = row is None
            prev_status = row["status"] if row else "unknown"
            is_managed = managed_row(row)
            if is_new and not allow_new:
                return
            assigned_network = row["assigned_network"] if row and "assigned_network" in row.keys() and row["assigned_network"] else infer_assigned_network(ip)
            ts = now_ts()
            conn.execute(
                """
                INSERT INTO devices(ip,name,hostname,category,vendor,mac,status,last_seen,critical,pinned,manual,ignored,approved,
                                    fail_count,success_count,state_changes_today,first_seen,updated_at,source,notes,assigned_network,tags_json)
                VALUES(?,?,?,?,?,?, 'new', ?,0,0,0,0,0,0,0,0,?,?,?,?, '[]')
                ON CONFLICT(ip) DO UPDATE SET hostname=?, last_seen=?, updated_at=?, source=?, assigned_network=CASE WHEN devices.assigned_network='' THEN excluded.assigned_network ELSE devices.assigned_network END,
                    name=CASE WHEN devices.name='' THEN excluded.name ELSE devices.name END,
                    category=CASE WHEN devices.category='' THEN excluded.category ELSE devices.category END,
                    vendor=CASE WHEN excluded.vendor!='' THEN excluded.vendor ELSE devices.vendor END,
                    mac=CASE WHEN excluded.mac!='' THEN excluded.mac ELSE devices.mac END,
                    fail_count=CASE WHEN devices.approved=1 OR devices.manual=1 THEN 0 ELSE devices.fail_count END,
                    success_count=CASE WHEN devices.approved=1 OR devices.manual=1 THEN CASE WHEN devices.success_count<1 THEN 1 ELSE devices.success_count+1 END ELSE devices.success_count END,
                    status=CASE WHEN devices.approved=1 OR devices.manual=1 THEN 'online' WHEN devices.manual=1 AND devices.status!='offline' THEN devices.status ELSE 'new' END
                """,
                (
                    ip, name, host, category, vendor, mac, ts, ts, ts, source, '', assigned_network,
                    host, ts, ts, source,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    if is_new:
        log_event("info", f"New device detected: {name or ip}", "new_device", ip)
        create_alert(ip, "medium", ALERT_TITLE_NEW, f"{name or ip} was discovered and awaits review")
    if row and is_managed and prev_status in ("offline", "unstable"):
        managed_device = row_to_device(row)
        managed_device["name"] = managed_device.get("name") or name or ip
        mark_device_recovered_with_policy(managed_device, prev_status)



def run_full_scan(mode: str = "manual") -> None:
    if scan_state["running"]:
        return
    scan_state.update({"running": True, "last_started": now_ts(), "last_mode": mode, "last_error": ""})
    log_system_event("info", f"Scan started ({mode})", "scan_started")
    try:
        protocols = set(get_discovery_protocols())
        discovery_mode = get_discovery_mode()
        monitored_networks = get_networks()
        scan_state["target_networks"] = monitored_networks
        discover_special_hosts()
        candidates: Dict[str, str] = {}
        if "ping" in protocols:
            for net in monitored_networks:
                try:
                    network = ipaddress.ip_network(net, strict=False)
                    for ip in network.hosts():
                        candidates.setdefault(str(ip), mode)
                except Exception as e:
                    scan_state["last_error"] = str(e)
        scan_state["target_count"] = len(candidates)
        log_system_event(
            "info",
            f"Scan targets prepared: {scan_state['target_count']} IPs across {len(monitored_networks)} network(s)",
            "scan_targets",
        )
        with ThreadPoolExecutor(max_workers=THREADS) as ex:
            for ip, src in candidates.items():
                ex.submit(scan_candidate_ip, ip, src)
        if "arp" in protocols or "vendor" in protocols:
            networks = [ipaddress.ip_network(n, strict=False) for n in monitored_networks]
            arp_items: Dict[str, Dict[str, str]] = {}
            for item in arp_scan_networks() + read_proc_arp():
                if item.get("ip"):
                    arp_items[item["ip"]] = item
            for item in arp_items.values():
                try:
                    ip_obj = ipaddress.ip_address(item["ip"])
                except Exception:
                    continue
                if networks and not any(ip_obj in net for net in networks):
                    continue
                conn = db()
                try:
                    row = conn.execute("SELECT * FROM devices WHERE ip=?", (item["ip"],)).fetchone()
                    if row and row["ignored"]:
                        continue
                    if row is None and discovery_mode == "manual_only":
                        continue
                    ts = now_ts()
                    host = reverse_dns(item["ip"]) if "dns" in protocols else (row["hostname"] if row else "")
                    vendor = item["vendor"] if "vendor" in protocols else (row["vendor"] if row else "")
                    if not vendor and item.get("mac"):
                        vendor = vendor_from_mac(item["mac"])
                    name = choose_display_name(row["name"] if row else "", host, vendor, item["ip"])
                    category = row["category"] if row and row["category"] else auto_category(name, vendor)
                    approved = bool(row["approved"]) if row and "approved" in row.keys() else False
                    status = row["status"] if row and row["status"] not in ("unknown", "") else ("online" if approved else "new")
                    assigned_network = row["assigned_network"] if row and row["assigned_network"] else infer_assigned_network(item["ip"])
                    prev_status = row["status"] if row else "unknown"
                    is_managed = managed_row(row)
                    conn.execute(
                        """
                        INSERT INTO devices(ip,name,hostname,category,vendor,mac,status,last_seen,critical,pinned,manual,ignored,approved,
                                            fail_count,success_count,state_changes_today,first_seen,updated_at,source,notes,assigned_network,tags_json)
                        VALUES(?,?,?,?,?,?,?,?,0,0,0,0,0,0,0,0,?,?,?,?,?, '[]')
                        ON CONFLICT(ip) DO UPDATE SET mac=excluded.mac, vendor=CASE WHEN excluded.vendor!='' THEN excluded.vendor ELSE devices.vendor END,
                            hostname=CASE WHEN excluded.hostname!='' THEN excluded.hostname ELSE devices.hostname END,
                            category=CASE WHEN devices.category='' THEN excluded.category ELSE devices.category END,
                            name=CASE WHEN devices.name='' THEN excluded.name ELSE devices.name END,
                            assigned_network=CASE WHEN devices.assigned_network='' THEN excluded.assigned_network ELSE devices.assigned_network END,
                            last_seen=CASE WHEN devices.approved=1 OR devices.manual=1 THEN devices.last_seen ELSE excluded.last_seen END,
                            fail_count=devices.fail_count,
                            success_count=devices.success_count,
                            status=CASE WHEN devices.approved=1 OR devices.manual=1 THEN devices.status
                                  ELSE CASE WHEN devices.status='unknown' THEN excluded.status ELSE devices.status END END,
                            updated_at=excluded.updated_at, source='arp'
                        """,
                        (item["ip"], name, host, category, vendor, item["mac"], status, ts, ts, ts, "arp", '', assigned_network),
                    )
                    conn.commit()
                finally:
                    conn.close()
    except Exception as e:
        scan_state["last_error"] = str(e)
    finally:
        scan_state["running"] = False
        scan_state["last_finished"] = now_ts()
        dbs = db_status_payload()
        size_kb = round((dbs.get("size") or 0)/1024, 1)
        log_system_event("info", f"Scan finished ({mode}) • DB {'OK' if dbs.get('exists') else 'MISSING'} • {size_kb} KB", "scan_finished")


def monitor_one(ip: str) -> None:
    conn = db()
    try:
        row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if not row:
            return
        d = row_to_device(row)
        fail_threshold = failure_threshold_for_device(d)
        if d["ignored"]:
            return
        ok, detected_source, ident = probe_device(ip)
        prev_state = d["status"] or "unknown"
        changed = False
        ts = now_ts()

        if ok:
            d["fail_count"] = 0
            d["success_count"] += 1
            d["last_seen"] = ts
            if ident.get("mac"):
                d["mac"] = ident["mac"]
            if ident.get("vendor") and (not d["vendor"] or d["vendor"] == "—"):
                d["vendor"] = ident["vendor"]
            host = reverse_dns(ip)
            if host and d["hostname"] != host:
                d["hostname"] = host
            d["name"] = choose_display_name(d.get("name",""), d.get("hostname",""), d.get("vendor",""), ip)
            if not d.get("assigned_network"):
                d["assigned_network"] = infer_assigned_network(ip)
            if (not d["vendor"] or d["vendor"] == "—") and d.get("mac") and "vendor" in set(get_discovery_protocols()):
                maybe_vendor = vendor_from_mac(d["mac"])
                if maybe_vendor:
                    d["vendor"] = maybe_vendor
            d["name"] = choose_display_name(d.get("name",""), d.get("hostname",""), d.get("vendor",""), ip)
            if not d["category"]:
                d["category"] = auto_category(f"{d['name']} {d['hostname']}", d["vendor"])
            if detected_source:
                d["source"] = detected_source
            if get_discovery_mode() == "manual_only" and not d.get("approved") and not d.get("manual"):
                return
            if not d.get("approved") and not d.get("manual"):
                d["status"] = "new"
            elif prev_state in ("offline", "unstable", "new", "unknown") and d["success_count"] >= RECOVER_THRESHOLD:
                d["status"] = "online"
                changed = True
        else:
            d["success_count"] = 0
            d["fail_count"] += 1
            if not d.get("approved") and not d.get("manual"):
                d["status"] = "new"
            elif d["fail_count"] >= fail_threshold and prev_state != "offline":
                d["status"] = "offline"
                changed = True

        if changed and d["status"] != prev_state:
            d["state_changes_today"] += 1
            conn.execute(
                "INSERT INTO device_history(ip,ts,old_status,new_status,kind) VALUES(?,?,?,?,?)",
                (ip, ts, prev_state, d["status"], "status"),
            )
            if should_mark_unstable(conn, ip, d) and d["status"] == "online":
                d["status"] = "unstable"
            if d["status"] == "offline":
                log_event("error", f"{d['name'] or ip} went offline", "device_offline", ip)
                create_alert_for_device(d, "high", ALERT_TITLE_OFFLINE, f"{d['name'] or ip} is offline")
            elif d["status"] == "unstable":
                msg = f"{d['name'] or ip} is unstable"
                log_event("warning", msg, "device_unstable", ip)
                create_alert_for_device(d, "medium", ALERT_TITLE_UNSTABLE, msg)
            elif d["status"] == "online":
                mark_device_recovered_with_policy(d, prev_state)

        d["updated_at"] = ts
        conn.execute(
            """
            UPDATE devices SET hostname=?, category=?, vendor=?, mac=?, status=?, last_seen=?, fail_count=?,
                success_count=?, state_changes_today=?, updated_at=?, name=?, source=?, approved=?, maintenance=?, mute_alerts=?, scan_profile=? WHERE ip=?
            """,
            (
                d["hostname"], d["category"], d["vendor"], d["mac"], d["status"], int(d["last_seen"] or 0),
                d["fail_count"], d["success_count"], d["state_changes_today"], d["updated_at"], d["name"], d["source"], 1 if d.get("approved") else 0, 1 if d.get("maintenance") else 0, 1 if d.get("mute_alerts") else 0, d.get("scan_profile", "normal"), ip,
            ),
        )
        conn.commit()
    finally:
        conn.close()


def monitor_one_safe(ip: str) -> None:
    with _db_lock:
        conn = db()
        try:
            row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        finally:
            conn.close()
    if not row:
        return
    d = row_to_device(row)
    if d["ignored"]:
        return

    ok, detected_source, ident = probe_device(ip)
    host = reverse_dns(ip) if ok else ""
    discovery_mode = get_discovery_mode()
    discovery_protocols = set(get_discovery_protocols())
    post_action: tuple[str, str, str] | None = None

    with _db_lock:
        conn = db()
        try:
            row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
            if not row:
                return
            d = row_to_device(row)
            fail_threshold = failure_threshold_for_device(d)
            if d["ignored"]:
                return
            prev_state = d["status"] or "unknown"
            changed = False
            ts = now_ts()

            if ok:
                d["fail_count"] = 0
                d["success_count"] += 1
                d["last_seen"] = ts
                if ident.get("mac"):
                    d["mac"] = ident["mac"]
                if ident.get("vendor") and (not d["vendor"] or d["vendor"] in ("—", "â€”")):
                    d["vendor"] = ident["vendor"]
                if host and d["hostname"] != host:
                    d["hostname"] = host
                if not d.get("assigned_network"):
                    d["assigned_network"] = infer_assigned_network(ip)
                if (not d["vendor"] or d["vendor"] in ("—", "â€”")) and d.get("mac") and "vendor" in discovery_protocols:
                    maybe_vendor = vendor_from_mac(d["mac"])
                    if maybe_vendor:
                        d["vendor"] = maybe_vendor
                d["name"] = choose_display_name(d.get("name", ""), d.get("hostname", ""), d.get("vendor", ""), ip)
                if not d["category"]:
                    d["category"] = auto_category(f"{d['name']} {d['hostname']}", d["vendor"])
                if detected_source:
                    d["source"] = detected_source
                if discovery_mode == "manual_only" and not d.get("approved") and not d.get("manual"):
                    return
                if not d.get("approved") and not d.get("manual"):
                    d["status"] = "new"
                elif prev_state in ("offline", "unstable", "new", "unknown") and d["success_count"] >= RECOVER_THRESHOLD:
                    d["status"] = "online"
                    changed = True
            else:
                d["success_count"] = 0
                d["fail_count"] += 1
                if not d.get("approved") and not d.get("manual"):
                    d["status"] = "new"
                elif d["fail_count"] >= fail_threshold and prev_state != "offline":
                    d["status"] = "offline"
                    changed = True

            if changed and d["status"] != prev_state:
                d["state_changes_today"] += 1
                next_state = d["status"]
                conn.execute(
                    "INSERT INTO device_history(ip,ts,old_status,new_status,kind) VALUES(?,?,?,?,?)",
                    (ip, ts, prev_state, next_state, "status"),
                )
            if should_mark_unstable(conn, ip, d) and d["status"] == "online":
                d["status"] = "unstable"
                if d["status"] == "offline":
                    post_action = ("offline", d["name"] or ip, prev_state)
                elif d["status"] == "unstable":
                    post_action = ("unstable", d["name"] or ip, prev_state)
                elif d["status"] == "online":
                    post_action = ("online", d["name"] or ip, prev_state)

            d["updated_at"] = ts
            conn.execute(
                """
                UPDATE devices SET hostname=?, category=?, vendor=?, mac=?, status=?, last_seen=?, fail_count=?,
                    success_count=?, state_changes_today=?, updated_at=?, name=?, source=?, approved=?, assigned_network=?, maintenance=?, mute_alerts=?, scan_profile=? WHERE ip=?
                """,
                (
                    d["hostname"], d["category"], d["vendor"], d["mac"], d["status"], int(d["last_seen"] or 0),
                    d["fail_count"], d["success_count"], d["state_changes_today"], d["updated_at"], d["name"], d["source"],
                    1 if d.get("approved") else 0, d.get("assigned_network", ""), 1 if d.get("maintenance") else 0, 1 if d.get("mute_alerts") else 0, d.get("scan_profile", "normal"), ip,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    if post_action:
        action, name, prev_state = post_action
        if action == "offline":
            log_event("error", f"{name} went offline", "device_offline", ip)
            create_alert_for_device(d, "high", ALERT_TITLE_OFFLINE, f"{name} is offline")
        elif action == "unstable":
            msg = f"{name} is unstable"
            log_event("warning", msg, "device_unstable", ip)
            create_alert_for_device(d, "medium", ALERT_TITLE_UNSTABLE, msg)
        elif action == "online":
            mark_device_recovered_with_policy(d, prev_state)


def run_monitor_pass(critical_only: bool = False) -> None:
    worker_name = "critical_monitor" if critical_only else "monitor"
    interval = critical_interval_seconds() if critical_only else interval_from_settings()
    set_worker_status(worker_name, last_started=now_ts(), interval=interval)
    conn = db()
    try:
        query = "SELECT ip FROM devices WHERE ignored=0"
        query += " AND critical=1" if critical_only else " AND critical=0"
        ips = [r[0] for r in conn.execute(query).fetchall()]
    finally:
        conn.close()
    error_count = 0
    first_error = ""
    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = [ex.submit(monitor_one_safe, ip) for ip in ips]
        for future in futures:
            try:
                future.result()
            except Exception as e:
                error_count += 1
                if not first_error:
                    first_error = str(e)
    set_worker_status(
        worker_name,
        last_finished=now_ts(),
        last_cycle=now_ts(),
        cycle_count=int(worker_state[worker_name]["cycle_count"]) + 1,
        last_error=(f"{error_count} device error(s): {first_error}" if error_count else ""),
    )
    if error_count:
        print(f"[HOMEii] {worker_name} pass had {error_count} error(s): {first_error}", flush=True)
        log_system_event("error", f"{worker_name} pass had {error_count} error(s): {first_error}", f"{worker_name}_pass_error")


def monitor_cycle(critical_only: bool = False) -> None:
    while True:
        try:
            run_monitor_pass(critical_only)
        except Exception as e:
            worker_name = "critical_monitor" if critical_only else "monitor"
            set_worker_status(worker_name, last_finished=now_ts(), last_error=str(e))
            print(f"[HOMEii] {worker_name} failed: {e}", flush=True)
            log_system_event("error", f"{worker_name} failed: {e}", f"{worker_name}_error")
        time.sleep(critical_interval_seconds() if critical_only else interval_from_settings())


def monitor_loop() -> None:
    monitor_cycle(False)


def critical_monitor_loop() -> None:
    monitor_cycle(True)



def rescan_loop() -> None:
    while True:
        try:
            set_worker_status("rescan", last_started=now_ts(), interval=30)
            if now_ts() - int(scan_state.get("last_finished") or 0) >= SCAN_RESCHEDULE_SECONDS:
                run_full_scan("auto")
            set_worker_status("rescan", last_finished=now_ts(), last_cycle=now_ts(), cycle_count=int(worker_state["rescan"]["cycle_count"]) + 1, last_error="")
        except Exception as e:
            set_worker_status("rescan", last_finished=now_ts(), last_error=str(e))
            log_system_event("error", f"rescan failed: {e}", "rescan_error")
        time.sleep(30)



def get_devices(include_ignored: bool = False) -> List[Dict[str, Any]]:
    conn = db()
    try:
        query = "SELECT * FROM devices"
        if not include_ignored:
            query += " WHERE ignored=0"
        query += " ORDER BY pinned DESC, critical DESC, CASE status WHEN 'offline' THEN 0 WHEN 'unstable' THEN 1 WHEN 'new' THEN 2 WHEN 'online' THEN 3 ELSE 4 END, name COLLATE NOCASE, ip"
        return [row_to_device(r) for r in conn.execute(query).fetchall()]
    finally:
        conn.close()



def status_payload() -> Dict[str, Any]:
    devices = get_devices()
    total = len(devices)
    counters = {k: 0 for k in ["online", "offline", "unstable", "new", "critical", "pinned", "manual"]}
    categories = set()
    tags = set()
    by_ip: Dict[str, Dict[str, Any]] = {}
    for d in devices:
        if d["status"] in counters:
            counters[d["status"]] += 1
        if d["critical"]:
            counters["critical"] += 1
        if d["pinned"]:
            counters["pinned"] += 1
        if d["manual"]:
            counters["manual"] += 1
        if d["category"]:
            categories.add(d["category"])
        for tag in d["tags"]:
            if tag:
                tags.add(tag)
        by_ip[d["ip"]] = d
    conn = db()
    try:
        events = [dict(r) for r in conn.execute("SELECT ts, level, event_type as type, ip, message FROM events ORDER BY id DESC LIMIT 12").fetchall()]
        alerts = [dict(r) for r in conn.execute("SELECT id, ip, severity, title, message, status, created_at, updated_at FROM alerts WHERE status='open' ORDER BY id DESC LIMIT 12").fetchall()]
    finally:
        conn.close()
    return {
        "version": APP_VERSION,
        "networks": get_networks(),
        "total": total,
        **counters,
        "devices": by_ip,
        "new_devices": {ip: d for ip, d in by_ip.items() if d["status"] == "new"},
        "categories": sorted(categories),
        "tags": sorted(tags),
        "events": events,
        "alerts": alerts,
        "scan": scan_state,
        "settings": {k: get_setting(k, v) for k, v in DEFAULT_SETTINGS.items()},
        "network_names": get_network_names(),
        "network_stats": network_stats_payload(devices),
        "discovery_mode": get_discovery_mode(),
        "discovery_protocols": get_discovery_protocols(),
        "workers": background_worker_payload(),
        "db_ok": DB_PATH.exists(),
        "db_path": str(DB_PATH),
    }


def device_detail_payload(ip: str) -> Dict[str, Any]:
    return device_detail_payload_with_window(ip)


def availability_score_for_status(status: str) -> float:
    normalized = str(status or "unknown").lower()
    if normalized == "online":
        return 100.0
    if normalized in ("unstable", "new"):
        return 50.0
    return 0.0


def local_timezone() -> ZoneInfo:
    tz_name = str(os.environ.get("TZ") or "Asia/Jerusalem")
    try:
        return ZoneInfo(tz_name)
    except Exception:
        return ZoneInfo("Asia/Jerusalem")


def history_report_payload(conn: sqlite3.Connection, ip: str, from_ts: int | None = None, to_ts: int | None = None) -> Dict[str, Any]:
    local_tz = local_timezone()
    now = int(time.time())
    to_ts = int(to_ts or now)
    default_from = datetime.fromtimestamp(to_ts, local_tz) - timedelta(days=13)
    default_from = default_from.replace(hour=0, minute=0, second=0, microsecond=0)
    from_ts = int(from_ts or default_from.timestamp())
    if from_ts >= to_ts:
        from_ts = max(0, to_ts - (14 * 86400))

    device_row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
    device = row_to_device(device_row) if device_row else {}
    fallback_status = (device.get("status") or "unknown") if device else "unknown"
    previous = conn.execute(
        "SELECT new_status, old_status FROM device_history WHERE ip=? AND kind='status' AND ts<? ORDER BY ts DESC LIMIT 1",
        (ip, from_ts),
    ).fetchone()
    start_status = (
        (previous["new_status"] if previous and previous["new_status"] else None)
        or (previous["old_status"] if previous and previous["old_status"] else None)
        or fallback_status
    )

    rows = [
        {
            "ts": int(item["ts"] or 0),
            "old_status": item["old_status"] or "unknown",
            "new_status": item["new_status"] or "unknown",
        }
        for item in conn.execute(
            "SELECT ts, old_status, new_status FROM device_history WHERE ip=? AND kind='status' AND ts>=? AND ts<? ORDER BY ts ASC",
            (ip, from_ts, to_ts),
        ).fetchall()
    ]

    def bucket_stats(bucket_start: int, bucket_end: int, initial_status: str) -> Dict[str, Any]:
        status = initial_status or "unknown"
        cursor = bucket_start
        score_seconds = 0.0
        disconnects = 0
        unstable = 0
        recoveries = 0
        changes = 0
        bucket_rows = [row for row in rows if bucket_start <= int(row["ts"]) < bucket_end]
        for row in bucket_rows:
            event_ts = int(row["ts"])
            if event_ts > cursor:
                score_seconds += ((event_ts - cursor) * availability_score_for_status(status)) / 100.0
            status = row["new_status"] or status
            changes += 1
            if status == "offline":
                disconnects += 1
            elif status == "unstable":
                unstable += 1
            elif status == "online" and (row["old_status"] or "") in ("offline", "unstable"):
                recoveries += 1
            cursor = event_ts
        if bucket_end > cursor:
            score_seconds += ((bucket_end - cursor) * availability_score_for_status(status)) / 100.0
        duration = max(1, bucket_end - bucket_start)
        return {
            "availability_pct": round((score_seconds / duration) * 100, 1),
            "disconnects": disconnects,
            "unstable": unstable,
            "recoveries": recoveries,
            "changes": changes,
            "end_state": status,
        }

    overall = bucket_stats(from_ts, to_ts, start_status)

    start_local = datetime.fromtimestamp(from_ts, local_tz).replace(hour=0, minute=0, second=0, microsecond=0)
    end_local = datetime.fromtimestamp(to_ts, local_tz).replace(hour=0, minute=0, second=0, microsecond=0)
    daily_series: list[dict[str, Any]] = []
    rolling_status = start_status
    cursor_day = start_local
    while cursor_day <= end_local:
        bucket_start = max(from_ts, int(cursor_day.timestamp()))
        bucket_end = min(to_ts, int((cursor_day + timedelta(days=1)).timestamp()))
        if bucket_end > bucket_start:
            stats = bucket_stats(bucket_start, bucket_end, rolling_status)
            daily_series.append(
                {
                    "ts": bucket_start,
                    "availability_pct": stats["availability_pct"],
                    "disconnects": stats["disconnects"],
                    "unstable": stats["unstable"],
                    "recoveries": stats["recoveries"],
                    "changes": stats["changes"],
                }
            )
            rolling_status = stats["end_state"]
        cursor_day += timedelta(days=1)

    device_rows = [row_to_device(row) for row in conn.execute("SELECT * FROM devices WHERE ignored=0").fetchall()]
    labels = {item["ip"]: (item.get("display_name") or item.get("name") or item.get("hostname") or item["ip"]) for item in device_rows if item.get("ip")}
    aggregate_rows = conn.execute(
        """
        SELECT ip,
               SUM(CASE WHEN new_status='offline' THEN 1 ELSE 0 END) AS offline_count,
               SUM(CASE WHEN new_status='unstable' THEN 1 ELSE 0 END) AS unstable_count,
               SUM(CASE WHEN new_status='online' AND old_status IN ('offline','unstable') THEN 1 ELSE 0 END) AS recovery_count,
               COUNT(*) AS total_changes
        FROM device_history
        WHERE kind='status' AND ts>=? AND ts<?
        GROUP BY ip
        """,
        (from_ts, to_ts),
    ).fetchall()
    aggregates: dict[str, dict[str, int]] = {}
    for row in aggregate_rows:
        aggregates[row["ip"]] = {
            "offline_count": int(row["offline_count"] or 0),
            "unstable_count": int(row["unstable_count"] or 0),
            "recovery_count": int(row["recovery_count"] or 0),
            "total_changes": int(row["total_changes"] or 0),
        }

    stable_rank = []
    unstable_rank = []
    offline_rank = []
    affected_devices = []
    for item in device_rows:
        ip_value = item.get("ip")
        if not ip_value:
            continue
        aggregate = aggregates.get(ip_value, {"offline_count": 0, "unstable_count": 0, "recovery_count": 0, "total_changes": 0})
        issue_score = (aggregate["offline_count"] * 4) + (aggregate["unstable_count"] * 2) + aggregate["total_changes"]
        entry = {
            "ip": ip_value,
            "name": labels.get(ip_value, ip_value),
            "offline_count": aggregate["offline_count"],
            "unstable_count": aggregate["unstable_count"],
            "recovery_count": aggregate["recovery_count"],
            "total_changes": aggregate["total_changes"],
            "value": issue_score,
        }
        stable_rank.append({**entry, "value": issue_score})
        unstable_rank.append({**entry, "value": issue_score})
        offline_rank.append({**entry, "value": aggregate["offline_count"]})
        if aggregate["offline_count"] or aggregate["unstable_count"]:
            affected_devices.append(entry)

    stable_rank = sorted(stable_rank, key=lambda item: (item["value"], item["offline_count"], item["unstable_count"], item["name"]))[:5]
    unstable_rank = sorted(unstable_rank, key=lambda item: (-item["value"], -item["offline_count"], -item["unstable_count"], item["name"]))[:5]
    offline_rank = [item for item in sorted(offline_rank, key=lambda item: (-item["value"], -item["unstable_count"], item["name"])) if item["value"] > 0][:5]
    affected_devices = sorted(affected_devices, key=lambda item: (-item["offline_count"], -item["unstable_count"], item["name"]))[:8]

    return {
        "window": {"from_ts": from_ts, "to_ts": to_ts},
        "summary": {
            "availability_pct": overall["availability_pct"],
            "disconnects": overall["disconnects"],
            "unstable": overall["unstable"],
            "recoveries": overall["recoveries"],
            "changes": overall["changes"],
        },
        "daily_series": daily_series[-14:],
        "rankings": {
            "stable": stable_rank,
            "unstable": unstable_rank,
            "offline": offline_rank,
        },
        "affected_devices": affected_devices,
        "traffic_history_available": False,
    }


def system_history_payload(from_ts: int | None = None, to_ts: int | None = None) -> Dict[str, Any]:
    conn = db()
    try:
        local_tz = local_timezone()
        now = int(time.time())
        to_ts = int(to_ts or now)
        default_from = datetime.fromtimestamp(to_ts, local_tz) - timedelta(days=13)
        default_from = default_from.replace(hour=0, minute=0, second=0, microsecond=0)
        from_ts = int(from_ts or default_from.timestamp())
        if from_ts >= to_ts:
            from_ts = max(0, to_ts - (14 * 86400))

        device_rows = [row_to_device(row) for row in conn.execute("SELECT * FROM devices WHERE ignored=0").fetchall()]
        ips = [item["ip"] for item in device_rows if item.get("ip")]
        labels = {
            item["ip"]: (item.get("display_name") or item.get("name") or item.get("hostname") or item["ip"])
            for item in device_rows
            if item.get("ip")
        }
        if not ips:
            return {
                "window": {"from_ts": from_ts, "to_ts": to_ts},
                "summary": {
                    "availability_pct": 100.0,
                    "disconnects": 0,
                    "unstable": 0,
                    "recoveries": 0,
                    "changes": 0,
                    "devices_affected": 0,
                },
                "daily_series": [],
                "rankings": {"stable": [], "unstable": [], "offline": []},
                "affected_devices": [],
                "recent_changes": [],
                "traffic_history_available": False,
            }

        placeholders = ",".join("?" for _ in ips)
        history_by_ip: Dict[str, List[Dict[str, Any]]] = {}
        for row in conn.execute(
            f"""
            SELECT ip, ts, old_status, new_status
            FROM device_history
            WHERE kind='status' AND ip IN ({placeholders}) AND ts>=? AND ts<?
            ORDER BY ip ASC, ts ASC
            """,
            (*ips, from_ts, to_ts),
        ).fetchall():
            history_by_ip.setdefault(row["ip"], []).append(
                {
                    "ts": int(row["ts"] or 0),
                    "old_status": row["old_status"] or "unknown",
                    "new_status": row["new_status"] or "unknown",
                }
            )

        start_statuses: Dict[str, str] = {}
        for item in device_rows:
            ip_value = item.get("ip")
            if not ip_value:
                continue
            previous = conn.execute(
                "SELECT new_status, old_status FROM device_history WHERE ip=? AND kind='status' AND ts<? ORDER BY ts DESC LIMIT 1",
                (ip_value, from_ts),
            ).fetchone()
            start_statuses[ip_value] = (
                (previous["new_status"] if previous and previous["new_status"] else None)
                or (previous["old_status"] if previous and previous["old_status"] else None)
                or (item.get("status") or "unknown")
            )

        def bucket_stats(ip_value: str, bucket_start: int, bucket_end: int, initial_status: str) -> Dict[str, Any]:
            status = initial_status or "unknown"
            cursor = bucket_start
            score_seconds = 0.0
            disconnects = 0
            unstable = 0
            recoveries = 0
            changes = 0
            bucket_rows = [
                row for row in history_by_ip.get(ip_value, [])
                if bucket_start <= int(row["ts"]) < bucket_end
            ]
            for row in bucket_rows:
                event_ts = int(row["ts"])
                if event_ts > cursor:
                    score_seconds += ((event_ts - cursor) * availability_score_for_status(status)) / 100.0
                status = row["new_status"] or status
                changes += 1
                if status == "offline":
                    disconnects += 1
                elif status == "unstable":
                    unstable += 1
                elif status == "online" and (row["old_status"] or "") in ("offline", "unstable"):
                    recoveries += 1
                cursor = event_ts
            if bucket_end > cursor:
                score_seconds += ((bucket_end - cursor) * availability_score_for_status(status)) / 100.0
            duration = max(1, bucket_end - bucket_start)
            return {
                "availability_pct": round((score_seconds / duration) * 100, 1),
                "disconnects": disconnects,
                "unstable": unstable,
                "recoveries": recoveries,
                "changes": changes,
                "end_state": status,
            }

        aggregate_rows = conn.execute(
            f"""
            SELECT ip,
                   SUM(CASE WHEN new_status='offline' THEN 1 ELSE 0 END) AS offline_count,
                   SUM(CASE WHEN new_status='unstable' THEN 1 ELSE 0 END) AS unstable_count,
                   SUM(CASE WHEN new_status='online' AND old_status IN ('offline','unstable') THEN 1 ELSE 0 END) AS recovery_count,
                   COUNT(*) AS total_changes
            FROM device_history
            WHERE kind='status' AND ip IN ({placeholders}) AND ts>=? AND ts<?
            GROUP BY ip
            """,
            (*ips, from_ts, to_ts),
        ).fetchall()
        aggregates: Dict[str, Dict[str, int]] = {}
        for row in aggregate_rows:
            aggregates[row["ip"]] = {
                "offline_count": int(row["offline_count"] or 0),
                "unstable_count": int(row["unstable_count"] or 0),
                "recovery_count": int(row["recovery_count"] or 0),
                "total_changes": int(row["total_changes"] or 0),
            }

        overall_availability_values: List[float] = []
        total_disconnects = 0
        total_unstable = 0
        total_recoveries = 0
        total_changes = 0
        affected_devices: List[Dict[str, Any]] = []
        stable_rank: List[Dict[str, Any]] = []
        unstable_rank: List[Dict[str, Any]] = []
        offline_rank: List[Dict[str, Any]] = []

        for item in device_rows:
            ip_value = item.get("ip")
            if not ip_value:
                continue
            overall_stats = bucket_stats(ip_value, from_ts, to_ts, start_statuses.get(ip_value, "unknown"))
            overall_availability_values.append(float(overall_stats["availability_pct"]))
            aggregate = aggregates.get(ip_value, {"offline_count": 0, "unstable_count": 0, "recovery_count": 0, "total_changes": 0})
            total_disconnects += aggregate["offline_count"]
            total_unstable += aggregate["unstable_count"]
            total_recoveries += aggregate["recovery_count"]
            total_changes += aggregate["total_changes"]
            issue_score = (aggregate["offline_count"] * 4) + (aggregate["unstable_count"] * 2) + aggregate["total_changes"]
            entry = {
                "ip": ip_value,
                "name": labels.get(ip_value, ip_value),
                "offline_count": aggregate["offline_count"],
                "unstable_count": aggregate["unstable_count"],
                "recovery_count": aggregate["recovery_count"],
                "total_changes": aggregate["total_changes"],
                "availability_pct": overall_stats["availability_pct"],
                "value": issue_score,
            }
            stable_rank.append({**entry, "value": round(overall_stats["availability_pct"], 1)})
            unstable_rank.append(entry)
            offline_rank.append({**entry, "value": aggregate["offline_count"]})
            if aggregate["offline_count"] or aggregate["unstable_count"]:
                affected_devices.append(entry)

        stable_rank = sorted(stable_rank, key=lambda item: (-item["value"], item["total_changes"], item["name"]))[:5]
        unstable_rank = sorted(unstable_rank, key=lambda item: (-item["value"], -item["offline_count"], -item["unstable_count"], item["name"]))[:5]
        offline_rank = [item for item in sorted(offline_rank, key=lambda item: (-item["value"], -item["unstable_count"], item["name"])) if item["value"] > 0][:5]
        affected_devices = sorted(affected_devices, key=lambda item: (-item["offline_count"], -item["unstable_count"], item["name"]))[:10]

        start_local = datetime.fromtimestamp(from_ts, local_tz).replace(hour=0, minute=0, second=0, microsecond=0)
        end_local = datetime.fromtimestamp(to_ts, local_tz).replace(hour=0, minute=0, second=0, microsecond=0)
        daily_series: List[Dict[str, Any]] = []
        rolling_statuses = dict(start_statuses)
        cursor_day = start_local
        while cursor_day <= end_local:
            bucket_start = max(from_ts, int(cursor_day.timestamp()))
            bucket_end = min(to_ts, int((cursor_day + timedelta(days=1)).timestamp()))
            if bucket_end > bucket_start:
                day_availability: List[float] = []
                day_disconnects = 0
                day_unstable = 0
                day_recoveries = 0
                day_changes = 0
                next_statuses = dict(rolling_statuses)
                for item in device_rows:
                    ip_value = item.get("ip")
                    if not ip_value:
                        continue
                    stats = bucket_stats(ip_value, bucket_start, bucket_end, rolling_statuses.get(ip_value, "unknown"))
                    day_availability.append(float(stats["availability_pct"]))
                    day_disconnects += int(stats["disconnects"])
                    day_unstable += int(stats["unstable"])
                    day_recoveries += int(stats["recoveries"])
                    day_changes += int(stats["changes"])
                    next_statuses[ip_value] = stats["end_state"]
                daily_series.append(
                    {
                        "ts": bucket_start,
                        "availability_pct": round(sum(day_availability) / max(1, len(day_availability)), 1),
                        "disconnects": day_disconnects,
                        "unstable": day_unstable,
                        "recoveries": day_recoveries,
                        "changes": day_changes,
                    }
                )
                rolling_statuses = next_statuses
            cursor_day += timedelta(days=1)

        recent_changes: List[Dict[str, Any]] = []
        for row in conn.execute(
            f"""
            SELECT ip, ts, old_status, new_status
            FROM device_history
            WHERE kind='status' AND ip IN ({placeholders}) AND ts>=? AND ts<?
            ORDER BY ts DESC
            LIMIT 18
            """,
            (*ips, from_ts, to_ts),
        ).fetchall():
            ip_value = row["ip"] or ""
            recent_changes.append(
                {
                    "ip": ip_value,
                    "name": labels.get(ip_value, ip_value or "—"),
                    "ts": int(row["ts"] or 0),
                    "old_status": row["old_status"] or "unknown",
                    "new_status": row["new_status"] or "unknown",
                }
            )

        return {
            "window": {"from_ts": from_ts, "to_ts": to_ts},
            "summary": {
                "availability_pct": round(sum(overall_availability_values) / max(1, len(overall_availability_values)), 1),
                "disconnects": total_disconnects,
                "unstable": total_unstable,
                "recoveries": total_recoveries,
                "changes": total_changes,
                "devices_affected": len(affected_devices),
            },
            "daily_series": daily_series[-14:],
            "rankings": {
                "stable": stable_rank,
                "unstable": unstable_rank,
                "offline": offline_rank,
            },
            "affected_devices": affected_devices,
            "recent_changes": recent_changes,
            "traffic_history_available": False,
        }
    finally:
        conn.close()


def device_detail_payload_with_window(ip: str, from_ts: int | None = None, to_ts: int | None = None) -> Dict[str, Any]:
    conn = db()
    try:
        row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if not row:
            return {"device": None, "history": [], "alerts": [], "events": [], "history_report": None}
        device = row_to_device(row)
        history = [
            {
                "ts": int(item["ts"] or 0),
                "old_status": item["old_status"] or "unknown",
                "new_status": item["new_status"] or "unknown",
            }
            for item in conn.execute(
                "SELECT ts, old_status, new_status FROM device_history WHERE ip=? AND kind='status' ORDER BY ts DESC LIMIT 32",
                (ip,),
            ).fetchall()
        ]
        alerts = [dict(item) for item in conn.execute(
            "SELECT id, ip, severity, title, message, status, created_at, updated_at FROM alerts WHERE ip=? ORDER BY id DESC LIMIT 16",
            (ip,),
        ).fetchall()]
        events = [dict(item) for item in conn.execute(
            "SELECT id, ts, level, event_type, ip, message FROM events WHERE ip=? ORDER BY id DESC LIMIT 20",
            (ip,),
        ).fetchall()]
        return {"device": device, "history": history, "alerts": alerts, "events": events, "history_report": history_report_payload(conn, ip, from_ts, to_ts)}
    finally:
        conn.close()


def viewer_categories_payload(hours: int = 24, buckets: int = 24) -> Dict[str, Any]:
    tz_name = str(os.environ.get("TZ") or "Asia/Jerusalem")
    try:
        local_tz = ZoneInfo(tz_name)
    except Exception:
        local_tz = ZoneInfo("Asia/Jerusalem")

    now = datetime.now(local_tz)
    day_start_local = now.replace(hour=0, minute=0, second=0, microsecond=0)
    bucket_starts_local = [day_start_local + timedelta(hours=idx) for idx in range(24)]
    bucket_points = [int(point.timestamp()) for point in bucket_starts_local]
    bucket_seconds = 3600
    window_start = bucket_points[0]
    window_end = bucket_points[-1] + bucket_seconds
    hours = 24
    buckets = 24

    devices = get_devices()
    grouped: Dict[str, List[Dict[str, Any]]] = {}
    for device in devices:
        key = (device.get("category") or "").strip()
        grouped.setdefault(key, []).append(device)

    history_by_ip: Dict[str, List[Dict[str, Any]]] = {}
    ips = [device["ip"] for device in devices if device.get("ip")]
    if ips:
        placeholders = ",".join("?" for _ in ips)
        conn = db()
        try:
            rows = conn.execute(
                f"""
                SELECT ip, ts, old_status, new_status
                FROM device_history
                WHERE kind='status' AND ip IN ({placeholders}) AND ts>=? AND ts<?
                ORDER BY ts ASC
                """,
                (*ips, window_start, window_end),
            ).fetchall()
        finally:
            conn.close()
        for row in rows:
            history_by_ip.setdefault(row["ip"], []).append(
                {
                    "ts": int(row["ts"] or 0),
                    "old_status": row["old_status"] or "unknown",
                    "new_status": row["new_status"] or "unknown",
                }
            )

    def device_status_at(device: Dict[str, Any], at_ts: int) -> str:
        status = device.get("status") or "unknown"
        for event in reversed(history_by_ip.get(device["ip"], [])):
            if int(event["ts"] or 0) > at_ts:
                status = event.get("old_status") or status
            else:
                break
        return status or "unknown"

    def aggregate_state(counts: Dict[str, int]) -> str:
        if counts.get("offline", 0) > 0:
            return "offline"
        if counts.get("unstable", 0) > 0:
            return "unstable"
        if counts.get("new", 0) > 0:
            return "new"
        if counts.get("online", 0) > 0:
            return "online"
        return "unknown"

    def availability_for_status(status: str) -> float:
        if status == "online":
            return 100.0
        if status in ("unstable", "new"):
            return 50.0
        return 0.0

    def hourly_availability(device: Dict[str, Any], hour_start: int, hour_end: int) -> Dict[str, Any]:
        status = device_status_at(device, hour_start)
        cursor = hour_start
        score_seconds = 0.0
        offline_events = 0
        unstable_events = 0
        events_in_hour = [
            event
            for event in history_by_ip.get(device["ip"], [])
            if hour_start <= int(event["ts"] or 0) < hour_end
        ]
        for event in events_in_hour:
            event_ts = int(event["ts"] or 0)
            if event_ts > cursor:
                score_seconds += ((event_ts - cursor) * availability_for_status(status)) / 100.0
            status = event.get("new_status") or status
            if status == "offline":
                offline_events += 1
            elif status == "unstable":
                unstable_events += 1
            cursor = event_ts
        if hour_end > cursor:
            score_seconds += ((hour_end - cursor) * availability_for_status(status)) / 100.0
        availability_pct = round((score_seconds / max(1, (hour_end - hour_start))) * 100, 1)
        return {
            "ts": hour_start,
            "state": status,
            "availability_pct": availability_pct,
            "offline_events": offline_events,
            "unstable_events": unstable_events,
        }

    device_timelines: Dict[str, Dict[str, Any]] = {}
    summary_series = []
    summary_total = max(1, len(devices))

    for device in devices:
        series = []
        total_score = 0.0
        for point in bucket_points:
            hour_data = hourly_availability(device, point, point + bucket_seconds)
            total_score += float(hour_data["availability_pct"])
            series.append(hour_data)
        device_timelines[device["ip"]] = {
            "ip": device["ip"],
            "category": device.get("category") or "",
            "availability_24h": round(total_score / max(1, len(series)), 1),
            "series": series,
        }

    for point_index, point in enumerate(bucket_points):
        counts = {"online": 0, "offline": 0, "unstable": 0, "new": 0, "unknown": 0}
        availability_sum = 0.0
        offline_events = 0
        unstable_events = 0
        for device in devices:
            device_point = device_timelines[device["ip"]]["series"][point_index]
            status = device_point["state"]
            counts[status] = counts.get(status, 0) + 1
            availability_sum += float(device_point["availability_pct"])
            offline_events += int(device_point.get("offline_events") or 0)
            unstable_events += int(device_point.get("unstable_events") or 0)
        summary_series.append(
            {
                "ts": point,
                "state": aggregate_state(counts),
                "counts": counts,
                "availability_pct": round(availability_sum / summary_total, 1),
                "offline_events": offline_events,
                "unstable_events": unstable_events,
            }
        )

    payload = []
    for category, category_devices in grouped.items():
        current_counts = {"online": 0, "offline": 0, "unstable": 0, "new": 0, "unknown": 0}
        for device in category_devices:
            current_counts[device.get("status") or "unknown"] = current_counts.get(device.get("status") or "unknown", 0) + 1

        series = []
        availability_total = 0.0
        for point_index, point in enumerate(bucket_points):
            counts = {"online": 0, "offline": 0, "unstable": 0, "new": 0, "unknown": 0}
            availability_sum = 0.0
            offline_events = 0
            unstable_events = 0
            for device in category_devices:
                device_point = device_timelines[device["ip"]]["series"][point_index]
                counts[device_point["state"]] = counts.get(device_point["state"], 0) + 1
                availability_sum += float(device_point["availability_pct"])
                offline_events += int(device_point.get("offline_events") or 0)
                unstable_events += int(device_point.get("unstable_events") or 0)
            availability_pct = round(availability_sum / max(1, len(category_devices)), 1)
            availability_total += availability_pct
            series.append(
                {
                    "ts": point,
                    "state": aggregate_state(counts),
                    "counts": counts,
                    "availability_pct": availability_pct,
                    "offline_events": offline_events,
                    "unstable_events": unstable_events,
                }
            )

        payload.append(
            {
                "category": category,
                "total": len(category_devices),
                "online": current_counts.get("online", 0),
                "offline": current_counts.get("offline", 0),
                "unstable": current_counts.get("unstable", 0),
                "new": current_counts.get("new", 0),
                "critical": sum(1 for device in category_devices if device.get("critical")),
                "pinned": sum(1 for device in category_devices if device.get("pinned")),
                "state": aggregate_state(current_counts),
                "devices": [device["ip"] for device in category_devices],
                "availability_24h": round(availability_total / max(1, len(series)), 1),
                "series": series,
            }
        )

    def sort_key(item: Dict[str, Any]):
        severity = {"offline": 0, "unstable": 1, "new": 2, "online": 3, "unknown": 4}
        return (severity.get(item["state"], 9), -int(item["total"]), str(item["category"]).lower())

    payload.sort(key=sort_key)
    return {
        "generated_at": now,
        "hours": hours,
        "bucket_seconds": bucket_seconds,
        "categories": payload,
        "devices": device_timelines,
        "summary": {
            "availability_24h": round(
                sum(float(point["availability_pct"]) for point in summary_series) / max(1, len(summary_series)),
                1,
            ),
            "series": summary_series,
        },
    }


def ha_summary_payload() -> Dict[str, Any]:
    status = status_payload()
    conn = db()
    try:
        open_alerts_row = conn.execute("SELECT COUNT(*) FROM alerts WHERE status='open'").fetchone()
        event_count_row = conn.execute("SELECT COUNT(*) FROM events").fetchone()
    finally:
        conn.close()
    return {
        "product": {
            "name": "HOMEii Network Monitor",
            "version": APP_VERSION,
            "integration_target": "home_assistant",
        },
        "scan": status["scan"],
        "counts": {
            "total": status["total"],
            "online": status["online"],
            "offline": status["offline"],
            "unstable": status["unstable"],
            "new": status["new"],
            "critical": status["critical"],
            "pinned": status["pinned"],
            "manual": status["manual"],
            "open_alerts": int(open_alerts_row[0] if open_alerts_row else 0),
            "events": int(event_count_row[0] if event_count_row else 0),
        },
        "networks": status["networks"],
        "network_names": status["network_names"],
        "db": {
            "ok": status["db_ok"],
            "path": status["db_path"],
        },
    }


def ha_entities_payload() -> Dict[str, Any]:
    devices = get_devices()
    summary = ha_summary_payload()
    counters = []
    for key, name, icon in [
        ("online", "Connected devices", "mdi:lan-connect"),
        ("offline", "Disconnected devices", "mdi:lan-disconnect"),
        ("new", "New devices", "mdi:new-box"),
        ("critical", "Critical devices", "mdi:alert"),
        ("open_alerts", "Open alerts", "mdi:alert-circle-outline"),
        ("total", "Total devices", "mdi:counter"),
    ]:
        counters.append(
            {
                "entity_id": f"sensor.homeii_{key}",
                "unique_id": f"homeii_{key}",
                "name": name,
                "icon": icon,
                "state": summary["counts"][key],
                "kind": "sensor",
            }
        )

    availability = []
    for device in devices:
        safe_ip = device["ip"].replace(".", "_")
        unique_suffix = normalize_mac(device.get("mac", "")) or device["ip"]
        availability.append(
            {
                "entity_id": f"binary_sensor.homeii_{safe_ip}_availability",
                "unique_id": f"homeii_device_{unique_suffix}_availability",
                "name": device["display_name"],
                "kind": "binary_sensor",
                "device_class": "connectivity",
                "state": device["status"] in ("online", "unstable"),
                "status": device["status"],
                "ip": device["ip"],
                "mac": device["mac"],
                "vendor": device["vendor"],
                "network": device["assigned_network"],
                "category": device["category"],
                "last_seen": device["last_seen"],
            }
        )

    return {
        "summary": summary,
        "entities": {
            "counters": counters,
            "availability": availability,
        },
    }


def ha_diagnostics_payload() -> Dict[str, Any]:
    return {
        "summary": ha_summary_payload(),
        "devices": get_devices(),
        "alerts": api_alerts(limit=200)["alerts"],
        "events": api_events(limit=200)["events"],
        "settings": api_settings(),
    }


@app.get("/")
def root():
    return FileResponse("/app/web/index.html", headers=NO_CACHE_HEADERS)


@app.get("/settings.html")
def settings_page():
    return FileResponse("/app/web/settings.html", headers=NO_CACHE_HEADERS)


@app.get("/viewer")
def viewer_page():
    return FileResponse("/app/web/index.html", headers=NO_CACHE_HEADERS)


@app.get("/viewer.html")
def viewer_html_page():
    return FileResponse("/app/web/index.html", headers=NO_CACHE_HEADERS)


@app.get("/logo")
def logo():
    path = "/app/web/logo.gif"
    if os.path.exists(path):
        return FileResponse(path, media_type="image/gif")
    return JSONResponse({"error": "logo not found"}, status_code=404)


@app.get("/api/status")
def api_status():
    ensure_background_workers()
    return status_payload()


@app.get("/api/viewer/categories")
def api_viewer_categories(hours: int = 24, buckets: int = 24):
    ensure_background_workers()
    return viewer_categories_payload(hours=hours, buckets=buckets)


@app.get("/api/devices")
def api_devices():
    ensure_background_workers()
    return {"devices": get_devices()}


@app.get("/api/device/{ip}/detail")
def api_device_detail(ip: str, from_ts: int | None = Query(None), to_ts: int | None = Query(None)):
    ensure_background_workers()
    return device_detail_payload_with_window(ip, from_ts, to_ts)


@app.get("/api/history/summary")
def api_history_summary(from_ts: int | None = Query(None), to_ts: int | None = Query(None)):
    ensure_background_workers()
    return system_history_payload(from_ts, to_ts)


@app.get("/api/alerts")
def api_alerts(limit: int = 50):
    conn = db()
    try:
        rows = conn.execute(
            "SELECT id, ip, severity, title, message, status, created_at, updated_at FROM alerts ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 500)),),
        ).fetchall()
        return {"alerts": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/events")
def api_events(limit: int = 50):
    conn = db()
    try:
        rows = conn.execute(
            "SELECT id, ts, level, event_type, ip, message FROM events ORDER BY id DESC LIMIT ?",
            (max(1, min(limit, 500)),),
        ).fetchall()
        return {"events": [dict(r) for r in rows]}
    finally:
        conn.close()


@app.get("/api/settings")
def api_settings():
    ensure_background_workers()
    conn = db()
    try:
        rows = conn.execute("SELECT key, value FROM settings ORDER BY key").fetchall()
        return {"settings": {r["key"]: r["value"] for r in rows}, "networks": get_networks(), "network_names": get_network_names(), "discovery_mode": get_discovery_mode(), "discovery_protocols": get_discovery_protocols(), "db_path": str(DB_PATH), "workers": background_worker_payload()}
    finally:
        conn.close()


@app.post("/api/tools/run")
async def api_tools_run(request: Request):
    payload = await request.json()
    target = str(payload.get("target", "") or "").strip()
    requested_tools = payload.get("tools", ["ping", "trace", "ports", "dns"])
    if not isinstance(requested_tools, list):
        requested_tools = ["ping", "trace", "ports", "dns"]
    selected_tools = [str(item).strip().lower() for item in requested_tools if str(item).strip()]
    needs_target = any(item in {"ping", "trace", "ports", "dns", "all"} for item in selected_tools)
    if needs_target and not target:
        return JSONResponse({"ok": False, "error": "Missing target"}, status_code=400)
    if needs_target and not looks_like_ip(target):
        return JSONResponse({"ok": False, "error": "Target must be an IP address"}, status_code=400)
    if not target and "speed" in selected_tools and not needs_target:
        target = "internet"

    ports = parse_ports(payload.get("ports", "80,443,554,8000,8080,22"))
    if not ports:
        ports = [80, 443, 554, 8000, 8080, 22]

    result: dict[str, Any] = {
        "ok": True,
        "target": target,
        "requested_tools": selected_tools,
        "started_at": now_ts(),
        "tools": {},
    }
    if "ping" in selected_tools or "all" in selected_tools:
        result["tools"]["ping"] = ping_diagnostics(target, int(payload.get("ping_count", 4) or 4))
    if "trace" in selected_tools or "all" in selected_tools:
        result["tools"]["trace"] = trace_diagnostics(target, int(payload.get("max_hops", 12) or 12))
    if "ports" in selected_tools or "all" in selected_tools:
        result["tools"]["ports"] = port_scan_diagnostics(target, ports)
    if "dns" in selected_tools or "all" in selected_tools:
        result["tools"]["dns"] = dns_diagnostics(target)
    if "speed" in selected_tools or "all" in selected_tools:
        result["tools"]["speed"] = speedtest_diagnostics()
    if "free_ips" in selected_tools:
        result["tools"]["free_ips"] = free_ips_diagnostics(target)

    status_rank = {"healthy": 0, "degraded": 1, "down": 2}
    overall = "healthy"
    for tool_payload in result["tools"].values():
        tool_status = str(tool_payload.get("status", "healthy"))
        if status_rank.get(tool_status, 0) > status_rank.get(overall, 0):
            overall = tool_status
    result["overall_status"] = overall
    result["finished_at"] = now_ts()
    return result


@app.get("/api/tools/traffic")
def api_tools_traffic():
    return traffic_diagnostics()


@app.get("/api/export/devices.csv")
def api_export_devices_csv():
    rows = get_devices(include_ignored=True)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ip", "display_name", "hostname", "vendor", "category", "status", "assigned_network", "mac", "last_seen", "approved", "manual", "critical", "pinned", "maintenance", "mute_alerts", "scan_profile", "notes"])
    for device in rows:
        writer.writerow([
            device.get("ip", ""),
            device.get("display_name", ""),
            device.get("hostname", ""),
            device.get("vendor", ""),
            device.get("category", ""),
            device.get("status", ""),
            device.get("assigned_network", ""),
            device.get("mac", ""),
            device.get("last_seen", ""),
            1 if device.get("approved") else 0,
            1 if device.get("manual") else 0,
            1 if device.get("critical") else 0,
            1 if device.get("pinned") else 0,
            1 if device.get("maintenance") else 0,
            1 if device.get("mute_alerts") else 0,
            device.get("scan_profile", "normal"),
            device.get("notes", ""),
        ])
    return Response(
        content=output.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="homeii_devices.csv"'},
    )


@app.get("/api/export/settings.json")
def api_export_settings_json():
    payload = {
        "version": APP_VERSION,
        "exported_at": now_ts(),
        "settings": {k: get_setting(k, v) for k, v in DEFAULT_SETTINGS.items()},
        "networks": get_networks(),
        "network_names": get_network_names(),
        "discovery_mode": get_discovery_mode(),
        "discovery_protocols": get_discovery_protocols(),
    }
    return Response(
        content=json.dumps(payload, ensure_ascii=False, indent=2),
        media_type="application/json; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="homeii_settings.json"'},
    )


def csv_bool(value: Any) -> bool:
    text = str(value or "").strip().lower()
    return text in {"1", "true", "yes", "on", "y"}


def csv_int(value: Any, default: int = 0) -> int:
    try:
        return int(float(str(value or "").strip()))
    except Exception:
        return default


@app.post("/api/import/devices")
async def api_import_devices(file: UploadFile = File(...)):
    raw = await file.read()
    text = raw.decode("utf-8-sig", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    imported = 0
    skipped = 0
    for row in reader:
        ip = str((row or {}).get("ip", "")).strip()
        if not ip:
            skipped += 1
            continue
        display_name = str(row.get("display_name", "")).strip()
        hostname = str(row.get("hostname", "")).strip()
        vendor = str(row.get("vendor", "")).strip()
        category = str(row.get("category", "")).strip()
        assigned_network = str(row.get("assigned_network", "")).strip() or infer_assigned_network(ip)
        if assigned_network and assigned_network not in get_networks():
            inferred = infer_assigned_network(ip)
            assigned_network = inferred or assigned_network
        upsert_device(ip, {
            "name": display_name,
            "hostname": hostname,
            "vendor": vendor,
            "category": category,
            "status": str(row.get("status", "")).strip() or "unknown",
            "assigned_network": assigned_network,
            "mac": str(row.get("mac", "")).strip(),
            "last_seen": csv_int(row.get("last_seen"), 0),
            "approved": csv_bool(row.get("approved")),
            "manual": csv_bool(row.get("manual")),
            "critical": csv_bool(row.get("critical")),
            "pinned": csv_bool(row.get("pinned")),
            "maintenance": csv_bool(row.get("maintenance")),
            "mute_alerts": csv_bool(row.get("mute_alerts")),
            "scan_profile": normalize_scan_profile(row.get("scan_profile")),
            "notes": str(row.get("notes", "")).strip(),
            "updated_at": now_ts(),
            "source": "import",
        })
        imported += 1
    if imported:
        refresh_assigned_networks()
        log_system_event("info", f"Imported {imported} device(s) from CSV", "devices_imported")
    return {"ok": True, "imported": imported, "skipped": skipped}


@app.post("/api/import/settings")
async def api_import_settings(file: UploadFile = File(...)):
    raw = await file.read()
    try:
        payload = json.loads(raw.decode("utf-8-sig", errors="ignore") or "{}")
    except Exception:
        return JSONResponse({"ok": False, "error": "Invalid settings file"}, status_code=400)
    if not isinstance(payload, dict):
        return JSONResponse({"ok": False, "error": "Invalid settings file"}, status_code=400)
    incoming_settings = payload.get("settings", {})
    if not isinstance(incoming_settings, dict):
        incoming_settings = {}
    for key, default in DEFAULT_SETTINGS.items():
        if key in {"networks_json", "network_names_json", "discovery_mode", "discovery_protocols_json"}:
            continue
        if key in incoming_settings:
            set_setting(key, str(incoming_settings.get(key, default) or default))
    networks = normalize_networks(payload.get("networks", [])) or get_networks()
    saved = save_networks(networks)
    names = normalize_network_name_map(payload.get("network_names", {}), saved)
    set_setting("network_names_json", json.dumps(names, ensure_ascii=False))
    discovery_mode = str(payload.get("discovery_mode", incoming_settings.get("discovery_mode", get_discovery_mode())) or get_discovery_mode())
    set_setting("discovery_mode", discovery_mode if discovery_mode in ("auto_manual", "manual_only", "auto_only") else "auto_manual")
    set_discovery_protocols(payload.get("discovery_protocols", incoming_settings.get("discovery_protocols_json", get_discovery_protocols())))
    reassigned = refresh_assigned_networks(saved)
    log_system_event("info", f"Imported settings profile with {len(saved)} network(s)", "settings_imported")
    return {
        "ok": True,
        "networks": saved,
        "network_names": get_network_names(),
        "discovery_mode": get_discovery_mode(),
        "discovery_protocols": get_discovery_protocols(),
        "reassigned": reassigned,
    }


@app.get("/api/ha/summary")
def api_ha_summary():
    return ha_summary_payload()


@app.get("/api/ha/entities")
def api_ha_entities():
    return ha_entities_payload()


@app.get("/api/ha/diagnostics")
def api_ha_diagnostics():
    return ha_diagnostics_payload()


def run_scan_job(mode: str = "manual") -> None:
    run_full_scan(mode)
    run_monitor_pass(False)
    run_monitor_pass(True)


@app.get("/api/scan")
def api_scan(mode: str = Query("manual")):
    threading.Thread(target=run_scan_job, args=(mode,), daemon=True).start()
    return {"ok": True, "scan": scan_state}



@app.get("/api/accept/{ip}")
def api_accept(ip: str):
    ok = ping(ip)
    conn = db()
    try:
        row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if not row:
            scan_candidate_ip(ip, "accept")
            row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if row:
            d = row_to_device(row)
            d["approved"] = True
            d["status"] = "online" if ok else "offline"
            if ok:
                d["last_seen"] = now_ts()
                d["success_count"] = max(1, d["success_count"])
            upsert_device(ip, d)
            resolve_alerts_for_ip(ip, ALERT_TITLE_NEW)
            log_event("success", f"Accepted device {d['name'] or ip}", "device_accepted", ip)
        return {"ok": True, "status": "online" if ok else "offline"}
    finally:
        conn.close()


@app.get("/api/accept_all")
def api_accept_all():
    conn = db()
    try:
        rows = conn.execute("SELECT ip FROM devices WHERE ignored=0 AND approved=0").fetchall()
    finally:
        conn.close()
    for row in rows:
        try:
            api_accept(row[0])
        except Exception:
            pass
    return {"ok": True, "count": len(rows)}


@app.get("/api/add/{ip}")
def api_add(ip: str):
    return api_accept(ip)


@app.get("/api/add_all")
def api_add_all():
    return api_accept_all()


@app.get("/api/remove/{ip}")
def api_remove(ip: str):
    with _db_lock:
        conn = db()
        try:
            conn.execute("DELETE FROM devices WHERE ip=?", (ip,))
            conn.execute("DELETE FROM device_history WHERE ip=?", (ip,))
            conn.execute("UPDATE alerts SET status='resolved', updated_at=? WHERE ip=? AND status='open'", (now_ts(), ip))
            conn.commit()
        finally:
            conn.close()
    log_event("info", f"Removed device {ip}", "device_removed", ip)
    return {"ok": True}


@app.get("/api/delete_device")
def api_delete_device(ip: str):
    return api_remove(ip)


@app.get("/api/ignore/{ip}")
def api_ignore(ip: str):
    with _db_lock:
        conn = db()
        try:
            conn.execute(
                "INSERT INTO devices(ip,ignored,updated_at,first_seen,source) VALUES(?,1,?,?,?) ON CONFLICT(ip) DO UPDATE SET ignored=1, updated_at=excluded.updated_at",
                (ip, now_ts(), now_ts(), "ignored"),
            )
            conn.commit()
        finally:
            conn.close()
    log_event("info", f"Ignored device {ip}", "device_ignored", ip)
    return {"ok": True}


@app.get("/api/update")
def api_update(ip: str, name: str = "", category: str = "", tags: str = "", notes: str = "", assigned_network: str = "", scan_profile: str = "normal", maintenance: int = -1, mute_alerts: int = -1, pinned: int = -1, critical: int = -1):
    conn = db()
    try:
        row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if row:
            d = row_to_device(row)
            d["name"] = unquote(name)
            d["category"] = unquote(category)
            d["notes"] = unquote(notes)
            d["assigned_network"] = unquote(assigned_network)
            d["scan_profile"] = normalize_scan_profile(unquote(scan_profile))
            d["tags"] = [x.strip() for x in unquote(tags).split(",") if x.strip()]
            if maintenance in (0,1):
                d["maintenance"] = bool(maintenance)
            if mute_alerts in (0,1):
                d["mute_alerts"] = bool(mute_alerts)
            if pinned in (0,1):
                d["pinned"] = bool(pinned)
            if critical in (0,1):
                d["critical"] = bool(critical)
            d["updated_at"] = now_ts()
            upsert_device(ip, d)
            if d.get("maintenance") or d.get("mute_alerts"):
                resolve_alerts_for_ip(ip)
        return {"ok": True}
    finally:
        conn.close()


@app.get("/api/toggle_critical/{ip}")
def api_toggle_critical(ip: str):
    conn = db()
    try:
        row = conn.execute("SELECT critical FROM devices WHERE ip=?", (ip,)).fetchone()
        if not row:
            return {"ok": False}
        new_value = 0 if row[0] else 1
        conn.execute("UPDATE devices SET critical=?, updated_at=? WHERE ip=?", (new_value, now_ts(), ip))
        conn.commit()
        return {"ok": True, "critical": bool(new_value)}
    finally:
        conn.close()




@app.get("/api/bulk_update")
def api_bulk_update(ips: str, pinned: int = -1, critical: int = -1, category: str = "", assigned_network: str = ""):
    ip_list = [x.strip() for x in unquote(ips).split(",") if x.strip()]
    if not ip_list:
        return {"ok": False, "updated": 0}
    conn = db()
    try:
        updated = 0
        for ip in ip_list:
            row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
            if not row:
                continue
            d = row_to_device(row)
            if pinned in (0, 1):
                d["pinned"] = bool(pinned)
            if critical in (0, 1):
                d["critical"] = bool(critical)
            if category != "":
                d["category"] = unquote(category)
            if assigned_network != "":
                d["assigned_network"] = unquote(assigned_network)
            d["updated_at"] = now_ts()
            upsert_device(ip, d)
            updated += 1
        log_event("info", f"Bulk update on {updated} devices", "bulk_update")
        return {"ok": True, "updated": updated}
    finally:
        conn.close()


@app.get("/api/bulk_delete")
def api_bulk_delete(ips: str):
    ip_list = [x.strip() for x in unquote(ips).split(",") if x.strip()]
    if not ip_list:
        return {"ok": False, "deleted": 0}
    conn = db()
    try:
        for ip in ip_list:
            conn.execute("DELETE FROM devices WHERE ip=?", (ip,))
        conn.commit()
        log_event("warning", f"Bulk removed {len(ip_list)} devices", "bulk_delete")
        return {"ok": True, "deleted": len(ip_list)}
    finally:
        conn.close()

@app.get("/api/toggle_pinned/{ip}")
def api_toggle_pinned(ip: str):
    conn = db()
    try:
        row = conn.execute("SELECT pinned FROM devices WHERE ip=?", (ip,)).fetchone()
        if not row:
            return {"ok": False}
        new_value = 0 if row[0] else 1
        conn.execute("UPDATE devices SET pinned=?, updated_at=? WHERE ip=?", (new_value, now_ts(), ip))
        conn.commit()
        return {"ok": True, "pinned": bool(new_value)}
    finally:
        conn.close()


@app.get("/api/ping_now/{ip}")
def api_ping_now(ip: str):
    ok = ping(ip)
    conn = db()
    try:
        row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if row:
            d = row_to_device(row)
            d["status"] = "online" if ok else "offline"
            if ok:
                d["last_seen"] = now_ts()
            d["updated_at"] = now_ts()
            upsert_device(ip, d)
        return {"ok": ok}
    finally:
        conn.close()


@app.get("/api/add_manual")
def api_add_manual(ip: str, name: str = "", category: str = "", notes: str = ""):
    host = reverse_dns(ip)
    vendor = ""
    d = {
        "name": choose_display_name(name, host, vendor, ip),
        "hostname": host,
        "category": category or auto_category(name or host or ip, vendor),
        "vendor": vendor,
        "mac": "",
        "status": "online" if ping(ip) else "offline",
        "last_seen": now_ts() if ping(ip) else 0,
        "critical": False,
        "pinned": False,
        "manual": True,
        "ignored": False,
        "approved": True,
        "fail_count": 0,
        "success_count": 1 if ping(ip) else 0,
        "state_changes_today": 0,
        "first_seen": now_ts(),
        "updated_at": now_ts(),
        "source": "manual",
        "notes": notes,
        "assigned_network": infer_assigned_network(ip),
        "maintenance": False,
        "mute_alerts": False,
        "scan_profile": "normal",
        "tags": [],
    }
    upsert_device(ip, d)
    log_event("info", f"Manual device added: {name or ip}", "device_manual", ip)
    return {"ok": True}


@app.get("/api/resolve_alert/{alert_id}")
def api_resolve_alert(alert_id: int):
    conn = db()
    try:
        conn.execute("UPDATE alerts SET status='resolved', updated_at=? WHERE id=?", (now_ts(), alert_id))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.get("/api/save_settings")
def api_save_settings(auto_refresh: str = "30", default_view: str = "table", dashboard_style: str = "advanced", theme: str = "light", language: str = "he", status_animation: str = "blink", networks: str = "", network_names: str = "", discovery_mode: str = "auto_manual", discovery_protocols: str = ""):
    set_setting("auto_refresh", auto_refresh or "30")
    set_setting("default_view", default_view or "table")
    set_setting("dashboard_style", dashboard_style or "advanced")
    set_setting("theme", theme if theme in ("light", "dark") else "light")
    set_setting("language", language if language in ("he", "en") else "he")
    set_setting("status_animation", status_animation if status_animation in ("blink", "static") else "blink")
    set_setting("discovery_mode", discovery_mode if discovery_mode in ("auto_manual", "manual_only", "auto_only") else "auto_manual")
    set_discovery_protocols(discovery_protocols or KNOWN_PROTOCOLS)
    saved_networks = get_networks()
    reassigned = 0
    if networks.strip():
        saved_networks = save_networks(networks)
        reassigned = refresh_assigned_networks(saved_networks)
    try:
        data = json.loads(unquote(network_names or "{}"))
        normalized_names = normalize_network_name_map(data, saved_networks)
        set_setting("network_names_json", json.dumps(normalized_names, ensure_ascii=False))
    except Exception:
        pass
    return {"ok": True, "networks": get_networks(), "network_names": get_network_names(), "network_stats": network_stats_payload(), "discovery_mode": get_discovery_mode(), "discovery_protocols": get_discovery_protocols(), "reassigned": reassigned}


@app.post("/api/save_settings")
async def api_save_settings_post(request: Request):
    payload = await request.json()
    networks_raw = parse_network_input(payload.get("networks", ""))
    protocols_raw = payload.get("discovery_protocols", "")
    if isinstance(protocols_raw, list):
        protocols_raw = ",".join(str(item).strip() for item in protocols_raw if str(item).strip())
    return api_save_settings(
        auto_refresh=str(payload.get("auto_refresh", "30") or "30"),
        default_view=str(payload.get("default_view", "table") or "table"),
        dashboard_style=str(payload.get("dashboard_style", "advanced") or "advanced"),
        theme=str(payload.get("theme", "light") or "light"),
        language=str(payload.get("language", "he") or "he"),
        status_animation=str(payload.get("status_animation", "blink") or "blink"),
        networks="\n".join(networks_raw) if isinstance(networks_raw, list) else str(networks_raw),
        network_names=json.dumps(payload.get("network_names", {}) or {}, ensure_ascii=False),
        discovery_mode=str(payload.get("discovery_mode", "auto_manual") or "auto_manual"),
        discovery_protocols=str(protocols_raw),
    )


@app.get("/api/save_networks")
def api_save_networks(networks: str = "", network_names: str = ""):
    saved = save_networks(networks)
    reassigned = refresh_assigned_networks(saved)
    try:
        data = json.loads(unquote(network_names or "{}"))
        normalized_names = normalize_network_name_map(data, saved)
        set_setting("network_names_json", json.dumps(normalized_names, ensure_ascii=False))
    except Exception:
        pass
    return {"ok": True, "networks": saved, "network_names": get_network_names(), "network_stats": network_stats_payload(), "reassigned": reassigned}


@app.post("/api/save_networks")
async def api_save_networks_post(request: Request):
    payload = await request.json()
    networks_raw = parse_network_input(payload.get("networks", ""))
    network_names_raw = payload.get("network_names", {}) or {}
    return api_save_networks(
        networks="\n".join(networks_raw) if isinstance(networks_raw, list) else str(networks_raw),
        network_names=json.dumps(network_names_raw, ensure_ascii=False),
    )


def start_worker(name: str, target, *args) -> None:
    with _worker_lock:
        thread = _worker_threads.get(name)
        if thread and thread.is_alive():
            return
        thread = threading.Thread(target=target, args=args, daemon=True, name=f"homeii-{name}")
        _worker_threads[name] = thread
        thread.start()


def start_background_workers() -> None:
    start_worker("monitor", monitor_loop)
    start_worker("critical_monitor", critical_monitor_loop)
    start_worker("rescan", rescan_loop)
    start_worker("special_hosts", discover_special_hosts)
    start_worker("startup_scan", run_full_scan, "startup")


def ensure_background_workers() -> None:
    start_background_workers()
    now = now_ts()
    monitor = worker_state.get("monitor", {})
    critical = worker_state.get("critical_monitor", {})
    if now - int(monitor.get("last_cycle") or 0) > max(45, interval_from_settings() * 2):
        start_worker("monitor_kick", run_monitor_pass, False)
    if now - int(critical.get("last_cycle") or 0) > max(30, critical_interval_seconds() * 2):
        start_worker("critical_monitor_kick", run_monitor_pass, True)


@app.on_event("startup")
def app_startup() -> None:
    start_background_workers()


init_db()
start_background_workers()
