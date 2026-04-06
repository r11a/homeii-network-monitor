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
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import unquote

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
FAIL_THRESHOLD = 1
RECOVER_THRESHOLD = 1
UNSTABLE_WINDOW = 600
UNSTABLE_THRESHOLD = 4
MAX_EVENTS = 300
SCAN_RESCHEDULE_SECONDS = 180
KNOWN_PROTOCOLS = ["ping", "arp", "dns", "special", "vendor"]
ALERT_TITLE_NEW = "New device detected"
ALERT_TITLE_OFFLINE = "Device offline"
ALERT_TITLE_BACK_ONLINE = "Device back online"
ALERT_TITLE_UNSTABLE = "Device unstable"


def load_options() -> Dict[str, Any]:
    try:
        with open("/data/options.json", "r", encoding="utf-8") as f:
            opts = json.load(f)
            return opts if isinstance(opts, dict) else {}
    except Exception:
        return {}


OPTIONS = load_options()
HOMEII_NETWORKS = OPTIONS.get("networks", ["192.168.1.0/24"])

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



def upsert_device(ip: str, fields: Dict[str, Any]) -> None:
    conn = db()
    try:
        current = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        base = row_to_device(current) if current else {
            "ip": ip, "name": "", "hostname": "", "category": "", "vendor": "", "mac": "",
            "status": "unknown", "last_seen": 0, "critical": False, "pinned": False, "manual": False,
            "ignored": False, "approved": False, "fail_count": 0, "success_count": 0, "state_changes_today": 0,
            "first_seen": now_ts(), "updated_at": now_ts(), "source": "", "notes": "", "assigned_network": "", "tags": []
        }
        base.update(fields)
        conn.execute(
            """
            INSERT INTO devices(
              ip,name,hostname,category,vendor,mac,status,last_seen,critical,pinned,manual,ignored,approved,
              fail_count,success_count,state_changes_today,first_seen,updated_at,source,notes,assigned_network,tags_json
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(ip) DO UPDATE SET
              name=excluded.name, hostname=excluded.hostname, category=excluded.category, vendor=excluded.vendor,
              mac=excluded.mac, status=excluded.status, last_seen=excluded.last_seen, critical=excluded.critical,
              pinned=excluded.pinned, manual=excluded.manual, ignored=excluded.ignored, approved=excluded.approved,
              fail_count=excluded.fail_count, success_count=excluded.success_count,
              state_changes_today=excluded.state_changes_today, first_seen=excluded.first_seen,
              updated_at=excluded.updated_at, source=excluded.source, notes=excluded.notes, assigned_network=excluded.assigned_network, tags_json=excluded.tags_json
            """,
            (
                ip,
                base["name"], base["hostname"], base["category"], base["vendor"], base["mac"],
                base["status"], int(base["last_seen"] or 0), 1 if base["critical"] else 0,
                1 if base["pinned"] else 0, 1 if base["manual"] else 0, 1 if base["ignored"] else 0, 1 if base.get("approved") else 0,
                int(base["fail_count"] or 0), int(base["success_count"] or 0), int(base["state_changes_today"] or 0),
                int(base["first_seen"] or now_ts()), int(base["updated_at"] or now_ts()), base["source"],
                base["notes"], base.get("assigned_network", ""), json.dumps(base["tags"]),
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
        mark_device_recovered(ip, name, prev_status)



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
            elif d["fail_count"] >= FAIL_THRESHOLD and prev_state != "offline":
                d["status"] = "offline"
                changed = True

        if changed and d["status"] != prev_state:
            d["state_changes_today"] += 1
            conn.execute(
                "INSERT INTO device_history(ip,ts,old_status,new_status,kind) VALUES(?,?,?,?,?)",
                (ip, ts, prev_state, d["status"], "status"),
            )
            if recent_history_count(conn, ip) >= UNSTABLE_THRESHOLD and d["status"] == "online":
                d["status"] = "unstable"
            if d["status"] == "offline":
                log_event("error", f"{d['name'] or ip} went offline", "device_offline", ip)
                create_alert(ip, "high", ALERT_TITLE_OFFLINE, f"{d['name'] or ip} is offline")
            elif d["status"] == "unstable":
                msg = f"{d['name'] or ip} is unstable"
                log_event("warning", msg, "device_unstable", ip)
                create_alert(ip, "medium", ALERT_TITLE_UNSTABLE, msg)
            elif d["status"] == "online":
                mark_device_recovered(ip, d["name"] or ip, prev_state)

        d["updated_at"] = ts
        conn.execute(
            """
            UPDATE devices SET hostname=?, category=?, vendor=?, mac=?, status=?, last_seen=?, fail_count=?,
                success_count=?, state_changes_today=?, updated_at=?, name=?, source=?, approved=? WHERE ip=?
            """,
            (
                d["hostname"], d["category"], d["vendor"], d["mac"], d["status"], int(d["last_seen"] or 0),
                d["fail_count"], d["success_count"], d["state_changes_today"], d["updated_at"], d["name"], d["source"], 1 if d.get("approved") else 0, ip,
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
                elif d["fail_count"] >= FAIL_THRESHOLD and prev_state != "offline":
                    d["status"] = "offline"
                    changed = True

            if changed and d["status"] != prev_state:
                d["state_changes_today"] += 1
                next_state = d["status"]
                conn.execute(
                    "INSERT INTO device_history(ip,ts,old_status,new_status,kind) VALUES(?,?,?,?,?)",
                    (ip, ts, prev_state, next_state, "status"),
                )
                if recent_history_count(conn, ip) >= UNSTABLE_THRESHOLD and d["status"] == "online":
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
                    success_count=?, state_changes_today=?, updated_at=?, name=?, source=?, approved=?, assigned_network=? WHERE ip=?
                """,
                (
                    d["hostname"], d["category"], d["vendor"], d["mac"], d["status"], int(d["last_seen"] or 0),
                    d["fail_count"], d["success_count"], d["state_changes_today"], d["updated_at"], d["name"], d["source"],
                    1 if d.get("approved") else 0, d.get("assigned_network", ""), ip,
                ),
            )
            conn.commit()
        finally:
            conn.close()

    if post_action:
        action, name, prev_state = post_action
        if action == "offline":
            log_event("error", f"{name} went offline", "device_offline", ip)
            create_alert(ip, "high", ALERT_TITLE_OFFLINE, f"{name} is offline")
        elif action == "unstable":
            msg = f"{name} is unstable"
            log_event("warning", msg, "device_unstable", ip)
            create_alert(ip, "medium", ALERT_TITLE_UNSTABLE, msg)
        elif action == "online":
            mark_device_recovered(ip, name, prev_state)


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
    return FileResponse("/app/web/index.html")


@app.get("/settings.html")
def settings_page():
    return RedirectResponse(url="/#settings")


@app.get("/viewer")
def viewer_page():
    return FileResponse("/app/web/index.html")


@app.get("/viewer.html")
def viewer_html_page():
    return FileResponse("/app/web/index.html")


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


@app.get("/api/devices")
def api_devices():
    ensure_background_workers()
    return {"devices": get_devices()}


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


@app.get("/api/export/devices.csv")
def api_export_devices_csv():
    rows = get_devices(include_ignored=True)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ip", "display_name", "hostname", "vendor", "category", "status", "assigned_network", "mac", "last_seen", "approved", "manual", "critical", "pinned", "notes"])
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
def api_update(ip: str, name: str = "", category: str = "", tags: str = "", notes: str = "", assigned_network: str = "", pinned: int = -1, critical: int = -1):
    conn = db()
    try:
        row = conn.execute("SELECT * FROM devices WHERE ip=?", (ip,)).fetchone()
        if row:
            d = row_to_device(row)
            d["name"] = unquote(name)
            d["category"] = unquote(category)
            d["notes"] = unquote(notes)
            d["assigned_network"] = unquote(assigned_network)
            d["tags"] = [x.strip() for x in unquote(tags).split(",") if x.strip()]
            if pinned in (0,1):
                d["pinned"] = bool(pinned)
            if critical in (0,1):
                d["critical"] = bool(critical)
            d["updated_at"] = now_ts()
            upsert_device(ip, d)
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
