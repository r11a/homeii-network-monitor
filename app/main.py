from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List
import sqlite3
import os
import ipaddress
import socket
import subprocess
import platform
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

app = FastAPI(title="HOMEii Network Monitor")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "/data/homeii.db"
os.makedirs("/data", exist_ok=True)


def utc_now() -> str:
    return datetime.utcnow().isoformat(timespec="seconds")


def get_conn():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT,
        ip TEXT UNIQUE,
        status TEXT DEFAULT 'new',
        approved INTEGER DEFAULT 0,
        pinned INTEGER DEFAULT 0,
        critical INTEGER DEFAULT 0,
        category TEXT DEFAULT '',
        flag TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        source TEXT DEFAULT 'scan',
        last_seen TEXT DEFAULT '',
        last_change TEXT DEFAULT '',
        created_at TEXT DEFAULT ''
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_id INTEGER,
        ip TEXT,
        message TEXT,
        severity TEXT DEFAULT 'warning',
        created_at TEXT DEFAULT '',
        resolved INTEGER DEFAULT 0
    )
    """)

    conn.commit()

    default_networks = "192.168.1.0/24"
    cur.execute("SELECT value FROM settings WHERE key='networks'")
    row = cur.fetchone()
    if not row:
        cur.execute(
            "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
            ("networks", default_networks),
        )

    conn.commit()
    conn.close()


init_db()


class DeviceCreate(BaseModel):
    ip: str
    name: Optional[str] = None


class DeviceUpdate(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None
    flag: Optional[str] = None
    notes: Optional[str] = None
    pinned: Optional[bool] = None
    critical: Optional[bool] = None
    approved: Optional[bool] = None


class SettingsUpdate(BaseModel):
    networks: str


def db_get_setting(key: str, default: str = "") -> str:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT value FROM settings WHERE key=?", (key,))
    row = cur.fetchone()
    conn.close()
    return row["value"] if row else default


def db_set_setting(key: str, value: str) -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT OR REPLACE INTO settings(key, value) VALUES (?, ?)",
        (key, value),
    )
    conn.commit()
    conn.close()


def ping_host(ip: str) -> bool:
    system = platform.system().lower()
    if "windows" in system:
        cmd = ["ping", "-n", "1", "-w", "800", ip]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", ip]

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
        )
        return result.returncode == 0
    except Exception:
        return False


def resolve_name(ip: str) -> str:
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host
    except Exception:
        return ip


def parse_networks(networks_text: str) -> List[str]:
    valid = []
    for line in networks_text.splitlines():
        n = line.strip()
        if not n:
            continue
        try:
            ipaddress.ip_network(n, strict=False)
            valid.append(n)
        except Exception:
            pass
    return valid


def iter_ips(network_cidr: str) -> List[str]:
    net = ipaddress.ip_network(network_cidr, strict=False)
    if net.num_addresses <= 2:
        return [str(ip) for ip in net.hosts()]
    return [str(ip) for ip in net.hosts()]


def upsert_device(ip: str, is_online: bool, source: str = "scan") -> None:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE ip=?", (ip,))
    row = cur.fetchone()

    now = utc_now()
    resolved_name = resolve_name(ip)

    if row is None:
        status = "new"
        last_seen = now if is_online else ""
        cur.execute("""
            INSERT INTO devices
            (name, ip, status, approved, pinned, critical, category, flag, notes, source, last_seen, last_change, created_at)
            VALUES (?, ?, ?, 0, 0, 0, '', '', '', ?, ?, ?, ?)
        """, (resolved_name, ip, status, source, last_seen, now, now))
    else:
        approved = int(row["approved"])
        prev_status = row["status"]
        new_status = "online" if is_online else "offline"
        status = prev_status if approved == 0 else new_status
        last_seen = now if is_online else row["last_seen"]

        if approved == 0:
            cur.execute("""
                UPDATE devices
                SET name=?,
                    source=?,
                    last_seen=?,
                    last_change=?
                WHERE ip=?
            """, (row["name"] or resolved_name, source, last_seen, now, ip))
        else:
            cur.execute("""
                UPDATE devices
                SET name=?,
                    status=?,
                    source=?,
                    last_seen=?,
                    last_change=?
                WHERE ip=?
            """, (row["name"] or resolved_name, status, source, last_seen, now, ip))

            if prev_status == "online" and new_status == "offline":
                cur.execute("""
                    INSERT INTO alerts (device_id, ip, message, severity, created_at, resolved)
                    VALUES (?, ?, ?, 'warning', ?, 0)
                """, (row["id"], ip, f"{row['name'] or ip} went offline", now))

    conn.commit()
    conn.close()


def scan_network(network_cidr: str) -> dict:
    ips = iter_ips(network_cidr)
    found = 0

    with ThreadPoolExecutor(max_workers=64) as executor:
        futures = {executor.submit(ping_host, ip): ip for ip in ips}
        for future in as_completed(futures):
            ip = futures[future]
            try:
                ok = future.result()
            except Exception:
                ok = False

            if ok:
                found += 1
                upsert_device(ip, True, source=network_cidr)

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT ip, approved FROM devices")
    rows = cur.fetchall()
    conn.close()

    scanned_set = set(ips)
    for row in rows:
        ip = row["ip"]
        approved = int(row["approved"])
        if approved == 1 and ip in scanned_set:
            online = ping_host(ip)
            upsert_device(ip, online, source=network_cidr)

    return {"network": network_cidr, "scanned": len(ips), "found_online": found}


@app.get("/api/health")
def api_health():
    return {"ok": True, "db_path": DB_PATH, "time": utc_now()}


@app.get("/api/settings")
def api_settings():
    return {
        "networks": db_get_setting("networks", "192.168.1.0/24")
    }


@app.post("/api/settings")
def api_save_settings(payload: SettingsUpdate):
    valid = parse_networks(payload.networks)
    if not valid:
        raise HTTPException(status_code=400, detail="No valid networks found")
    networks_text = "\n".join(valid)
    db_set_setting("networks", networks_text)
    return {"ok": True, "networks": networks_text}


@app.get("/api/devices")
def api_devices():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT *
        FROM devices
        ORDER BY
            pinned DESC,
            CASE status
                WHEN 'offline' THEN 0
                WHEN 'new' THEN 1
                WHEN 'online' THEN 2
                ELSE 3
            END,
            ip ASC
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


@app.post("/api/scan")
def api_scan():
    networks_text = db_get_setting("networks", "192.168.1.0/24")
    networks = parse_networks(networks_text)
    if not networks:
        raise HTTPException(status_code=400, detail="No valid networks configured")

    results = []
    for network in networks:
        results.append(scan_network(network))

    return {"ok": True, "results": results}


@app.post("/api/add_device")
def api_add_device(payload: DeviceCreate):
    ip = payload.ip.strip()
    try:
        ipaddress.ip_address(ip)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid IP")

    name = (payload.name or ip).strip()
    now = utc_now()

    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id FROM devices WHERE ip=?", (ip,))
    row = cur.fetchone()

    if row:
        cur.execute("""
            UPDATE devices
            SET name=?,
                approved=1,
                status='offline',
                source='manual',
                last_change=?
            WHERE ip=?
        """, (name, now, ip))
    else:
        cur.execute("""
            INSERT INTO devices
            (name, ip, status, approved, pinned, critical, category, flag, notes, source, last_seen, last_change, created_at)
            VALUES (?, ?, 'offline', 1, 0, 0, '', '', '', 'manual', '', ?, ?)
        """, (name, ip, now, now))

    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/devices/{device_id}/approve")
def api_approve_device(device_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id=?", (device_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    online = ping_host(row["ip"])
    status = "online" if online else "offline"
    now = utc_now()

    cur.execute("""
        UPDATE devices
        SET approved=1,
            status=?,
            last_seen=?,
            last_change=?
        WHERE id=?
    """, (status, now if online else row["last_seen"], now, device_id))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.post("/api/devices/approve_all")
def api_approve_all():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, ip, last_seen FROM devices WHERE approved=0")
    rows = cur.fetchall()

    now = utc_now()
    for row in rows:
        online = ping_host(row["ip"])
        status = "online" if online else "offline"
        cur.execute("""
            UPDATE devices
            SET approved=1,
                status=?,
                last_seen=?,
                last_change=?
            WHERE id=?
        """, (status, now if online else row["last_seen"], now, row["id"]))

    conn.commit()
    conn.close()
    return {"ok": True, "count": len(rows)}


@app.patch("/api/devices/{device_id}")
def api_update_device(device_id: int, payload: DeviceUpdate):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM devices WHERE id=?", (device_id,))
    row = cur.fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Device not found")

    fields = dict(row)
    if payload.name is not None:
        fields["name"] = payload.name.strip()
    if payload.category is not None:
        fields["category"] = payload.category.strip()
    if payload.flag is not None:
        fields["flag"] = payload.flag.strip()
    if payload.notes is not None:
        fields["notes"] = payload.notes.strip()
    if payload.pinned is not None:
        fields["pinned"] = 1 if payload.pinned else 0
    if payload.critical is not None:
        fields["critical"] = 1 if payload.critical else 0
    if payload.approved is not None:
        fields["approved"] = 1 if payload.approved else 0

    cur.execute("""
        UPDATE devices
        SET name=?,
            category=?,
            flag=?,
            notes=?,
            pinned=?,
            critical=?,
            approved=?
        WHERE id=?
    """, (
        fields["name"],
        fields["category"],
        fields["flag"],
        fields["notes"],
        fields["pinned"],
        fields["critical"],
        fields["approved"],
        device_id
    ))

    conn.commit()
    conn.close()
    return {"ok": True}


@app.delete("/api/devices/{device_id}")
def api_delete_device(device_id: int):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("DELETE FROM devices WHERE id=?", (device_id,))
    conn.commit()
    conn.close()
    return {"ok": True}


@app.get("/api/alerts")
def api_alerts():
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("""
        SELECT *
        FROM alerts
        ORDER BY resolved ASC, created_at DESC
        LIMIT 200
    """)
    rows = [dict(r) for r in cur.fetchall()]
    conn.close()
    return rows


app.mount("/", StaticFiles(directory="/web", html=True), name="web")
