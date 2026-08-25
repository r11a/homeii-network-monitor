import asyncio
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse

from app.core import *
from app.security import login_attempt_allowed, password_hash, password_matches, record_login_attempt


@asynccontextmanager
async def app_lifespan(_: FastAPI):
    start_background_workers()
    start_worker("startup_scan", run_full_scan, "startup")
    try:
        yield
    finally:
        stop_background_workers()


app = FastAPI(title="HOMEii Network Monitor", version=APP_VERSION, lifespan=app_lifespan)
app.mount("/assets", StaticFiles(directory="/app/web/assets", check_dir=False), name="assets")
app.mount("/icons", StaticFiles(directory="/app/web/icons", check_dir=False), name="icons")
@app.get("/")
def root():
    return FileResponse("/app/web/index.html", headers=NO_CACHE_HEADERS)


@app.get("/manifest.webmanifest")
def pwa_manifest():
    return FileResponse("/app/web/manifest.webmanifest", media_type="application/manifest+json")


@app.get("/sw.js")
def pwa_service_worker():
    return FileResponse("/app/web/sw.js", media_type="application/javascript", headers=NO_CACHE_HEADERS)


@app.get("/settings.html")
def settings_page():
    return FileResponse("/app/web/index.html", headers=NO_CACHE_HEADERS)


@app.get("/viewer")
def viewer_page():
    return FileResponse("/app/web/index.html", headers=NO_CACHE_HEADERS)


@app.get("/viewer.html")
def viewer_html_page():
    return FileResponse("/app/web/index.html", headers=NO_CACHE_HEADERS)


@app.get("/logo")
def logo():
    path = "/app/web/logo.png"
    if os.path.exists(path):
        return FileResponse(path, media_type="image/png", headers=NO_CACHE_HEADERS)
    return JSONResponse({"error": "logo not found"}, status_code=404)


@app.get("/api/health/live")
def api_health_live():
    return {"status": "ok", "version": APP_VERSION, "timestamp": now_ts()}


@app.get("/api/health/ready")
def api_health_ready():
    database_ok = False
    database_error = ""
    try:
        conn = db()
        try:
            result = conn.execute("PRAGMA quick_check").fetchone()
            database_ok = bool(result and result[0] == "ok")
        finally:
            conn.close()
    except Exception as exc:
        database_error = str(exc)

    now = now_ts()
    workers = background_worker_payload()
    stale_workers = stale_worker_names(workers, now)
    ready = database_ok and not stale_workers and not _shutdown_event.is_set()
    payload = {
        "status": "ready" if ready else "degraded",
        "version": APP_VERSION,
        "database_ok": database_ok,
        "database_error": database_error,
        "stale_workers": stale_workers,
        "workers": workers,
        "timestamp": now,
    }
    return JSONResponse(payload, status_code=200 if ready else 503)


@app.get("/api/status")
def api_status():
    ensure_background_workers()
    return status_payload()


@app.get("/api/stream")
async def api_stream(request: Request):
    async def events():
        previous = ""
        heartbeat = 0
        while not await request.is_disconnected():
            token = live_change_token()
            heartbeat += 1
            if token != previous or heartbeat >= 15:
                event = "update" if token != previous else "heartbeat"
                yield f"event: {event}\ndata: {token}\n\n"
                previous = token
                heartbeat = 0
            await asyncio.sleep(2)

    return StreamingResponse(events(), media_type="text/event-stream", headers={
        "Cache-Control": "no-cache",
        "X-Accel-Buffering": "no",
    })


@app.get("/api/viewer/categories")
def api_viewer_categories(hours: int = 24, buckets: int = 24):
    ensure_background_workers()
    return viewer_categories_payload(hours=hours, buckets=buckets)


@app.get("/api/devices")
def api_devices():
    ensure_background_workers()
    return {"devices": get_devices(include_quarantined=True)}


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
            "SELECT id, ip, severity, title, message, status, created_at, updated_at, acknowledged_at, acknowledged_by FROM alerts ORDER BY id DESC LIMIT ?",
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


def ingress_request(request: Request) -> bool:
    return bool(
        request.headers.get("x-ingress-path")
        and (
            request.headers.get("x-remote-user-id")
            or request.headers.get("x-remote-user-name")
        )
    )


def public_user(user: sqlite3.Row | Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": user["id"], "username": user["username"],
        "display_name": user["display_name"] or user["username"], "role": user["role"],
        "active": bool(user["active"]), "viewer_edge_to_edge": bool(user["viewer_edge_to_edge"]),
        "can_manage_alerts": bool(user["can_manage_alerts"]) if "can_manage_alerts" in user.keys() else False,
        "last_login": int(user["last_login"] or 0),
    }


def session_user(request: Request) -> Dict[str, Any] | None:
    if ingress_request(request):
        username = request.headers.get("x-remote-user-name") or "home-assistant"
        display_name = request.headers.get("x-remote-user-display-name") or username
        return {"id": 0, "username": username, "display_name": display_name, "role": "admin", "active": True, "viewer_edge_to_edge": False, "can_manage_alerts": True, "ingress": True}
    token = request.cookies.get("homeii_session", "")
    if not token:
        return None
    token_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    conn = db()
    try:
        conn.execute("DELETE FROM auth_sessions WHERE expires_at<?", (now_ts(),))
        row = conn.execute("SELECT users.* FROM auth_sessions JOIN users ON users.id=auth_sessions.user_id WHERE auth_sessions.token_hash=? AND auth_sessions.expires_at>=? AND users.active=1", (token_digest, now_ts())).fetchone()
        conn.commit()
        return public_user(row) if row else None
    finally:
        conn.close()


def require_role(request: Request, *roles: str) -> Dict[str, Any]:
    user = session_user(request)
    if not user:
        raise PermissionError("authentication_required")
    if roles and user["role"] not in roles:
        raise PermissionError("permission_denied")
    return user


def login_client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


@app.exception_handler(PermissionError)
async def permission_error_handler(_request: Request, exc: PermissionError):
    code = 401 if str(exc) == "authentication_required" else 403
    return JSONResponse({"error": str(exc)}, status_code=code)


@app.middleware("http")
async def enforce_api_permissions(request: Request, call_next):
    path = request.url.path
    if not path.startswith("/api/") or path.startswith("/api/health/"):
        return await call_next(request)

    public_auth = {"/api/auth/session", "/api/auth/setup", "/api/auth/login", "/api/auth/logout"}
    if path in public_auth:
        return await call_next(request)

    def authorize(*roles: str) -> JSONResponse | None:
        try:
            require_role(request, *roles)
        except PermissionError as exc:
            code = 401 if str(exc) == "authentication_required" else 403
            return JSONResponse({"error": str(exc)}, status_code=code)
        return None

    if path == "/api/settings" and request.method == "GET":
        denied = authorize("admin", "user", "viewer")
        return denied or await call_next(request)

    admin_prefixes = (
        "/api/admin/", "/api/tools/", "/api/export/",
        "/api/import/", "/api/save_settings", "/api/save_networks",
        "/api/recycle-bin", "/api/audit", "/api/alert-rules",
    )
    operator_get_prefixes = (
        "/api/scan", "/api/accept", "/api/add/", "/api/add_all",
        "/api/remove/", "/api/restore/", "/api/delete_device", "/api/ignore/",
        "/api/update", "/api/toggle_", "/api/bulk_", "/api/ping_now/",
        "/api/add_manual", "/api/resolve_alert/", "/api/acknowledge_alert/",
        "/api/devices/", "/api/labels",
    )

    if any(path.startswith(prefix) for prefix in admin_prefixes):
        denied = authorize("admin")
        if denied:
            return denied
    elif request.method != "GET" or any(path.startswith(prefix) for prefix in operator_get_prefixes):
        denied = authorize("admin", "user")
        if denied:
            return denied
    return await call_next(request)


@app.middleware("http")
async def audit_api_mutations(request: Request, call_next):
    response = await call_next(request)
    if request.url.path.startswith("/api/") and request.method in {"POST", "PUT", "PATCH", "DELETE"}:
        user = session_user(request) or {"username": "anonymous", "role": "anonymous"}
        log_audit(
            user.get("username", "anonymous"), user.get("role", "anonymous"),
            request.client.host if request.client else "", f"{request.method} {request.url.path}",
            request.url.path, "success" if response.status_code < 400 else "failed",
            {"status_code": response.status_code},
        )
    return response


@app.get("/api/auth/session")
def api_auth_session(request: Request):
    user = session_user(request)
    conn = db()
    try:
        setup_required = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0
    finally:
        conn.close()
    return {"authenticated": bool(user), "setup_required": setup_required, "user": user}


@app.post("/api/auth/setup")
async def api_auth_setup(request: Request):
    payload = await request.json()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    display_name = str(payload.get("display_name", "")).strip()
    if len(username) < 3 or len(password) < 8:
        return JSONResponse({"error": "invalid_credentials"}, status_code=400)
    conn = db()
    try:
        if conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return JSONResponse({"error": "setup_complete"}, status_code=409)
        now = now_ts()
        cursor = conn.execute("INSERT INTO users(username,display_name,password_hash,role,active,created_at,updated_at) VALUES(?,?,?,?,1,?,?)", (username, display_name, password_hash(password), "admin", now, now))
        conn.commit()
        user_id = cursor.lastrowid
    finally:
        conn.close()
    token = secrets.token_urlsafe(40)
    conn = db()
    try:
        conn.execute("INSERT INTO auth_sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)", (hashlib.sha256(token.encode("utf-8")).hexdigest(), user_id, now_ts() + SESSION_TTL_SECONDS, now_ts()))
        conn.commit()
    finally:
        conn.close()
    response = JSONResponse({"ok": True})
    secure_cookie = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"
    response.set_cookie("homeii_session", token, httponly=True, secure=secure_cookie, samesite="lax", max_age=SESSION_TTL_SECONDS, path="/")
    return response


@app.post("/api/auth/login")
async def api_auth_login(request: Request):
    client_key = login_client_key(request)
    if not login_attempt_allowed(client_key):
        return JSONResponse({"error": "rate_limited"}, status_code=429, headers={"Retry-After": "300"})
    payload = await request.json()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    conn = db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username=? COLLATE NOCASE AND active=1", (username,)).fetchone()
        if not row or not password_matches(password, row["password_hash"]):
            record_login_attempt(client_key, False)
            return JSONResponse({"error": "invalid_credentials"}, status_code=401)
        conn.execute("UPDATE users SET last_login=? WHERE id=?", (now_ts(), row["id"]))
        conn.commit()
        user = public_user(row)
    finally:
        conn.close()
    record_login_attempt(client_key, True)
    token = secrets.token_urlsafe(40)
    conn = db()
    try:
        conn.execute("INSERT INTO auth_sessions(token_hash,user_id,expires_at,created_at) VALUES(?,?,?,?)", (hashlib.sha256(token.encode("utf-8")).hexdigest(), user["id"], now_ts() + SESSION_TTL_SECONDS, now_ts()))
        conn.commit()
    finally:
        conn.close()
    response = JSONResponse({"ok": True, "user": user})
    secure_cookie = request.url.scheme == "https" or request.headers.get("x-forwarded-proto", "").lower() == "https"
    response.set_cookie("homeii_session", token, httponly=True, secure=secure_cookie, samesite="lax", max_age=SESSION_TTL_SECONDS, path="/")
    return response


@app.post("/api/auth/logout")
def api_auth_logout(request: Request):
    token = request.cookies.get("homeii_session", "")
    if token:
        conn = db()
        try:
            conn.execute("DELETE FROM auth_sessions WHERE token_hash=?", (hashlib.sha256(token.encode("utf-8")).hexdigest(),))
            conn.commit()
        finally:
            conn.close()
    response = JSONResponse({"ok": True})
    response.delete_cookie("homeii_session", path="/")
    return response


@app.get("/api/admin/users")
def api_admin_users(request: Request):
    require_role(request, "admin")
    conn = db()
    try:
        return {"users": [public_user(row) for row in conn.execute("SELECT * FROM users ORDER BY username").fetchall()]}
    finally:
        conn.close()


@app.post("/api/admin/users")
async def api_admin_create_user(request: Request):
    require_role(request, "admin")
    payload = await request.json()
    username = str(payload.get("username", "")).strip()
    password = str(payload.get("password", ""))
    role = str(payload.get("role", "viewer"))
    if len(username) < 3 or len(password) < 8 or role not in {"admin", "user", "viewer"}:
        return JSONResponse({"error": "invalid_user"}, status_code=400)
    conn = db()
    try:
        now = now_ts()
        conn.execute("INSERT INTO users(username,display_name,password_hash,role,active,viewer_edge_to_edge,can_manage_alerts,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?)", (username, str(payload.get("display_name", "")).strip(), password_hash(password), role, 1, 1 if payload.get("viewer_edge_to_edge") else 0, 1 if payload.get("can_manage_alerts") else 0, now, now))
        conn.commit()
    except sqlite3.IntegrityError:
        return JSONResponse({"error": "username_exists"}, status_code=409)
    finally:
        conn.close()
    return {"ok": True}


@app.patch("/api/admin/users/{user_id}")
async def api_admin_update_user(user_id: int, request: Request):
    current = require_role(request, "admin")
    payload = await request.json()
    role = str(payload.get("role", "viewer"))
    if role not in {"admin", "user", "viewer"} or (current.get("id") == user_id and not payload.get("active", True)):
        return JSONResponse({"error": "invalid_user"}, status_code=400)
    fields = ["display_name=?", "role=?", "active=?", "viewer_edge_to_edge=?", "can_manage_alerts=?", "updated_at=?"]
    values: List[Any] = [str(payload.get("display_name", "")).strip(), role, 1 if payload.get("active", True) else 0, 1 if payload.get("viewer_edge_to_edge") else 0, 1 if payload.get("can_manage_alerts") else 0, now_ts()]
    password = str(payload.get("password", ""))
    if password:
        if len(password) < 8:
            return JSONResponse({"error": "invalid_password"}, status_code=400)
        fields.append("password_hash=?")
        values.append(password_hash(password))
    values.append(user_id)
    conn = db()
    try:
        conn.execute(f"UPDATE users SET {','.join(fields)} WHERE id=?", values)
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}


@app.get("/api/tools/traffic")
def api_tools_traffic():
    return traffic_diagnostics()


@app.get("/api/export/devices.csv")
def api_export_devices_csv():
    rows = get_devices(include_ignored=True, include_quarantined=True)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ip", "display_name", "hostname", "vendor", "category", "status", "assigned_network", "mac", "last_seen", "approved", "manual", "critical", "pinned", "maintenance", "mute_alerts", "scan_profile", "device_profile", "quarantined", "quarantined_at", "notes"])
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
            device.get("device_profile", "generic"),
            1 if device.get("quarantined") else 0,
            int(device.get("quarantined_at") or 0),
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


@app.get("/api/export/database.db")
def api_export_database(request: Request):
    require_role(request, "admin")
    backup_path = create_database_backup()
    return FileResponse(
        backup_path,
        media_type="application/vnd.sqlite3",
        filename=backup_path.name,
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
            "device_profile": normalize_device_profile(row.get("device_profile")),
            "quarantined": csv_bool(row.get("quarantined")),
            "quarantined_at": csv_int(row.get("quarantined_at"), 0),
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


def run_reconciliation_job() -> None:
    scan_state["reconciliation"] = {"running": True, "started_at": now_ts()}
    try:
        summary = reconcile_network_inventory()
        scan_state["reconciliation"] = {**summary, "running": False, "finished_at": now_ts(), "error": ""}
    except Exception as exc:
        scan_state["reconciliation"] = {"running": False, "finished_at": now_ts(), "error": str(exc)}
        log_system_event("error", f"Inventory reconciliation failed: {exc}", "inventory_reconcile_error")


@app.get("/api/scan")
def api_scan(mode: str = Query("manual")):
    threading.Thread(target=run_scan_job, args=(mode,), daemon=True).start()
    return {"ok": True, "scan": scan_state}


@app.post("/api/admin/reconcile-inventory")
def api_admin_reconcile_inventory():
    current = scan_state.get("reconciliation", {})
    if current.get("running"):
        return {"ok": False, "already_running": True, "reconciliation": current}
    threading.Thread(target=run_reconciliation_job, daemon=True).start()
    return {"ok": True, "reconciliation": {"running": True}}


@app.get("/api/admin/reconcile-inventory")
def api_admin_reconcile_inventory_status():
    return {"ok": True, "reconciliation": scan_state.get("reconciliation", {})}



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
            conflicts = device_identity_conflicts(ip, d.get("mac", ""), exclude_ip=ip)
            if conflicts:
                return JSONResponse(
                    {
                        "error": "device_identity_conflict",
                        "ip": ip,
                        "mac": d.get("mac", ""),
                        "conflicts": conflicts,
                    },
                    status_code=409,
                )
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
        rows = conn.execute("SELECT ip FROM devices WHERE ignored=0 AND approved=0 AND quarantined=0").fetchall()
    finally:
        conn.close()
    accepted: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    unreachable: list[dict[str, Any]] = []
    for row in rows:
        try:
            result = api_accept(row[0])
            if isinstance(result, JSONResponse):
                payload = json.loads(result.body.decode("utf-8"))
                conflicts.append(payload)
            elif result.get("status") == "online":
                accepted.append({"ip": row[0], "status": "online"})
            else:
                unreachable.append({"ip": row[0], "status": "offline"})
        except Exception as exc:
            unreachable.append({"ip": row[0], "error": str(exc)})
    return {
        "ok": not conflicts,
        "checked": len(rows),
        "accepted": accepted,
        "conflicts": conflicts,
        "unreachable": unreachable,
    }


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
            conn.execute(
                "UPDATE devices SET quarantined=1, quarantined_at=?, updated_at=? WHERE ip=?",
                (now_ts(), now_ts(), ip),
            )
            conn.execute("UPDATE alerts SET status='resolved', updated_at=? WHERE ip=? AND status='open'", (now_ts(), ip))
            conn.commit()
        finally:
            conn.close()
    log_event("warning", f"Quarantined device {ip}", "device_quarantined", ip)
    return {"ok": True}


@app.get("/api/restore/{ip}")
def api_restore(ip: str):
    with _db_lock:
        conn = db()
        try:
            conn.execute(
                "UPDATE devices SET quarantined=0, quarantined_at=0, updated_at=? WHERE ip=?",
                (now_ts(), ip),
            )
            conn.commit()
        finally:
            conn.close()
    log_event("success", f"Restored device {ip}", "device_restored", ip)
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
def api_update(ip: str, name: str = "", category: str = "", tags: str = "", notes: str = "", assigned_network: str = "", scan_profile: str = "normal", device_profile: str = "generic", maintenance: int = -1, mute_alerts: int = -1, pinned: int = -1, critical: int = -1):
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
            d["device_profile"] = normalize_device_profile(unquote(device_profile))
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
            conn.execute(
                "UPDATE devices SET quarantined=1, quarantined_at=?, updated_at=? WHERE ip=?",
                (now_ts(), now_ts(), ip),
            )
        conn.commit()
        log_event("warning", f"Bulk quarantined {len(ip_list)} devices", "bulk_quarantine")
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
def api_ping_now(ip: str, request: Request):
    ok = ping(ip)
    checked_at = now_ts()
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
        user = session_user(request) or {"username": "system", "role": "system"}
        log_audit(
            user.get("username", "system"), user.get("role", "system"),
            request.client.host if request.client else "", "manual_device_check", ip,
            "success" if ok else "unreachable", {"reachable": bool(ok), "checked_at": checked_at},
        )
        return {"ok": ok, "status": "online" if ok else "offline", "checked_at": checked_at}
    finally:
        conn.close()


def create_manual_device(
    preflight: dict[str, Any], name: str = "", category: str = "", notes: str = ""
) -> dict[str, Any]:
    ip = preflight["ip"]
    host = reverse_dns(ip)
    vendor = preflight.get("vendor", "")
    reachable = bool(preflight.get("reachable"))
    d = {
        "name": choose_display_name(name, host, vendor, ip),
        "hostname": host,
        "category": category or auto_category(name or host or ip, vendor),
        "vendor": vendor,
        "mac": preflight.get("mac", ""),
        "status": "online" if reachable else "offline",
        "last_seen": now_ts() if reachable else 0,
        "critical": False,
        "pinned": False,
        "manual": True,
        "ignored": False,
        "approved": True,
        "fail_count": 0,
        "success_count": 1 if reachable else 0,
        "state_changes_today": 0,
        "first_seen": now_ts(),
        "updated_at": now_ts(),
        "source": "manual",
        "notes": notes,
        "assigned_network": infer_assigned_network(ip),
        "maintenance": False,
        "mute_alerts": False,
        "scan_profile": "normal",
        "device_profile": "generic",
        "tags": [],
    }
    upsert_device(ip, d)
    log_event("info", f"Manual device added: {name or ip}", "device_manual", ip)
    return {"ok": True, "device": {"ip": ip, "mac": d["mac"], "status": d["status"]}}


@app.post("/api/devices/preflight")
async def api_device_preflight(request: Request):
    payload = await request.json()
    try:
        return manual_device_preflight(
            str(payload.get("ip", "")).strip(), str(payload.get("mac", "")).strip()
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)


@app.get("/api/add_manual")
def api_add_manual(ip: str, name: str = "", category: str = "", notes: str = "", mac: str = ""):
    try:
        preflight = manual_device_preflight(ip, mac)
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    if preflight["conflicts"]:
        return JSONResponse(
            {"error": "device_identity_conflict", **preflight}, status_code=409
        )
    return create_manual_device(preflight, name, category, notes)


@app.post("/api/add_manual")
async def api_add_manual_post(request: Request):
    payload = await request.json()
    try:
        preflight = manual_device_preflight(
            str(payload.get("ip", "")).strip(), str(payload.get("mac", "")).strip()
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    if preflight["conflicts"]:
        return JSONResponse(
            {"error": "device_identity_conflict", **preflight}, status_code=409
        )
    result = create_manual_device(
        preflight,
        str(payload.get("name", "")).strip(),
        str(payload.get("category", "")).strip(),
        str(payload.get("notes", "")).strip(),
    )
    tags = payload.get("tags", [])
    if result.get("ok") and isinstance(tags, list):
        conn = db()
        try:
            conn.execute(
                "UPDATE devices SET tags_json=?, updated_at=? WHERE ip=?",
                (json.dumps([str(tag).strip() for tag in tags if str(tag).strip()]), now_ts(), str(payload.get("ip", "")).strip()),
            )
            conn.commit()
        finally:
            conn.close()
    return result


@app.get("/api/labels")
def api_labels():
    return label_definitions_payload()


@app.post("/api/labels")
async def api_save_label(request: Request):
    require_role(request, "admin")
    payload = await request.json()
    try:
        saved = save_label_definition(
            str(payload.get("kind", "")), str(payload.get("name", "")),
            str(payload.get("color", "")), str(payload.get("icon", "")),
        )
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    return {"ok": True, "label": saved, **label_definitions_payload()}


@app.delete("/api/labels/{label_id}")
def api_delete_label(label_id: int, request: Request):
    require_role(request, "admin")
    deleted = delete_label_definition(label_id)
    if not deleted:
        return JSONResponse({"error": "label_not_found"}, status_code=404)
    return {"ok": True, **label_definitions_payload()}


@app.patch("/api/labels/{label_id}")
async def api_update_label(label_id: int, request: Request):
    require_role(request, "admin")
    payload = await request.json()
    try:
        label = update_label_definition(label_id, str(payload.get("name", "")), str(payload.get("color", "")), str(payload.get("icon", "")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=404 if str(exc) == "label_not_found" else 400)
    return {"ok": True, "label": label, **label_definitions_payload()}


@app.post("/api/categories/{category}/check")
def api_check_category(category: str):
    category = unquote(category).strip()
    if not category:
        return JSONResponse({"error": "category_required"}, status_code=400)
    if category_check_state.get(category, {}).get("running"):
        return {"ok": True, "state": category_check_state[category]}
    start_worker(f"category-{hashlib.sha256(category.encode()).hexdigest()[:10]}", run_category_check, category)
    return {"ok": True, "state": {"running": True, "category": category}}


@app.get("/api/categories/{category}/check")
def api_category_check_status(category: str):
    return {"state": category_check_state.get(unquote(category).strip(), {"running": False})}


@app.get("/api/recycle-bin")
def api_recycle_bin():
    maintain_recycle_bin(force=True)
    devices = get_devices(include_ignored=True, include_quarantined=True, include_trashed=True)
    return {"devices": [device for device in devices if device.get("trashed_at")], "retention_days": 14, "offline_hours": 48}


@app.post("/api/recycle-bin/trash-offline")
def api_trash_all_offline():
    return {"ok": True, "trashed": trash_all_offline_devices()}


@app.post("/api/admin/inventory/cleanup")
def api_cleanup_inventory():
    return {"ok": True, **permanently_suppress_stale_inventory()}


@app.post("/api/admin/backup-now")
def api_backup_now(request: Request):
    require_role(request, "admin")
    return {"ok": True, **maintain_automatic_backups(force=True)}


@app.get("/api/admin/backups")
def api_backup_status(request: Request):
    require_role(request, "admin")
    result = maintain_automatic_backups(force=False)
    result["share_available"] = Path("/share").exists() and os.access("/share", os.W_OK)
    result["retention"] = int(get_setting("backup_retention", "3"))
    directory = Path(result["directory"])
    result["backups"] = [
        {
            "name": path.name,
            "size": path.stat().st_size,
            "size_human": f"{path.stat().st_size / 1024 / 1024:.1f} MB",
            "modified": int(path.stat().st_mtime),
        }
        for path in sorted(directory.glob("*.db"), key=lambda item: item.stat().st_mtime, reverse=True)[:20]
    ] if directory.exists() else []
    return result


@app.post("/api/admin/backups/settings")
async def api_backup_settings(request: Request):
    user = require_role(request, "admin")
    payload = await request.json()
    target = str(payload.get("target", "data")).lower()
    if target not in ("data", "share"):
        return JSONResponse({"error": "invalid_backup_target"}, status_code=400)
    if target == "share" and not (Path("/share").exists() and os.access("/share", os.W_OK)):
        return JSONResponse({"error": "share_not_available"}, status_code=400)
    retention = max(1, min(10, int(payload.get("retention", 3))))
    set_setting("backup_target", target)
    set_setting("backup_retention", str(retention))
    set_setting("backup_enabled", "1" if payload.get("enabled", True) else "0")
    log_audit(user["username"], user["role"], request.client.host if request.client else "", "backup_settings_updated", target, "success", {"retention": retention, "enabled": bool(payload.get("enabled", True))})
    return {"ok": True, **maintain_automatic_backups(force=False)}


@app.post("/api/recycle-bin/{ip}/restore")
def api_restore_recycled(ip: str):
    conn = db()
    try:
        cursor = conn.execute("UPDATE devices SET trashed_at=0,updated_at=? WHERE ip=?", (now_ts(), ip))
        conn.commit()
        return {"ok": cursor.rowcount > 0}
    finally:
        conn.close()


@app.delete("/api/recycle-bin/{ip}")
def api_delete_recycled(ip: str):
    conn = db()
    try:
        cursor = conn.execute(
            "UPDATE devices SET ignored=1,trashed_at=0,quarantined=0,quarantined_at=0,updated_at=? "
            "WHERE ip=? AND trashed_at>0",
            (now_ts(), ip),
        )
        conn.commit()
        return {"ok": cursor.rowcount > 0}
    finally:
        conn.close()


@app.get("/api/audit")
def api_audit(limit: int = 200, actor: str = "", action: str = "", outcome: str = "", date_from: int = 0, date_to: int = 0):
    conn = db()
    try:
        clauses = []
        values: list[Any] = []
        if actor:
            clauses.append("actor LIKE ?")
            values.append(f"%{actor}%")
        if action:
            clauses.append("action LIKE ?")
            values.append(f"%{action}%")
        if outcome:
            clauses.append("outcome=?")
            values.append(outcome)
        if date_from:
            clauses.append("ts>=?")
            values.append(date_from)
        if date_to:
            clauses.append("ts<=?")
            values.append(date_to)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(max(1, min(limit, 1000)))
        rows = conn.execute(f"SELECT * FROM audit_log{where} ORDER BY id DESC LIMIT ?", values).fetchall()
        return {"records": [dict(row) for row in rows]}
    finally:
        conn.close()


@app.get("/api/alert-rules")
def api_alert_rules():
    conn = db()
    try:
        rows = conn.execute("SELECT * FROM alert_rules ORDER BY enabled DESC,id DESC").fetchall()
        return {"rules": [{**dict(row), "enabled": bool(row["enabled"]), "condition": json.loads(row["condition_json"] or "{}"), "action": json.loads(row["action_json"] or "{}")} for row in rows]}
    finally:
        conn.close()


@app.post("/api/alert-rules")
async def api_create_alert_rule(request: Request):
    user = require_role(request, "admin")
    payload = await request.json()
    name = str(payload.get("name", "")).strip()
    trigger = str(payload.get("trigger_type", "device_offline")).strip()
    if not name or trigger not in ("device_offline", "device_recovered", "device_unstable", "new_device", "critical_offline"):
        return JSONResponse({"error": "invalid_alert_rule"}, status_code=400)
    ts = now_ts()
    conn = db()
    try:
        cursor = conn.execute("INSERT INTO alert_rules(name,enabled,trigger_type,condition_json,action_json,severity,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)", (name, 1 if payload.get("enabled", True) else 0, trigger, json.dumps(payload.get("condition", {}), ensure_ascii=False), json.dumps(payload.get("action", {}), ensure_ascii=False), str(payload.get("severity", "high")), ts, ts))
        conn.commit()
        rule_id = cursor.lastrowid
    finally:
        conn.close()
    log_audit(user["username"], user["role"], request.client.host if request.client else "", "alert_rule_created", str(rule_id), "success", {"name": name, "trigger": trigger})
    return {"ok": True, "id": rule_id}


@app.patch("/api/alert-rules/{rule_id}")
async def api_update_alert_rule(rule_id: int, request: Request):
    user = require_role(request, "admin")
    payload = await request.json()
    conn = db()
    try:
        row = conn.execute("SELECT * FROM alert_rules WHERE id=?", (rule_id,)).fetchone()
        if not row:
            return JSONResponse({"error": "alert_rule_not_found"}, status_code=404)
        conn.execute("UPDATE alert_rules SET name=?,enabled=?,trigger_type=?,condition_json=?,action_json=?,severity=?,updated_at=? WHERE id=?", (str(payload.get("name", row["name"])), 1 if payload.get("enabled", bool(row["enabled"])) else 0, str(payload.get("trigger_type", row["trigger_type"])), json.dumps(payload.get("condition", json.loads(row["condition_json"] or "{}")), ensure_ascii=False), json.dumps(payload.get("action", json.loads(row["action_json"] or "{}")), ensure_ascii=False), str(payload.get("severity", row["severity"])), now_ts(), rule_id))
        conn.commit()
    finally:
        conn.close()
    log_audit(user["username"], user["role"], request.client.host if request.client else "", "alert_rule_updated", str(rule_id))
    return {"ok": True}


@app.delete("/api/alert-rules/{rule_id}")
def api_delete_alert_rule(rule_id: int, request: Request):
    user = require_role(request, "admin")
    conn = db()
    try:
        cursor = conn.execute("DELETE FROM alert_rules WHERE id=?", (rule_id,))
        conn.commit()
    finally:
        conn.close()
    log_audit(user["username"], user["role"], request.client.host if request.client else "", "alert_rule_deleted", str(rule_id))
    return {"ok": cursor.rowcount > 0}


@app.post("/api/devices/{source_ip}/clone")
async def api_clone_device(source_ip: str, request: Request):
    payload = await request.json()
    try:
        device = clone_device(source_ip, str(payload.get("ip", "")), str(payload.get("name", "")))
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    log_event("info", f"Device cloned from {source_ip}", "device_cloned", device["ip"])
    return {"ok": True, "device": device}


@app.get("/api/resolve_alert/{alert_id}")
def api_resolve_alert(alert_id: int):
    conn = db()
    try:
        conn.execute("UPDATE alerts SET status='resolved', updated_at=? WHERE id=?", (now_ts(), alert_id))
        conn.commit()
        return {"ok": True}
    finally:
        conn.close()


@app.post("/api/acknowledge_alert/{alert_id}")
def api_acknowledge_alert(alert_id: int, request: Request):
    user = require_role(request, "admin", "user")
    if user.get("role") != "admin" and not user.get("can_manage_alerts"):
        return JSONResponse({"error": "permission_denied"}, status_code=403)
    return {"ok": acknowledge_alert(alert_id, user.get("username", "operator"))}


@app.delete("/api/alerts")
def api_clear_alerts(request: Request, scope: str = "resolved"):
    user = require_role(request, "admin", "user")
    if user.get("role") != "admin" and not user.get("can_manage_alerts"):
        return JSONResponse({"error": "permission_denied"}, status_code=403)
    conn = db()
    try:
        if scope == "all":
            cursor = conn.execute("DELETE FROM alerts")
        else:
            cursor = conn.execute("DELETE FROM alerts WHERE status='resolved'")
        conn.commit()
        return {"ok": True, "deleted": cursor.rowcount}
    finally:
        conn.close()


@app.get("/api/save_settings")
def api_save_settings(auto_refresh: str = "30", default_view: str = "table", dashboard_style: str = "advanced", theme: str = "light", language: str = "he", status_animation: str = "blink", history_retention_days: str = "30", alert_profile: str = "normal", auto_restore_quarantined: str = "1", networks: str = "", network_names: str = "", discovery_mode: str = "auto_manual", discovery_protocols: str = ""):
    set_setting("auto_refresh", auto_refresh or "30")
    set_setting("default_view", default_view or "table")
    set_setting("dashboard_style", dashboard_style or "advanced")
    set_setting("theme", theme if theme in ("light", "dark", "granite", "navy") else "granite")
    set_setting("language", language if language in ("he", "en") else "he")
    set_setting("status_animation", status_animation if status_animation in ("blink", "static") else "blink")
    set_setting("alert_profile", normalize_alert_profile(alert_profile))
    set_setting("auto_restore_quarantined", "1" if str(auto_restore_quarantined).lower() in ("1", "true", "yes", "on") else "0")
    try:
        retention_value = max(1, min(int(str(history_retention_days or "30").strip() or "30"), 365))
    except Exception:
        retention_value = int(DEFAULT_SETTINGS["history_retention_days"])
    set_setting("history_retention_days", str(retention_value))
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
    prune_old_history(force=True)
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
        history_retention_days=str(payload.get("history_retention_days", "30") or "30"),
        alert_profile=str(payload.get("alert_profile", "normal") or "normal"),
        auto_restore_quarantined=str(payload.get("auto_restore_quarantined", "1") or "1"),
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


