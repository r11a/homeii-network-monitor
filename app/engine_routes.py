"""Authenticated HOMEii product API for the independent local Zabbix engine."""
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets

from fastapi import Query, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from .zabbix import Engine, EngineError

_engines = {}


def engine(directory):
    key = str(directory)
    if key not in _engines: _engines[key] = Engine(Path(directory))
    return _engines[key]


def valid_ha_token(header, directory):
    if not header.startswith('Bearer '): return False
    try: digest = (Path(directory) / 'home-assistant-token.sha256').read_text().strip()
    except OSError: return False
    return hmac.compare_digest(digest, hashlib.sha256(header[7:].encode()).hexdigest())


def ha_dashboard(directory):
    snapshot = engine(directory).snapshot()
    if snapshot['stale']:
        return JSONResponse({'error': 'monitoring_unavailable'}, status_code=503)
    return {'status': {**snapshot['counts'], 'version': '8.0.0', 'monitoring_stale': False, 'engine': 'zabbix',
                       'last_update': snapshot['updated_at'], 'open_alerts': len(snapshot['events'])},
            'devices': [{**d, 'device_id': 'zabbix-' + d['id'], 'display_name': d['name'],
                         'category': ', '.join(d['groups']), 'last_seen': d['last_check'], 'approved': True,
                         'mac': '', 'pinned': False, 'manual': True} for d in snapshot['devices']],
            'alerts': snapshot['events'], 'availability': {}}


def register_engine_routes(app, core, require_role):
    def current(): return engine(core.BASE_DIR)

    @app.exception_handler(EngineError)
    async def engine_error(_request, exc):
        return JSONResponse({'error': str(exc)}, status_code=502 if str(exc).startswith('engine_') else 400)

    async def body(request):
        try:
            value = await request.json()
            if not isinstance(value, dict): raise ValueError()
            return value
        except (ValueError, TypeError): raise EngineError('invalid_request') from None

    @app.get('/api/engine/config')
    def config():
        return {**current().public_config(), 'active': core.zabbix_enabled(), 'version_label': '8.0.0'}

    @app.post('/api/engine/connect')
    async def connect(request: Request):
        payload = await body(request)
        # Backup before the first switch; the old inventory is never migrated destructively.
        if not core.zabbix_enabled():
            await run_in_threadpool(core.create_database_backup, 'homeii-before-zabbix')
        result = await run_in_threadpool(current().connect, payload)
        core.set_setting('monitoring_engine', 'zabbix')
        return {**result, 'active': True}

    @app.get('/api/engine/devices')
    def devices(search: str = '', state: str = '', page: int = Query(1, ge=1), limit: int = Query(50, ge=1, le=100)):
        return current().inventory(search[:200], state, page, limit)

    @app.get('/api/engine/hosts/{hostid}/history')
    def history(hostid: str): return current().history(hostid)

    @app.post('/api/engine/hosts')
    async def create_host(request: Request):
        return await run_in_threadpool(current().add_host, await body(request))

    @app.post('/api/engine/hosts/{hostid}/check')
    def check(hostid: str): return current().check_now(hostid)

    @app.post('/api/engine/events/{eventid}/acknowledge')
    def acknowledge(eventid: str, request: Request):
        actor = require_role(request, 'admin', 'user')
        if actor['role'] != 'admin' and not actor.get('can_manage_alerts'):
            return JSONResponse({'error': 'permission_denied'}, status_code=403)
        return current().acknowledge(eventid, actor.get('username', 'operator'))

    @app.get('/api/engine/discovery')
    def discoveries(): return current().discoveries()

    @app.post('/api/engine/discovery')
    async def discovery(request: Request):
        return await run_in_threadpool(current().discover, (await body(request)).get('network', ''))

    @app.post('/api/engine/ha-token')
    def ha_token():
        token = secrets.token_urlsafe(40)
        path = Path(core.BASE_DIR) / 'home-assistant-token.sha256'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as handle: handle.write(hashlib.sha256(token.encode()).hexdigest())
        return {'token': token}

    @app.post('/api/engine/legacy')
    def legacy():
        if os.environ.get('HOMEII_ENGINE') == 'zabbix':
            raise EngineError('bundled_engine_required')
        core.set_setting('monitoring_engine', 'legacy')
        core.ensure_background_workers()
        return {'ok': True}
