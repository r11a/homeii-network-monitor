"""Local Zabbix 7.x adapter. Zabbix remains the measurement/event authority."""
from __future__ import annotations

import copy
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import threading
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlunsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler, HTTPSHandler
import uuid


class EngineError(Exception):
    """Public, credential-free error code."""


def normalize_url(value: str) -> str:
    try:
        parts = urlsplit(value.strip())
        if parts.scheme not in ('http', 'https') or not parts.hostname or parts.username or parts.password or parts.query or parts.fragment:
            raise ValueError()
        _ = parts.port
        path = parts.path.rstrip('/')
        if not path.endswith('/api_jsonrpc.php'): path += '/api_jsonrpc.php'
        return urlunsplit((parts.scheme, parts.netloc, path, '', ''))
    except (ValueError, AttributeError):
        raise EngineError('invalid_server_url') from None


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise EngineError('server_redirect_not_allowed')


class Client:
    def __init__(self, config: dict):
        self.url = normalize_url(config.get('url', ''))
        self.token = config.get('token', '')
        context = ssl.create_default_context()
        if config.get('verify_tls', True) is not True:
            raise EngineError('tls_verification_required')
        self.opener = build_opener(NoRedirect(), HTTPSHandler(context=context))

    def call(self, method: str, params=None):
        headers = {'Content-Type': 'application/json-rpc'}
        if self.token and method not in ('apiinfo.version', 'user.login'):
            headers['Authorization'] = f'Bearer {self.token}'
        body = {'jsonrpc': '2.0', 'method': method, 'params': params if params is not None else {}, 'id': 1}
        try:
            with self.opener.open(Request(self.url, json.dumps(body).encode(), headers), timeout=15) as response:
                raw = response.read(32 * 1024 * 1024 + 1)
            if len(raw) > 32 * 1024 * 1024: raise EngineError('engine_response_too_large')
            result = json.loads(raw)
            if not isinstance(result, dict) or 'result' not in result:
                raise EngineError('engine_request_rejected')
            return result['result']
        except HTTPError as exc:
            raise EngineError('engine_access_denied' if exc.code in (401, 403) else 'engine_unreachable') from None
        except (URLError, TimeoutError, OSError):
            raise EngineError('engine_unreachable') from None
        except (ValueError, UnicodeError):
            raise EngineError('invalid_engine_response') from None


def interval_seconds(delay) -> int:
    match = re.fullmatch(r'(\d+)([smhd]?)', str(delay))
    if not match: return 60
    return max(1, int(match[1]) * {'': 1, 's': 1, 'm': 60, 'h': 3600, 'd': 86400}[match[2]])


def history_buckets(rows: list, now: int, interval: int = 60) -> dict:
    start = now - 86400
    buckets = [{'start': start + n * 900, 'status': 'unknown', 'samples': 0, 'availability': None} for n in range(96)]
    values = {}
    for row in rows:
        stamp = int(row['clock'])
        if start <= stamp <= now and str(row['value']) in ('0', '1'):
            values[stamp] = int(row['value'])
    counts = [[] for _ in buckets]
    covered = 0
    end = start
    for stamp, value in sorted(values.items()):
        counts[min(95, (stamp - start) // 900)].append(value)
        span_end = min(now, stamp + interval)
        covered += max(0, span_end - max(stamp, end))
        end = max(end, span_end)
    for bucket, samples in zip(buckets, counts):
        if samples:
            bucket.update(samples=len(samples), availability=round(sum(samples) / len(samples) * 100, 2),
                          status='online' if all(samples) else 'offline' if not any(samples) else 'unstable')
    return {'series': buckets, 'samples': len(values), 'coverage': round(covered / 86400 * 100, 2),
            'availability': round(sum(values.values()) / len(values) * 100, 2) if values else None,
            'method': 'successful_recorded_checks', 'from': start, 'to': now}


class Engine:
    def __init__(self, directory: Path):
        self.directory = directory
        self.lock = threading.RLock()
        self.cached = None
        self.attempted = 0.0
        self.histories = {}

    @property
    def config_path(self): return self.directory / 'zabbix-connection.json'

    def config(self) -> dict:
        try:
            result = json.loads(self.config_path.read_text(encoding='utf-8'))
            return result if isinstance(result, dict) else {}
        except (OSError, ValueError): return {}

    def save_config(self, config: dict):
        config = {**config, 'url': normalize_url(config['url'])}
        with self.lock:
            self.directory.mkdir(parents=True, exist_ok=True)
            temporary = self.config_path.with_suffix('.tmp')
            fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as handle:
                json.dump(config, handle)
            os.replace(temporary, self.config_path)
            self.cached = None; self.attempted = 0; self.histories.clear()

    def public_config(self):
        config = self.config()
        return {'configured': bool(config.get('token')), 'url': config.get('url', ''),
                'version': config.get('version', ''), 'local_bundle': bool(os.environ.get('HOMEII_BUNDLED_ZABBIX'))}

    def client(self):
        config = self.config()
        if not config.get('token'): raise EngineError('engine_not_configured')
        return Client(config)

    def connect(self, payload: dict):
        config = {'url': payload.get('url', ''), 'token': payload.get('token', ''), 'verify_tls': True}
        client = Client(config)
        version = str(client.call('apiinfo.version'))
        if not version.startswith('7.'): raise EngineError('unsupported_engine_version')
        # API token is preferred; username/password creates a session without retaining the password.
        if not config['token']:
            if not payload.get('username') or not payload.get('password'): raise EngineError('credentials_required')
            config['token'] = client.call('user.login', {'username': payload['username'], 'password': payload['password']})
            client.token = config['token']
        client.call('host.get', {'countOutput': True})
        config['version'] = version
        self.save_config(config)
        return self.public_config()

    def snapshot(self, force=False) -> dict:
        with self.lock:
            now = int(time.time())
            if not force and self.cached and time.monotonic() - self.attempted < 15:
                return self._aged(copy.deepcopy(self.cached), now)
            self.attempted = time.monotonic()
            try:
                client = self.client()
                hosts = client.call('host.get', {'output': ['hostid', 'host', 'name', 'status', 'maintenance_status'],
                    'selectInterfaces': ['interfaceid', 'ip', 'dns', 'useip', 'main'],
                    'selectHostGroups': ['groupid', 'name'], 'selectTags': 'extend', 'limit': 10001})
                if len(hosts) > 10000: raise EngineError('inventory_limit_exceeded')
                items = []
                for start in range(0, len(hosts), 500):
                    items.extend(client.call('item.get', {'hostids': [h['hostid'] for h in hosts[start:start+500]],
                        'output': ['itemid', 'hostid', 'key_', 'lastvalue', 'lastclock', 'state', 'status', 'value_type', 'delay'],
                        'search': {'key_': 'icmpping'}, 'startSearch': True}))
                by_host = {}
                for item in items:
                    key = item.get('key_', '').split('[')[0]
                    # Prefer enabled/supported items when a host has multiple checks.
                    entries = by_host.setdefault(item['hostid'], {})
                    if key not in entries or (item.get('status') == '0' and item.get('state') == '0'):
                        entries[key] = item
                problems = client.call('problem.get', {'output': ['eventid', 'objectid', 'name', 'severity', 'clock', 'acknowledged', 'suppressed'],
                    'source': 0, 'object': 0, 'sortfield': ['eventid'], 'sortorder': 'DESC', 'limit': 5001})
                truncated = len(problems) > 5000
                problems = problems[:5000]
                trigger_hosts = {}
                for start in range(0, len(problems), 500):
                    triggers = client.call('trigger.get', {'triggerids': list({p['objectid'] for p in problems[start:start+500]}),
                        'output': ['triggerid'], 'selectHosts': ['hostid']})
                    trigger_hosts.update({t['triggerid']: [h['hostid'] for h in t.get('hosts', [])] for t in triggers})
                devices = []
                for host in hosts:
                    probes = by_host.get(host['hostid'], {})
                    ping = probes.get('icmpping', {})
                    interfaces = sorted(host.get('interfaces', []), key=lambda x: x.get('main') != '1')
                    interface = interfaces[0] if interfaces else {}
                    tags = {t['tag']: t['value'] for t in host.get('tags', [])}
                    devices.append({'id': host['hostid'], 'name': host.get('name') or host['host'],
                        'ip': interface.get('ip', '') if interface.get('useip', '1') == '1' else interface.get('dns', ''),
                        'groups': [g['name'] for g in host.get('hostgroups', [])],
                        'critical': tags.get('homeii.priority') == 'critical', 'location': tags.get('homeii.location', ''),
                        'status': 'unknown', 'paused': host.get('status') != '0', 'maintenance': host.get('maintenance_status') == '1',
                        'last_check': int(ping.get('lastclock') or 0), 'check_interval': interval_seconds(ping.get('delay', '60')),
                        'probe_ok': ping.get('state') == '0' and ping.get('status') == '0',
                        'probe_value': ping.get('lastvalue'), 'itemid': ping.get('itemid'),
                        'latency_ms': self._metric(probes.get('icmppingsec'), now, 1000),
                        'loss_percent': self._metric(probes.get('icmppingloss'), now)})
                events = [{'id': p['eventid'], 'name': p['name'], 'severity': int(p['severity']), 'since': int(p['clock']),
                           'acknowledged': p.get('acknowledged') == '1', 'suppressed': p.get('suppressed') == '1',
                           'hostids': trigger_hosts.get(p['objectid'], [])} for p in problems]
                self.cached = {'devices': devices, 'events': events, 'updated_at': now, 'stale': False, 'error': '',
                               'events_truncated': truncated, 'engine': 'zabbix'}
            except EngineError as exc:
                self.cached = {**(self.cached or {'devices': [], 'events': [], 'updated_at': 0, 'engine': 'zabbix'}),
                               'stale': True, 'error': str(exc)}
            return self._aged(copy.deepcopy(self.cached), now)

    @staticmethod
    def _metric(item, now, multiplier=1):
        if not item or item.get('state') != '0' or item.get('status') != '0': return None
        if now - int(item.get('lastclock') or 0) > max(90, 3 * interval_seconds(item.get('delay', '60'))): return None
        try: return round(float(item['lastvalue']) * multiplier, 2)
        except (ValueError, TypeError, KeyError): return None

    @staticmethod
    def _aged(snapshot, now):
        counts = {'online': 0, 'offline': 0, 'unknown': 0, 'paused': 0, 'maintenance': 0}
        for device in snapshot['devices']:
            fresh = 0 <= now - device['last_check'] <= max(90, 3 * device['check_interval'])
            state = 'unknown'
            if device['paused']: state = 'paused'
            elif device['maintenance']: state = 'maintenance'
            elif device['probe_ok'] and fresh and device['probe_value'] in ('0', '1'):
                state = 'online' if device['probe_value'] == '1' else 'offline'
            device['status'] = state
            counts[state] += 1
        snapshot['counts'] = {**counts, 'total': len(snapshot['devices']), 'problems': len(snapshot['events'])}
        return snapshot

    def inventory(self, search='', state='', page=1, limit=50):
        snapshot = self.snapshot()
        needle = search.casefold().strip()
        devices = [d for d in snapshot['devices'] if (not state or d['status'] == state) and
                   (not needle or needle in ' '.join([d['name'], d['ip'], d['location'], *d['groups']]).casefold())]
        rank = {'offline': 0, 'unknown': 1, 'maintenance': 2, 'paused': 3, 'online': 4}
        devices.sort(key=lambda d: (not d['critical'], rank[d['status']], d['name'].casefold(), d['id']))
        page = max(1, int(page)); limit = max(1, min(100, int(limit)))
        return {**{k: v for k, v in snapshot.items() if k != 'devices'}, 'devices': devices[(page-1)*limit:page*limit],
                'total': len(devices), 'page': page, 'limit': limit}

    def history(self, hostid):
        snapshot = self.snapshot()
        if snapshot['stale']: raise EngineError(snapshot['error'])
        host = next((d for d in snapshot['devices'] if d['id'] == hostid), None)
        if not host: raise EngineError('host_not_found')
        now = int(time.time())
        with self.lock:
            cached = self.histories.get(hostid)
            if cached and now - cached['to'] < 30: return cached
            rows = []
            if host['itemid']:
                rows = self.client().call('history.get', {'itemids': [host['itemid']], 'history': 3,
                    'output': ['clock', 'value'], 'time_from': now-86400, 'time_till': now,
                    'sortfield': ['clock'], 'sortorder': 'DESC', 'limit': 20000})
            result = {**history_buckets(rows, now, host['check_interval']), 'hostid': hostid,
                      'truncated': len(rows) == 20000}
            if len(self.histories) > 200: self.histories.clear()
            self.histories[hostid] = result
            return result

    def add_host(self, payload):
        try: ip = str(ipaddress.ip_address(str(payload.get('ip', '')).strip()))
        except ValueError: raise EngineError('invalid_ip') from None
        name = str(payload.get('name') or ip).strip()[:128]
        group = str(payload.get('group') or 'HOMEii').strip()[:128]
        with self.lock:
            snapshot = self.snapshot(force=True)
            if snapshot['stale']: raise EngineError(snapshot['error'])
            if any(d['ip'] == ip for d in snapshot['devices']): raise EngineError('duplicate_address')
            client = self.client()
            groups = client.call('hostgroup.get', {'filter': {'name': [group]}, 'output': ['groupid']})
            groupid = groups[0]['groupid'] if groups else client.call('hostgroup.create', {'name': group})['groupids'][0]
            templates = client.call('template.get', {'filter': {'host': ['ICMP Ping']}, 'output': ['templateid']})
            if not templates: raise EngineError('icmp_template_missing')
            result = client.call('host.create', {'host': 'homeii-' + uuid.uuid5(uuid.NAMESPACE_URL, 'homeii:ip:' + ip).hex, 'name': name,
                'interfaces': [{'type': 1, 'main': 1, 'useip': 1, 'ip': ip, 'dns': '', 'port': '10050'}],
                'groups': [{'groupid': groupid}], 'templates': [{'templateid': templates[0]['templateid']}],
                'tags': [{'tag': 'homeii.priority', 'value': 'critical' if payload.get('critical') is True else 'normal'},
                         {'tag': 'homeii.location', 'value': str(payload.get('location', ''))[:255]}]})
            self.attempted = 0
            return {'id': result['hostids'][0], 'name': name, 'ip': ip}

    def acknowledge(self, eventid, actor):
        snapshot = self.snapshot(force=True)
        if snapshot['stale']: raise EngineError(snapshot['error'])
        if not any(e['id'] == eventid for e in snapshot['events']): raise EngineError('event_not_found')
        self.client().call('event.acknowledge', {'eventids': [eventid], 'action': 6, 'message': f'HOMEii: acknowledged by {actor[:128]}'})
        self.attempted = 0
        return {'ok': True}

    def check_now(self, hostid):
        snapshot = self.snapshot()
        if snapshot['stale']: raise EngineError(snapshot['error'])
        host = next((d for d in snapshot['devices'] if d['id'] == hostid), None)
        if not host or not host['itemid'] or host['paused']: raise EngineError('check_unavailable')
        self.client().call('task.create', {'type': 6, 'request': {'itemid': host['itemid']}})
        return {'ok': True, 'queued': True}

    def discover(self, network):
        try:
            net = ipaddress.ip_network(network, strict=False)
            private = [ipaddress.ip_network(n) for n in ('10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16')]
            if net.version != 4 or net.num_addresses > 4096 or not any(net.subnet_of(p) for p in private): raise ValueError()
        except (ValueError, TypeError): raise EngineError('invalid_local_network') from None
        name = f'HOMEii {net}'
        with self.lock:
            client = self.client()
            rules = client.call('drule.get', {'filter': {'name': [name]}, 'output': ['druleid']})
            if rules: return {'ok': True, 'id': rules[0]['druleid']}
            # Zabbix accepts IPv4 CIDR masks only through /30. Keep /31-/32
            # bounded by listing their actual addresses instead of widening them.
            iprange = ','.join(str(address) for address in net) if net.prefixlen > 30 else str(net)
            result = client.call('drule.create', {'name': name, 'iprange': iprange, 'delay': '10m',
                'dchecks': [{'type': 12}]})
            return {'ok': True, 'id': result['druleids'][0]}

    def discoveries(self):
        client = self.client()
        rules = client.call('drule.get', {'output': ['druleid', 'name', 'iprange', 'status'], 'search': {'name': 'HOMEii '}, 'startSearch': True})
        if not rules: return {'rules': [], 'devices': []}
        found = client.call('dhost.get', {'druleids': [r['druleid'] for r in rules], 'output': ['dhostid', 'status'],
            'selectDServices': ['ip', 'dns', 'status', 'lastup'], 'limit': 10001})
        snapshot = self.snapshot()
        if snapshot['stale']: raise EngineError(snapshot['error'])
        existing = {d['ip'] for d in snapshot['devices']}
        devices = {}
        for host in found:
            for service in host.get('dservices', []):
                ip = service.get('ip')
                if ip and ip not in existing and service.get('status') == '0':
                    devices[ip] = {'ip': ip, 'name': service.get('dns') or ip, 'identity': 'address_only',
                                   'last_seen': int(service.get('lastup') or 0)}
        return {'rules': rules, 'devices': list(devices.values()), 'truncated': len(found) > 10000}
