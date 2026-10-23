"""Run inside the built image with --network none; never touches a real LAN."""
import http.cookiejar
import json
import time
import urllib.error
import urllib.request

base = 'http://127.0.0.1:8384'
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))


def request(path, payload=None, headers=None):
    req = urllib.request.Request(base + path, None if payload is None else json.dumps(payload).encode(),
                                 {'Content-Type': 'application/json', **(headers or {})})
    with opener.open(req, timeout=20) as response:
        return json.load(response)


deadline = time.monotonic() + 180
while True:
    try:
        request('/api/health/live')
        break
    except (OSError, urllib.error.URLError):
        if time.monotonic() > deadline: raise
        time.sleep(3)
credentials = {'username': 'smoke-admin', 'password': 'Offline-test-only-1234'}
session = request('/api/auth/session')
request('/api/auth/setup' if session['setup_required'] else '/api/auth/login', credentials)
assert request('/api/engine/config')['configured']
snapshot = request('/api/engine/devices')
assert not snapshot['stale'], snapshot
devices = snapshot['devices']
host = next((d for d in devices if d['ip'] == '127.0.0.1'), None)
if host is None:
    host = request('/api/engine/hosts', {'name': 'Offline loopback', 'ip': '127.0.0.1', 'critical': True})
else:
    print('Persisted device found:', host['id'])
try:
    request('/api/engine/hosts', {'name': 'Duplicate', 'ip': '127.0.0.1'})
    raise AssertionError('Duplicate accepted')
except urllib.error.HTTPError as exc:
    assert exc.code == 400 and json.load(exc)['error'] == 'duplicate_address'
deadline = time.monotonic() + 180
while True:
    snapshot = request('/api/engine/devices')
    measured = next(d for d in snapshot['devices'] if d['id'] == host['id'])
    if measured['status'] == 'online': break
    assert time.monotonic() < deadline, snapshot
    time.sleep(10)
history = request('/api/engine/hosts/' + host['id'] + '/history')
assert history['samples'] > 0 and len(history['series']) == 96, history
assert request('/api/engine/hosts/' + host['id'] + '/check', {})['queued']
rule = request('/api/engine/discovery', {'network': '192.168.254.254/32'})
assert request('/api/engine/discovery', {'network': '192.168.254.254/32'})['id'] == rule['id']
assert 'devices' in request('/api/engine/discovery')
print('PASS: offline boot, authentication, real ICMP, history, deduplication, check-now, discovery')
