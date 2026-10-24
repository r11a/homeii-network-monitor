"""Protocol and product contracts for the local monitoring engine."""
import importlib.util
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import tempfile
import threading
import time
import unittest


class EngineTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('app.zabbix'), 'Zabbix adapter is implemented')
        from app import zabbix
        self.z = zabbix
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.calls = []
        self.now = int(time.time())
        self.hosts = [{'hostid': '42', 'host': 'camera', 'name': 'Camera', 'status': '0', 'maintenance_status': '0',
                      'interfaces': [{'ip': '192.0.2.4', 'dns': '', 'useip': '1', 'main': '1'}], 'hostgroups': [], 'tags': []}]
        self.items = [{'hostid': '42', 'itemid': '11', 'key_': 'icmpping', 'lastvalue': '1', 'lastclock': str(self.now),
                       'state': '0', 'status': '0', 'value_type': '3', 'delay': '30s'}]
        self.failure = False
        owner = self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_): pass
            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                owner.calls.append((request, self.headers.get('Authorization')))
                method = request['method']
                results = {'apiinfo.version': '7.0.21', 'host.get': owner.hosts, 'item.get': owner.items,
                           'problem.get': [], 'history.get': [], 'hostgroup.get': [{'groupid': '2'}],
                           'template.get': [{'templateid': '3'}], 'host.create': {'hostids': ['43']},
                           'dhost.get': [], 'drule.get': [], 'drule.create': {'druleids': ['1']},
                           'event.acknowledge': {'eventids': ['9']}, 'task.create': {'taskids': ['1']}}
                reply = {'jsonrpc': '2.0', 'id': request['id']}
                if owner.failure: reply['error'] = {'code': -32602, 'data': 'SECRET must not leak'}
                else: reply['result'] = results.get(method, [])
                raw = json.dumps(reply).encode()
                self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(raw)
        self.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close); self.addCleanup(self.server.shutdown)
        self.config = {'url': f'http://127.0.0.1:{self.server.server_port}', 'token': 'SECRET', 'verify_tls': True}
        self.engine = zabbix.Engine(Path(self.tmp.name))
        self.engine.save_config(self.config)

    def test_snapshot_uses_stable_hostid_and_measured_state(self):
        first = self.engine.snapshot()
        self.assertEqual(first['devices'][0]['id'], '42')
        self.assertEqual(first['devices'][0]['status'], 'online')
        self.hosts[0]['interfaces'][0]['ip'] = '192.0.2.9'
        second = self.engine.snapshot(force=True)
        self.assertEqual(second['devices'][0]['id'], '42')
        self.assertEqual(second['devices'][0]['ip'], '192.0.2.9')
        self.assertNotIn('SECRET', json.dumps(second))
        self.assertEqual(self.calls[0][1], 'Bearer SECRET')

    def test_missing_old_and_unsupported_samples_are_unknown(self):
        for change in ({'lastclock': '0'}, {'lastclock': str(self.now - 1000)}, {'state': '1'}, {'status': '1'}):
            original = self.items[0].copy(); self.items[0].update(change)
            self.assertEqual(self.engine.snapshot(force=True)['devices'][0]['status'], 'unknown')
            self.items[0] = original

    def test_failure_preserves_snapshot_with_stale_flag_and_sanitized_error(self):
        self.engine.snapshot()
        self.failure = True
        result = self.engine.snapshot(force=True)
        self.assertTrue(result['stale'])
        self.assertEqual(len(result['devices']), 1)
        self.assertNotIn('SECRET', json.dumps(result))

    def test_snapshot_cache_avoids_per_viewer_engine_polling(self):
        self.engine.snapshot(); count = len(self.calls)
        self.engine.snapshot()
        self.assertEqual(len(self.calls), count)

    def test_private_configuration_never_exposes_token(self):
        self.assertNotIn('SECRET', json.dumps(self.engine.public_config()))
        self.assertTrue(self.engine.public_config()['configured'])
        self.assertTrue((Path(self.tmp.name) / 'zabbix-connection.json').exists())

    def test_history_has_real_gaps_and_sample_availability(self):
        result = self.z.history_buckets([{'clock': str(self.now - 30), 'value': '1'},
                                        {'clock': str(self.now - 60), 'value': '0'}], self.now)
        self.assertEqual(len(result['series']), 96)
        self.assertEqual(result['availability'], 50.0)
        self.assertEqual(result['samples'], 2)
        self.assertEqual(result['series'][0]['status'], 'unknown')
        self.assertLess(result['coverage'], 1)

    def test_host_creation_rejects_duplicate_address(self):
        with self.assertRaisesRegex(self.z.EngineError, 'duplicate_address'):
            self.engine.add_host({'ip': '192.0.2.4', 'name': 'Duplicate'})
        self.assertFalse(any(call[0]['method'] == 'host.create' for call in self.calls))

    def test_new_host_uses_template_and_does_not_auto_approve_discoveries(self):
        self.engine.add_host({'ip': '192.0.2.5', 'name': 'New camera', 'group': 'Cameras'})
        first = next(c[0]['params']['host'] for c in self.calls if c[0]['method'] == 'host.create')
        self.calls.clear()
        self.engine.add_host({'ip': '192.0.2.5', 'name': 'Other name'})
        second = next(c[0]['params']['host'] for c in self.calls if c[0]['method'] == 'host.create')
        self.assertEqual(first, second, 'Zabbix must enforce one internal host name per address across workers')
        request = next(call[0] for call in self.calls if call[0]['method'] == 'host.create')
        self.assertEqual(request['params']['templates'], [{'templateid': '3'}])
        self.assertEqual(request['params']['interfaces'][0]['ip'], '192.0.2.5')
        self.assertFalse(any(call[0]['method'] == 'action.create' for call in self.calls))

    def test_discovery_rejects_unbounded_and_public_networks(self):
        for network in ('0.0.0.0/0', '8.8.8.0/24', '192.168.0.0/16', 'bad'):
            with self.assertRaises(self.z.EngineError): self.engine.discover(network)
        self.assertFalse(any(call[0]['method'] == 'drule.create' for call in self.calls))

    def test_single_address_discovery_uses_engine_supported_range(self):
        self.engine.discover('192.168.1.4/32')
        params = next(c[0]['params'] for c in self.calls if c[0]['method'] == 'drule.create')
        self.assertEqual(params['iprange'], '192.168.1.4')
        self.assertNotIn('uniq', params['dchecks'][0])

    def test_update_preserves_external_tags_and_sets_pause(self):
        self.hosts[0]['tags'] = [{'tag': 'owner', 'value': 'IT'}, {'tag': 'homeii.location', 'value': 'old'}]
        self.engine.update_host('42', {'name': 'Camera gate', 'location': 'Gate', 'critical': True, 'paused': True})
        params = next(c[0]['params'] for c in self.calls if c[0]['method'] == 'host.update')
        self.assertEqual(params['status'], '1')
        self.assertEqual(params['name'], 'Camera gate')
        self.assertIn({'tag': 'owner', 'value': 'IT'}, params['tags'])
        self.assertIn({'tag': 'homeii.location', 'value': 'Gate'}, params['tags'])
        self.assertNotIn('interfaces', params)

    def test_period_report_queries_requested_window_and_separate_cache(self):
        self.engine.history('42', 7)
        params = next(c[0]['params'] for c in self.calls if c[0]['method'] == 'history.get')
        self.assertAlmostEqual(params['time_till'] - params['time_from'], 7*86400, delta=2)
        count = len(self.calls)
        self.engine.history('42', 7)
        self.assertEqual(len(self.calls), count)
        result = self.engine.history('42', 1)
        self.assertEqual(result['to'] - result['from'], 86400)

    def test_period_coverage_uses_full_window(self):
        result = self.z.history_buckets([{'clock': self.now-30, 'value': '1'}], self.now, 30, 7)
        self.assertEqual(result['to']-result['from'], 7*86400)
        self.assertEqual(len(result['series']), 96)
        self.assertLess(result['coverage'], 0.01)

    def test_url_rejects_credentials_query_and_non_http(self):
        for value in ('file:///etc/passwd', 'https://user:pass@host', 'https://host?token=x'):
            with self.assertRaises(self.z.EngineError): self.z.normalize_url(value)


if __name__ == '__main__': unittest.main()
