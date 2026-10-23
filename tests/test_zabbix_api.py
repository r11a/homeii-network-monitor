import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

os.environ.setdefault('HOMEII_DATA_DIR', tempfile.mkdtemp(prefix='homeii-api-'))
from fastapi.testclient import TestClient
from app import api, core


class ZabbixPermissionTests(unittest.TestCase):
    def test_lan_cannot_forge_ingress_identity(self):
        from starlette.requests import Request
        request = Request({'type': 'http', 'client': ('192.168.1.20', 1234),
                           'headers': [(b'x-ingress-path', b'/fake'), (b'x-remote-user-name', b'admin')]})
        self.assertFalse(api.ingress_request(request))

    def test_ha_bridge_keeps_open_events_and_stable_device_identity(self):
        from app import engine_routes
        snapshot = {'stale': False, 'updated_at': 10, 'counts': {},
                    'events': [{'id': '7', 'name': 'Disconnected', 'since': 5}],
                    'devices': [{'id': '42', 'name': 'Camera', 'groups': [], 'last_check': 8}]}
        with patch.object(engine_routes, 'engine') as mocked:
            mocked.return_value.snapshot.return_value = snapshot
            result = engine_routes.ha_dashboard('unused')
        self.assertEqual(result['alerts'][0]['status'], 'open')
        self.assertEqual(result['alerts'][0]['message'], 'Disconnected')
        self.assertEqual(result['devices'][0]['device_id'], 'zabbix-42')

    def test_engine_read_requires_login(self):
        with patch.object(api, 'session_user', return_value=None):
            response = TestClient(api.app).get('/api/engine/devices')
        self.assertEqual(response.status_code, 401)

    def test_viewer_cannot_connect_or_create_hosts(self):
        with patch.object(api, 'session_user', return_value={'role': 'viewer', 'username': 'viewer'}), patch.object(api, 'log_audit'):
            client = TestClient(api.app)
            self.assertEqual(client.post('/api/engine/connect', json={}).status_code, 403)
            self.assertEqual(client.post('/api/engine/hosts', json={}).status_code, 403)

    def test_engine_route_exists_for_authenticated_viewer(self):
        with patch.object(api, 'session_user', return_value={'role': 'viewer', 'username': 'viewer'}):
            response = TestClient(api.app).get('/api/engine/config')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn('token', response.json())

    def test_legacy_workers_do_not_start_when_engine_selected(self):
        with patch.object(core, 'get_setting', return_value='zabbix'), patch.object(core, 'start_worker') as worker:
            core.ensure_background_workers()
        worker.assert_not_called()


if __name__ == '__main__': unittest.main()
