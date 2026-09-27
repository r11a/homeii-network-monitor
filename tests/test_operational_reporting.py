import asyncio
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from app import core, api


class IsolatedDatabase(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="homeii-operations-")
        self.original = core.BASE_DIR, core.DB_PATH
        core.BASE_DIR = Path(self.directory.name)
        core.DB_PATH = core.BASE_DIR / "homeii.db"
        core.init_db()
        core.set_setting("history_retention_days", "365")
        self.now = int(time.time())

    def tearDown(self):
        core.BASE_DIR, core.DB_PATH = self.original
        self.directory.cleanup()

    def device(self, ip="192.0.2.1", first_seen=None):
        core.upsert_device(ip, {"name": ip, "status": "online", "approved": True, "first_seen": first_seen or self.now - 60 * 86400, "category": "Cameras"})
        conn = core.db()
        conn.execute("DELETE FROM device_history WHERE ip=?", (ip,))
        conn.commit()
        conn.close()

    def transition(self, ip, ts, old, new):
        conn = core.db()
        conn.execute("INSERT INTO device_history(ip,ts,old_status,new_status,kind) VALUES(?,?,?,?,?)", (ip, ts, old, new, "status"))
        conn.commit()
        conn.close()


class ReportingTests(IsolatedDatabase):
    def test_empty_and_unobserved_inventory_never_reports_full_uptime(self):
        report = core.system_history_payload(self.now - 86400, self.now)
        self.assertIsNone(report["summary"]["availability_pct"])
        self.device()
        report = core.system_history_payload(self.now - 86400, self.now)
        self.assertIsNone(report["summary"]["availability_pct"])
        self.assertIsNone(report["devices"][0]["availability_pct"])
        self.assertEqual(report["devices"][0]["coverage_pct"], 0)
        self.assertEqual(report["rankings"]["stable"], [])

    def test_partial_window_excludes_unknown_time_and_counts_events(self):
        self.device(first_seen=self.now - 1800)
        self.transition("192.0.2.1", self.now - 1800, "unknown", "online")
        self.transition("192.0.2.1", self.now - 900, "online", "offline")
        report = core.system_history_payload(self.now - 3600, self.now)
        row = report["devices"][0]
        self.assertEqual(row["availability_pct"], 50.0)
        self.assertEqual(row["coverage_pct"], 50.0)
        self.assertEqual(row["offline_count"], 1)
        self.assertEqual(row["category"], "Cameras")
        conn = core.db()
        detail = core.history_report_payload(conn, "192.0.2.1", self.now - 3600, self.now)
        conn.close()
        self.assertEqual(detail["summary"]["availability_pct"], row["availability_pct"])
        self.assertEqual(detail["summary"]["coverage_pct"], row["coverage_pct"])

    def test_initial_state_is_not_current_state_backfilled_into_past(self):
        self.device()
        self.transition("192.0.2.1", self.now - 1800, "offline", "online")
        report = core.system_history_payload(self.now - 3600, self.now)
        self.assertEqual(report["devices"][0]["coverage_pct"], 50.0)
        self.assertEqual(report["devices"][0]["recovery_count"], 1)

    def test_long_report_returns_all_days_and_true_affected_count(self):
        for index in range(12):
            ip = f"192.0.2.{index + 1}"
            self.device(ip)
            self.transition(ip, self.now - 40 * 86400, "unknown", "online")
            self.transition(ip, self.now - 86400, "online", "offline")
        report = core.system_history_payload(self.now - 30 * 86400, self.now)
        self.assertGreaterEqual(len(report["daily_series"]), 30)
        self.assertEqual(len(report["devices"]), 12)
        self.assertEqual(report["summary"]["devices_affected"], 12)
        self.assertEqual(len(report["affected_devices"]), 10)

    def test_retention_bounds_coverage(self):
        core.set_setting("history_retention_days", "1")
        self.device()
        self.transition("192.0.2.1", self.now - 4 * 86400, "unknown", "online")
        report = core.system_history_payload(self.now - 2 * 86400, self.now)
        self.assertEqual(report["summary"]["coverage_pct"], 50.0)

    def test_control_center_uses_retained_anchor_outside_the_day_window(self):
        self.device()
        self.transition("192.0.2.1", self.now - 2 * 86400, "unknown", "online")
        report = core.viewer_categories_payload()
        self.assertEqual(report["devices"]["192.0.2.1"]["availability_24h"], 100.0)
        self.assertEqual(report["devices"]["192.0.2.1"]["history_samples"], 1)

    def test_new_control_center_device_only_counts_time_after_first_evidence(self):
        self.device(first_seen=self.now - 120)
        self.transition("192.0.2.1", self.now - 120, "unknown", "online")
        timeline = core.viewer_categories_payload()["devices"]["192.0.2.1"]
        observed = sum(point["observed_seconds"] for point in timeline["series"])
        self.assertGreaterEqual(observed, 120)
        self.assertLessEqual(observed, 123)
        self.assertEqual(timeline["availability_24h"], 100.0)

    def test_stable_device_gets_initial_evidence_from_a_real_probe(self):
        self.device()
        with patch.object(core, "probe_device", return_value=(True, "ping", {})), patch.object(core, "reverse_dns", return_value=""):
            core.monitor_one_safe("192.0.2.1")
            core.monitor_one_safe("192.0.2.1")
        conn = core.db()
        rows = conn.execute("SELECT ts,old_status,new_status FROM device_history WHERE ip='192.0.2.1'").fetchall()
        conn.close()
        self.assertEqual(len(rows), 1)
        self.assertGreaterEqual(rows[0]["ts"], self.now)
        self.assertEqual(rows[0]["old_status"], "unknown")
        self.assertEqual(rows[0]["new_status"], "online")


class UserAdministrationTests(IsolatedDatabase):
    def setUp(self):
        super().setUp()
        conn = core.db()
        for name, role in [("primary", "admin"), ("operator", "user")]:
            conn.execute("INSERT INTO users(username,password_hash,role,created_at,updated_at) VALUES(?,?,?,?,?)", (name, "unused", role, self.now, self.now))
        conn.execute("INSERT INTO auth_sessions(token_hash,user_id,expires_at,created_at) VALUES('test-session',2,?,?)", (self.now + 3600, self.now))
        conn.commit(); conn.close()

    def update(self, payload, user_id=2):
        class Request:
            async def json(self):
                return payload
        with patch.object(api, "require_role", return_value={"id": 1, "role": "admin"}):
            return asyncio.run(api.api_admin_update_user(user_id, Request()))

    def test_partial_update_preserves_role_and_revokes_password_sessions(self):
        self.assertEqual(self.update({"password": "replacement-for-test"}), {"ok": True})
        conn = core.db()
        row = conn.execute("SELECT * FROM users WHERE id=2").fetchone()
        self.assertEqual(row["role"], "user")
        self.assertTrue(api.password_matches("replacement-for-test", row["password_hash"]))
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0], 0)
        conn.close()

    def test_role_change_revokes_sessions_but_cosmetic_change_does_not(self):
        self.update({"display_name": "Operator"})
        conn = core.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0], 1)
        conn.close()
        self.update({"role": "viewer"})
        conn = core.db()
        self.assertEqual(conn.execute("SELECT COUNT(*) FROM auth_sessions").fetchone()[0], 0)
        conn.close()

    def test_invalid_and_missing_users_are_rejected(self):
        self.assertEqual(self.update({"active": "false"}).status_code, 400)
        self.assertEqual(self.update({"password": "short"}).status_code, 400)
        self.assertEqual(self.update({}, 999).status_code, 404)
        self.assertEqual(self.update({"role": "viewer"}, 1).status_code, 409)

    def test_alert_resolution_requires_permission(self):
        with patch.object(api, "require_role", return_value={"role": "user", "can_manage_alerts": False}):
            self.assertEqual(api.api_resolve_alert(1, object()).status_code, 403)

    def test_successful_login_identifies_the_verified_audit_actor(self):
        from types import SimpleNamespace
        class Request:
            headers = {}
            client = SimpleNamespace(host="local-test")
            url = SimpleNamespace(scheme="http")
            state = SimpleNamespace()
            async def json(self):
                return {"username": "operator", "password": "test-only"}
        request = Request()
        with patch.object(api, "password_matches", return_value=True), patch.object(api, "login_attempt_allowed", return_value=True), patch.object(api, "record_login_attempt"):
            response = asyncio.run(api.api_auth_login(request))
        self.assertEqual(response.status_code, 200)
        self.assertEqual(request.state.audit_actor["username"], "operator")
        self.assertNotIn("password", request.state.audit_actor)


if __name__ == "__main__":
    unittest.main()
