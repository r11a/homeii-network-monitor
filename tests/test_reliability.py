import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import unittest


TEST_DATA = tempfile.mkdtemp(prefix="homeii-tests-")
os.environ["HOMEII_DATA_DIR"] = TEST_DATA

from app.main import (  # noqa: E402
    login_attempt_allowed,
    next_probe_status,
    password_hash,
    password_matches,
    record_login_attempt,
    stale_worker_names,
)
import app.core as main  # noqa: E402


class ProbeStateTests(unittest.TestCase):
    def test_unmanaged_device_remains_new(self):
        self.assertEqual(next_probe_status("unknown", False, True, 0, 1, 2), "new")

    def test_managed_device_does_not_fail_before_threshold(self):
        self.assertEqual(next_probe_status("online", True, False, 1, 0, 2), "online")

    def test_managed_device_fails_at_threshold(self):
        self.assertEqual(next_probe_status("online", True, False, 2, 0, 2), "offline")

    def test_managed_device_recovers(self):
        self.assertEqual(next_probe_status("offline", True, True, 0, 1, 2), "online")


class PasswordTests(unittest.TestCase):
    def test_password_hash_is_salted_and_verifiable(self):
        first = password_hash("correct horse battery staple")
        second = password_hash("correct horse battery staple")
        self.assertNotEqual(first, second)
        self.assertTrue(password_matches("correct horse battery staple", first))
        self.assertFalse(password_matches("wrong", first))

    def test_login_rate_limit_resets_after_success(self):
        client = "unit-test-client"
        for _ in range(5):
            record_login_attempt(client, False)
        self.assertFalse(login_attempt_allowed(client))
        record_login_attempt(client, True)
        self.assertTrue(login_attempt_allowed(client))


class WorkerHealthTests(unittest.TestCase):
    def test_missing_cycle_is_stale(self):
        workers = {
            name: {"alive": True, "last_cycle": 0, "interval": 30}
            for name in ("monitor", "critical_monitor", "rescan")
        }
        self.assertEqual(
            stale_worker_names(workers, timestamp=1_000),
            ["monitor", "critical_monitor", "rescan"],
        )

    def test_recent_workers_are_healthy(self):
        workers = {
            name: {"alive": True, "last_cycle": 990, "interval": 30}
            for name in ("monitor", "critical_monitor", "rescan")
        }
        self.assertEqual(stale_worker_names(workers, timestamp=1_000), [])


class AvailabilityTimelineTests(unittest.TestCase):
    def test_viewer_timeline_is_a_rolling_24_hour_window(self):
        payload = main.viewer_categories_payload()
        series = payload["summary"]["series"]
        self.assertEqual(len(series), 24)
        self.assertEqual([point["ts"] for point in series], sorted(point["ts"] for point in series))
        self.assertLessEqual(series[-1]["ts"], int(time.time()))
        self.assertGreaterEqual(series[0]["ts"], int(time.time()) - (24 * 3600) - 60)


class AlertRuleTests(unittest.TestCase):
    def setUp(self):
        self.original_base, self.original_db = main.BASE_DIR, main.DB_PATH
        self.temp_dir = tempfile.TemporaryDirectory(prefix="homeii-alert-rules-")
        main.BASE_DIR = Path(self.temp_dir.name)
        main.DB_PATH = main.BASE_DIR / "homeii.db"
        main.init_db()

    def tearDown(self):
        main.BASE_DIR, main.DB_PATH = self.original_base, self.original_db
        self.temp_dir.cleanup()

    def test_critical_offline_rule_is_attached_to_matching_alert(self):
        conn = main.db()
        try:
            now = int(time.time())
            conn.execute(
                "INSERT INTO devices(ip,name,status,critical,approved,updated_at) VALUES(?,?,?,?,?,?)",
                ("10.0.0.20", "Core switch", "offline", 1, 1, now),
            )
            conn.execute(
                "INSERT INTO alert_rules(name,enabled,trigger_type,condition_json,action_json,severity,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?)",
                ("Critical offline", 1, "critical_offline", "{}", '{"sound": true, "toast": true}', "critical", now, now),
            )
            conn.commit()
        finally:
            conn.close()
        main.create_alert("10.0.0.20", "high", main.ALERT_TITLE_OFFLINE, "Core switch is offline")
        conn = main.db()
        try:
            alert = conn.execute("SELECT severity,rule_id,action_json FROM alerts").fetchone()
            self.assertEqual(alert["severity"], "critical")
            self.assertGreater(alert["rule_id"], 0)
            self.assertTrue(json.loads(alert["action_json"])["sound"])
        finally:
            conn.close()


class InventoryCleanupTests(unittest.TestCase):
    def test_cleanup_suppresses_offline_and_duplicate_devices(self):
        original_base, original_db = main.BASE_DIR, main.DB_PATH
        with tempfile.TemporaryDirectory(prefix="homeii-cleanup-") as temp_dir:
            main.BASE_DIR = Path(temp_dir)
            main.DB_PATH = main.BASE_DIR / "homeii.db"
            try:
                main.init_db()
                conn = main.db()
                try:
                    now = int(time.time())
                    conn.execute("INSERT INTO devices(ip,mac,status,approved,last_seen,updated_at) VALUES(?,?,?,?,?,?)", ("10.0.0.10", "aa:bb:cc:dd:ee:ff", "online", 1, now, now))
                    conn.execute("INSERT INTO devices(ip,mac,status,approved,last_seen,updated_at) VALUES(?,?,?,?,?,?)", ("10.0.0.11", "AA-BB-CC-DD-EE-FF", "new", 0, now - 60, now - 60))
                    conn.execute("INSERT INTO devices(ip,status,approved,last_seen,updated_at) VALUES(?,?,?,?,?)", ("10.0.0.12", "offline", 1, now - 3600, now))
                    conn.commit()
                finally:
                    conn.close()
                result = main.permanently_suppress_stale_inventory()
                self.assertEqual(result, {"offline": 1, "duplicates": 1})
                conn = main.db()
                try:
                    visible = conn.execute("SELECT ip FROM devices WHERE ignored=0 ORDER BY ip").fetchall()
                    self.assertEqual([row["ip"] for row in visible], ["10.0.0.10"])
                finally:
                    conn.close()
            finally:
                main.BASE_DIR, main.DB_PATH = original_base, original_db


class DeviceIdentityTests(unittest.TestCase):
    def setUp(self):
        self.original_base, self.original_db = main.BASE_DIR, main.DB_PATH
        self.temp_dir = tempfile.TemporaryDirectory(prefix="homeii-identity-")
        main.BASE_DIR = Path(self.temp_dir.name)
        main.DB_PATH = main.BASE_DIR / "homeii.db"
        main.init_db()

    def tearDown(self):
        main.BASE_DIR, main.DB_PATH = self.original_base, self.original_db
        self.temp_dir.cleanup()

    def test_preflight_blocks_existing_ip_and_mac(self):
        now = int(time.time())
        conn = main.db()
        try:
            conn.execute(
                "INSERT INTO devices(ip,mac,name,status,approved,last_seen,updated_at) VALUES(?,?,?,?,?,?,?)",
                ("10.0.0.30", "aa:bb:cc:dd:ee:ff", "Core switch", "online", 1, now, now),
            )
            conn.commit()
        finally:
            conn.close()
        conflicts = main.device_identity_conflicts("10.0.0.31", "AA-BB-CC-DD-EE-FF")
        self.assertEqual(conflicts[0]["ip"], "10.0.0.30")
        self.assertIn("mac", conflicts[0]["reasons"])

    def test_known_mac_moves_to_new_ip_without_losing_metadata(self):
        now = int(time.time())
        conn = main.db()
        try:
            conn.execute(
                "INSERT INTO devices(ip,mac,name,status,approved,category,tags_json,last_seen,updated_at) VALUES(?,?,?,?,?,?,?,?,?)",
                ("10.0.0.40", "aa:bb:cc:dd:ee:11", "Camera A", "offline", 1, "Cameras", '["Core"]', now - 60, now),
            )
            conn.execute(
                "INSERT INTO device_history(ip,ts,old_status,new_status) VALUES(?,?,?,?)",
                ("10.0.0.40", now - 30, "online", "offline"),
            )
            conn.commit()
            moved = main.reconcile_mac_identity(conn, "10.0.0.41", "AA-BB-CC-DD-EE-11")
            conn.commit()
            self.assertEqual(moved["ip"], "10.0.0.41")
            row = conn.execute("SELECT * FROM devices WHERE ip='10.0.0.41'").fetchone()
            self.assertEqual(row["name"], "Camera A")
            self.assertEqual(row["category"], "Cameras")
            self.assertEqual(json.loads(row["tags_json"]), ["Core"])
            self.assertIsNone(conn.execute("SELECT ip FROM devices WHERE ip='10.0.0.40'").fetchone())
            self.assertEqual(
                conn.execute("SELECT ip FROM device_history LIMIT 1").fetchone()["ip"],
                "10.0.0.41",
            )
        finally:
            conn.close()


class LabelDefinitionTests(unittest.TestCase):
    def test_deleting_definition_preserves_device_assignment(self):
        original_base, original_db = main.BASE_DIR, main.DB_PATH
        with tempfile.TemporaryDirectory(prefix="homeii-labels-") as temp_dir:
            main.BASE_DIR = Path(temp_dir)
            main.DB_PATH = main.BASE_DIR / "homeii.db"
            try:
                main.init_db()
                main.save_label_definition("category", "Cameras", "#35d49a", "camera")
                label = main.label_definitions_payload()["categories"][0]
                conn = main.db()
                try:
                    now = int(time.time())
                    conn.execute(
                        "INSERT INTO devices(ip,status,category,last_seen,updated_at) VALUES(?,?,?,?,?)",
                        ("10.0.0.20", "online", "Cameras", now, now),
                    )
                    conn.commit()
                finally:
                    conn.close()
                self.assertTrue(main.delete_label_definition(label["id"]))
                conn = main.db()
                try:
                    device = conn.execute("SELECT category FROM devices WHERE ip='10.0.0.20'").fetchone()
                    self.assertEqual(device["category"], "Cameras")
                finally:
                    conn.close()
            finally:
                main.BASE_DIR, main.DB_PATH = original_base, original_db

    def test_renaming_category_updates_assigned_devices(self):
        original_base, original_db = main.BASE_DIR, main.DB_PATH
        with tempfile.TemporaryDirectory(prefix="homeii-label-rename-") as temp_dir:
            main.BASE_DIR = Path(temp_dir)
            main.DB_PATH = main.BASE_DIR / "homeii.db"
            try:
                main.init_db()
                main.save_label_definition("category", "Cameras", "#35d49a", "camera")
                label = main.label_definitions_payload()["categories"][0]
                conn = main.db()
                try:
                    now = int(time.time())
                    conn.execute("INSERT INTO devices(ip,status,category,last_seen,updated_at) VALUES(?,?,?,?,?)", ("10.0.0.21", "online", "Cameras", now, now))
                    conn.commit()
                finally:
                    conn.close()
                main.update_label_definition(label["id"], "Security Cameras", "#ffb52e", "camera")
                conn = main.db()
                try:
                    device = conn.execute("SELECT category FROM devices WHERE ip='10.0.0.21'").fetchone()
                    self.assertEqual(device["category"], "Security Cameras")
                finally:
                    conn.close()
                category = next(
                    item
                    for item in main.viewer_categories_payload()["categories"]
                    if item["category"] == "Security Cameras"
                )
                self.assertEqual(category["color"], "#ffb52e")
                self.assertEqual(category["icon"], "camera")
            finally:
                main.BASE_DIR, main.DB_PATH = original_base, original_db

    def test_renaming_tag_updates_device_assignments(self):
        original_base, original_db = main.BASE_DIR, main.DB_PATH
        with tempfile.TemporaryDirectory(prefix="homeii-tag-rename-") as temp_dir:
            main.BASE_DIR = Path(temp_dir)
            main.DB_PATH = main.BASE_DIR / "homeii.db"
            try:
                main.init_db()
                main.save_label_definition("tag", "Production", "#35d49a", "server")
                label = main.label_definitions_payload()["tags"][0]
                conn = main.db()
                try:
                    now = int(time.time())
                    conn.execute(
                        "INSERT INTO devices(ip,status,tags_json,last_seen,updated_at) VALUES(?,?,?,?,?)",
                        ("10.0.0.22", "online", '["Production", "Critical"]', now, now),
                    )
                    conn.commit()
                finally:
                    conn.close()
                main.update_label_definition(label["id"], "Core", "#ffb52e", "server")
                conn = main.db()
                try:
                    device = conn.execute(
                        "SELECT tags_json FROM devices WHERE ip='10.0.0.22'"
                    ).fetchone()
                    self.assertEqual(json.loads(device["tags_json"]), ["Core", "Critical"])
                finally:
                    conn.close()
            finally:
                main.BASE_DIR, main.DB_PATH = original_base, original_db


class MigrationSafetyTests(unittest.TestCase):
    def test_existing_database_is_backed_up_before_schema_upgrade(self):
        original_base, original_db = main.BASE_DIR, main.DB_PATH
        with tempfile.TemporaryDirectory(prefix="homeii-migration-") as temp_dir:
            base = Path(temp_dir)
            target = base / "homeii.db"
            source = sqlite3.connect(original_db)
            destination = sqlite3.connect(target)
            try:
                source.backup(destination)
                destination.execute("DELETE FROM schema_migrations")
                destination.execute(
                    "INSERT INTO schema_migrations(version, applied_at) VALUES(6, 1)"
                )
                destination.commit()
            finally:
                destination.close()
                source.close()
            try:
                main.BASE_DIR, main.DB_PATH = base, target
                main.init_db()
                backups = list((base / "backups").glob("homeii-pre-schema-10-*.db"))
                self.assertEqual(len(backups), 1)
            finally:
                main.BASE_DIR, main.DB_PATH = original_base, original_db

    def test_real_legacy_schema_is_upgraded_before_indexes_are_created(self):
        original_base, original_db = main.BASE_DIR, main.DB_PATH
        with tempfile.TemporaryDirectory(prefix="homeii-v5-migration-") as temp_dir:
            base = Path(temp_dir)
            target = base / "homeii.db"
            legacy = sqlite3.connect(target)
            try:
                legacy.executescript(
                    """
                    CREATE TABLE devices (
                      ip TEXT PRIMARY KEY, name TEXT DEFAULT '', hostname TEXT DEFAULT '',
                      category TEXT DEFAULT '', vendor TEXT DEFAULT '', mac TEXT DEFAULT '',
                      status TEXT DEFAULT 'unknown', last_seen INTEGER DEFAULT 0,
                      critical INTEGER DEFAULT 0, pinned INTEGER DEFAULT 0,
                      manual INTEGER DEFAULT 0, ignored INTEGER DEFAULT 0,
                      fail_count INTEGER DEFAULT 0, success_count INTEGER DEFAULT 0,
                      state_changes_today INTEGER DEFAULT 0, first_seen INTEGER DEFAULT 0,
                      updated_at INTEGER DEFAULT 0, source TEXT DEFAULT 'ping',
                      notes TEXT DEFAULT '', tags_json TEXT DEFAULT '[]'
                    );
                    CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
                    INSERT INTO devices(ip,name,status) VALUES('192.168.1.25','Legacy device','online');
                    """
                )
                legacy.commit()
            finally:
                legacy.close()
            try:
                main.BASE_DIR, main.DB_PATH = base, target
                main.init_db()
                upgraded = main.db()
                try:
                    columns = {
                        row[1] for row in upgraded.execute("PRAGMA table_info(devices)").fetchall()
                    }
                    indexes = {
                        row[1] for row in upgraded.execute("PRAGMA index_list(devices)").fetchall()
                    }
                    device = upgraded.execute(
                        "SELECT name,quarantined,assigned_network FROM devices WHERE ip='192.168.1.25'"
                    ).fetchone()
                    self.assertIn("quarantined", columns)
                    self.assertIn("assigned_network", columns)
                    self.assertIn("idx_devices_operational", indexes)
                    self.assertEqual(device["name"], "Legacy device")
                    self.assertEqual(device["quarantined"], 0)
                finally:
                    upgraded.close()
                backups = list((base / "backups").glob("homeii-pre-schema-10-*.db"))
                self.assertEqual(len(backups), 1)
            finally:
                main.BASE_DIR, main.DB_PATH = original_base, original_db


if __name__ == "__main__":
    unittest.main()
