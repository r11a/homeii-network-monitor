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
                backups = list((base / "backups").glob("homeii-pre-schema-9-*.db"))
                self.assertEqual(len(backups), 1)
            finally:
                main.BASE_DIR, main.DB_PATH = original_base, original_db


if __name__ == "__main__":
    unittest.main()
