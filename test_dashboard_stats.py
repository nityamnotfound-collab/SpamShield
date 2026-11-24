import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from utils import database


class DashboardStatsTests(unittest.TestCase):
    def setUp(self):
        self.temp_directory = tempfile.TemporaryDirectory()
        self.original_database_path = database.DATABASE_PATH
        self.original_database_directory = database.DATABASE_DIRECTORY
        self.original_use_mongodb = database.USE_MONGODB
        database.USE_MONGODB = False
        database.DATABASE_DIRECTORY = self.temp_directory.name
        database.DATABASE_PATH = os.path.join(self.temp_directory.name, "stats.sqlite")
        database.init_db()
        self.user_id = database.create_user("Stats User", "stats@example.com", "hash")
        self.other_user_id = database.create_user(
            "Other User", "other@example.com", "hash"
        )
        self.today = datetime.now(timezone.utc).date()

    def tearDown(self):
        database.DATABASE_PATH = self.original_database_path
        database.DATABASE_DIRECTORY = self.original_database_directory
        database.USE_MONGODB = self.original_use_mongodb
        self.temp_directory.cleanup()

    def add_scan(
        self,
        user_id,
        scan_type,
        prediction,
        source,
        days_ago,
        categories=None,
        keywords=None,
        language="en",
    ):
        scan_id = database.save_scan(
            user_id,
            scan_type,
            "test " + scan_type + " content",
            source,
            prediction,
            25,
            ["test explanation"],
            keywords or [],
            categories=categories or [],
            keywords=keywords or [],
            language=language,
        )
        created_at = datetime.combine(
            self.today - timedelta(days=days_ago),
            datetime.min.time(),
        ).strftime("%Y-%m-%d %H:%M:%S")
        connection = sqlite3.connect(database.DATABASE_PATH)
        try:
            connection.execute(
                "UPDATE scans SET created_at = ? WHERE id = ?",
                (created_at, scan_id),
            )
            connection.commit()
        finally:
            connection.close()
        return scan_id

    def test_dashboard_aggregates_are_range_and_user_scoped(self):
        self.add_scan(
            self.user_id,
            "message",
            "SAFE",
            "SMS",
            0,
            ["banking", "phishing"],
            ["KYC", "Verify"],
        )
        self.add_scan(
            self.user_id,
            "message",
            "SUSPICIOUS",
            "WhatsApp",
            2,
            ["otp"],
            ["verify", "OTP"],
        )
        self.add_scan(
            self.user_id,
            "url",
            "SUSPICIOUS",
            "manual",
            0,
            ["phishing"],
            ["login"],
        )
        self.add_scan(
            self.user_id,
            "message",
            "SPAM",
            "Email",
            7,
            ["lottery"],
            ["prize"],
        )
        self.add_scan(
            self.other_user_id,
            "message",
            "SPAM",
            "Email",
            0,
            ["promotional"],
            ["discount"],
        )

        stats = database.get_dashboard_stats(self.user_id, "7d")
        self.assertEqual(stats["messages"], 2)
        self.assertEqual(stats["safe"], 1)
        self.assertEqual(stats["suspicious"], 1)
        self.assertEqual(stats["spam"], 0)
        self.assertEqual(stats["urls"], 1)
        self.assertEqual(stats["total_scans"], 3)
        self.assertEqual(stats["lifetime_total"], 4)
        self.assertEqual(stats["url_risk_counts"]["SUSPICIOUS"], 1)
        self.assertEqual(len(stats["scans_per_day"]), 7)
        self.assertEqual(sum(day["total"] for day in stats["scans_per_day"]), 3)
        self.assertEqual(
            stats["changes"]["messages"],
            {"percent": 100.0, "previous": 1},
        )
        self.assertIsNone(stats["changes"]["safe"]["percent"])
        self.assertEqual(
            {item["category"]: item["count"] for item in stats["categories"]}[
                "phishing"
            ],
            2,
        )
        self.assertEqual(stats["top_keywords"][0], {"keyword": "verify", "count": 2})
        self.assertEqual(len(stats["recent_scans"]), 4)
        self.assertTrue(all("user_id" not in scan for scan in stats["recent_scans"]))

        all_time = database.get_dashboard_stats(self.user_id, "all")
        self.assertEqual(all_time["total_scans"], 4)
        self.assertIsNone(all_time["changes"]["messages"]["percent"])
        self.assertEqual(len(all_time["scans_per_day"]), 8)

        recent_id = stats["recent_scans"][0]["id"]
        self.assertTrue(database.delete_scan(self.user_id, recent_id))
        self.assertEqual(database.get_dashboard_stats(self.user_id, "7d")["total_scans"], 2)

    def test_scan_language_is_persisted_in_history_and_dashboard(self):
        scan_id = self.add_scan(
            self.user_id,
            "message",
            "SAFE",
            "WhatsApp",
            0,
            language="hi",
        )

        history = database.get_history(self.user_id)
        details = database.get_scan_by_id(self.user_id, scan_id)
        stats = database.get_dashboard_stats(self.user_id, "all")

        self.assertEqual(history[0]["language"], "hi")
        self.assertEqual(details["language"], "hi")
        self.assertEqual(stats["recent_scans"][0]["language"], "hi")


if __name__ == "__main__":
    unittest.main()
