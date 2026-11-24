import os
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

if not os.getenv("MONGODB_URI"):
    os.environ["MONGODB_URI"] = "mongodb://localhost:27017/spamshield-test"

from utils import database
from utils.database import _assemble_dashboard_stats


class DashboardStatsTests(unittest.TestCase):
    def test_database_initialization_requires_mongodb(self):
        with patch.object(database, "mongo_database", None):
            with self.assertRaises(database.DatabaseError):
                database.init_db()

    def test_dashboard_aggregates_are_range_and_user_scoped(self):
        today = datetime.now(timezone.utc).date()
        current_start = today - timedelta(days=6)
        seven_days_ago = today - timedelta(days=7)
        current_rows = [
            {"scan_type": "message", "prediction": "SAFE", "count": 1},
            {"scan_type": "message", "prediction": "SUSPICIOUS", "count": 1},
            {"scan_type": "url", "prediction": "SUSPICIOUS", "count": 1},
        ]
        previous_rows = [
            {"scan_type": "message", "prediction": "SPAM", "count": 1},
        ]
        recent_scans = [
            {"id": str(index), "scan_type": "message"}
            for index in range(4)
        ]

        stats = _assemble_dashboard_stats(
            "7d",
            current_rows,
            previous_rows,
            [
                {
                    "day": today.isoformat(),
                    "scan_type": "message",
                    "count": 2,
                },
                {
                    "day": today.isoformat(),
                    "scan_type": "url",
                    "count": 1,
                },
            ],
            [{"source": "SMS", "count": 2}, {"source": "manual", "count": 1}],
            [{"category": "phishing", "count": 2}],
            [{"keyword": "verify", "count": 2}],
            recent_scans,
            4,
            current_start,
            today,
        )

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

        all_time = _assemble_dashboard_stats(
            "all",
            current_rows + previous_rows,
            [],
            [
                {
                    "day": today.isoformat(),
                    "scan_type": "message",
                    "count": 2,
                },
                {
                    "day": today.isoformat(),
                    "scan_type": "url",
                    "count": 1,
                },
                {
                    "day": seven_days_ago.isoformat(),
                    "scan_type": "message",
                    "count": 1,
                },
            ],
            [],
            [],
            [],
            recent_scans,
            4,
            None,
            today,
        )
        self.assertEqual(all_time["total_scans"], 4)
        self.assertIsNone(all_time["changes"]["messages"]["percent"])
        self.assertEqual(len(all_time["scans_per_day"]), 8)

    def test_empty_dashboard_aggregation(self):
        today = datetime.now(timezone.utc).date()
        stats = _assemble_dashboard_stats(
            "7d",
            [],
            [],
            [],
            [],
            [],
            [],
            [],
            0,
            today - timedelta(days=6),
            today,
        )
        self.assertEqual(stats["total_scans"], 0)
        self.assertEqual(stats["scans_per_day"][0]["total"], 0)
        self.assertEqual(stats["changes"]["messages"], {"percent": 0, "previous": 0})


if __name__ == "__main__":
    unittest.main()
