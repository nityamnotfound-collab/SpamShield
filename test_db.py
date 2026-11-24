import os

from utils import database


def print_check(name, passed):
    """Print a consistent result for one database verification check."""
    status = "PASS" if passed else "FAIL"
    print("{}: {}".format(status, name))


def main():
    database.init_db()
    email = os.getenv("TEST_USER_EMAIL", "").strip().lower()
    user = database.get_user_by_email(email) if email else None
    if user is None:
        print("Set TEST_USER_EMAIL to an existing account before running this diagnostic.")
        return
    user_id = user["id"]

    if database.USE_MONGODB:
        print("Database in use: MongoDB")
    else:
        print("Database in use: SQLite")

    message_scan_id = None
    fetched_scan = None

    try:
        try:
            database.init_db()
            print_check("init_db", True)
        except Exception:
            print_check("init_db", False)

        try:
            message_scan_id = database.save_scan(
                user_id,
                "message",
                "Please review the meeting notes when you have time.",
                "test_db.py",
                "SAFE",
                5.0,
                ["No warning patterns in this test message."],
                [],
            )
            print_check("save message scan", True)
        except Exception:
            print_check("save message scan", False)

        try:
            database.save_scan(
                user_id,
                "url",
                "http://example.test/verify",
                "test_db.py",
                "SUSPICIOUS",
                42.0,
                ["Test URL has a suspicious pattern."],
                ["verify"],
            )
            print_check("save URL scan", True)
        except Exception:
            print_check("save URL scan", False)

        try:
            history = database.get_history(user_id)
            print("get_history():", history)
            print_check("get_history", isinstance(history, list))
        except Exception:
            print_check("get_history", False)

        try:
            stats = database.get_dashboard_stats(user_id)
            print("get_dashboard_stats():", stats)
            print_check("get_dashboard_stats", isinstance(stats, dict))
        except Exception:
            print_check("get_dashboard_stats", False)

        if message_scan_id is not None:
            try:
                fetched_scan = database.get_scan_by_id(user_id, message_scan_id)
                print_check("get_scan_by_id for saved scan", fetched_scan is not None)
            except Exception:
                print_check("get_scan_by_id for saved scan", False)
        else:
            print_check("get_scan_by_id for saved scan", False)

        if fetched_scan is not None:
            try:
                deleted = database.delete_scan(user_id, fetched_scan["id"])
                print_check("delete_scan", deleted)
            except Exception:
                print_check("delete_scan", False)
        else:
            print_check("delete_scan", False)

        try:
            invalid_scan = database.get_scan_by_id(user_id, "abc")
            print("get_scan_by_id('abc'):", invalid_scan)
            print_check("invalid ID does not crash", True)
        except Exception:
            print_check("invalid ID does not crash", False)

        try:
            final_stats = database.get_dashboard_stats(user_id)
            print("get_dashboard_stats() after deletion:", final_stats)
            print_check("get_dashboard_stats after deletion", isinstance(final_stats, dict))
        except Exception:
            print_check("get_dashboard_stats after deletion", False)
    finally:
        # Only the explicitly selected test account is cleared.
        try:
            database.clear_history(user_id)
            print_check("clear_history", True)
        except Exception:
            print_check("clear_history", False)


if __name__ == "__main__":
    main()
