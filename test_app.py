"""Exercise SpamShield API routes with Flask's test client and isolated storage."""

import os
from datetime import datetime, timedelta, timezone

if not os.getenv("MONGODB_URI"):
    os.environ["MONGODB_URI"] = "mongodb://localhost:27017/spamshield-test"
import app as spamshield
from werkzeug.security import generate_password_hash
from utils.scam_categories import SCAM_CATEGORIES


TEST_SCANS = {}
NEXT_SCAN_ID = 1
TEST_USERS = {}
NEXT_USER_ID = 1


def fake_create_user(name, email, password_hash):
    global NEXT_USER_ID
    if email in TEST_USERS:
        raise spamshield.UserAlreadyExistsError("Duplicate account.")
    user_id = "test-user-{}".format(NEXT_USER_ID)
    NEXT_USER_ID += 1
    TEST_USERS[email] = {
        "id": user_id,
        "name": name,
        "email": email,
        "password_hash": password_hash,
        "failed_attempts": 0,
        "locked_until": None,
    }
    return user_id


def fake_get_user_by_email(email):
    return TEST_USERS.get(email)


def fake_get_user_by_id(user_id):
    return next(
        (user for user in TEST_USERS.values() if user["id"] == str(user_id)),
        None,
    )


def fake_record_failed_login(user_id):
    user = fake_get_user_by_id(user_id)
    if user is None:
        return 0
    user["failed_attempts"] += 1
    if user["failed_attempts"] >= 5:
        user["locked_until"] = datetime.now(timezone.utc) + timedelta(minutes=5)
    return user["failed_attempts"]


def fake_reset_failed_logins(user_id):
    user = fake_get_user_by_id(user_id)
    if user:
        user["failed_attempts"] = 0
        user["locked_until"] = None


def fake_save_scan(
    user_id,
    scan_type,
    content,
    source,
    prediction,
    score,
    explanation,
    flags,
    categories=None,
    keywords=None,
    language="en",
):
    """Save a scan in memory so tests never write to the configured database."""
    global NEXT_SCAN_ID
    scan_id = "test-scan-{}".format(NEXT_SCAN_ID)
    NEXT_SCAN_ID += 1
    TEST_SCANS[scan_id] = {
        "id": scan_id,
        "user_id": str(user_id),
        "scan_type": scan_type,
        "content": content,
        "source": source,
        "prediction": prediction,
        "score": score,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "explanation": explanation,
        "flags": flags,
        "categories": categories or [],
        "keywords": keywords or [],
        "language": language,
    }
    return scan_id


def fake_get_history(user_id, search=None, scan_type=None, prediction=None):
    """Return in-memory scans using the filters accepted by the real function."""
    records = [
        record for record in TEST_SCANS.values()
        if record["user_id"] == str(user_id)
    ]
    if search:
        search_lower = search.lower()
        records = [
            record
            for record in records
            if search_lower in record["content"].lower()
            or search_lower in record["source"].lower()
        ]
    if scan_type:
        records = [record for record in records if record["scan_type"] == scan_type]
    if prediction:
        records = [
            record
            for record in records
            if record["prediction"] == prediction.upper()
        ]
    return list(reversed(records[-200:]))


def fake_get_scan_by_id(user_id, scan_id):
    """Look up a test scan by its string ID."""
    record = TEST_SCANS.get(str(scan_id))
    return record if record and record["user_id"] == str(user_id) else None


def fake_delete_scan(user_id, scan_id):
    """Delete one in-memory scan."""
    record = fake_get_scan_by_id(user_id, scan_id)
    if record:
        del TEST_SCANS[str(scan_id)]
    return record is not None


def fake_clear_history(user_id):
    """Clear only one user's isolated in-memory test records."""
    for scan_id, record in list(TEST_SCANS.items()):
        if record["user_id"] == str(user_id):
            del TEST_SCANS[scan_id]


def fake_get_dashboard_stats(user_id, range_name="7d"):
    """Build the dashboard response from the in-memory test records."""
    all_records = [
        record for record in TEST_SCANS.values()
        if record["user_id"] == str(user_id)
    ]
    today = datetime.now().date()
    days = {"7d": 7, "30d": 30}.get(range_name)
    current_start = today - timedelta(days=days - 1) if days else None
    previous_start = today - timedelta(days=(days * 2) - 1) if days else None
    previous_end = current_start

    def scan_day(record):
        return datetime.strptime(record["created_at"], "%Y-%m-%d %H:%M:%S").date()

    records = [
        record for record in all_records
        if current_start is None or scan_day(record) >= current_start
    ]
    previous_records = [
        record for record in all_records
        if previous_start is not None
        and previous_start <= scan_day(record) < previous_end
    ]
    messages = [record for record in records if record["scan_type"] == "message"]
    urls = [record for record in records if record["scan_type"] == "url"]
    previous_messages = [
        record for record in previous_records if record["scan_type"] == "message"
    ]
    previous_urls = [
        record for record in previous_records if record["scan_type"] == "url"
    ]
    message_counts = {
        prediction: sum(1 for record in messages if record["prediction"] == prediction)
        for prediction in ("SAFE", "SUSPICIOUS", "SPAM")
    }

    def percentage(current, previous):
        if range_name == "all" or previous == 0:
            return None if current else 0
        return round((current - previous) * 100 / previous, 1)

    changes = {}
    for key, current_count, previous_count in (
        ("messages", len(messages), len(previous_messages)),
        ("safe", message_counts["SAFE"], sum(
            1 for record in previous_messages if record["prediction"] == "SAFE"
        )),
        ("suspicious", message_counts["SUSPICIOUS"], sum(
            1 for record in previous_messages if record["prediction"] == "SUSPICIOUS"
        )),
        ("spam", message_counts["SPAM"], sum(
            1 for record in previous_messages if record["prediction"] == "SPAM"
        )),
        ("urls", len(urls), len(previous_urls)),
    ):
        changes[key] = {
            "percent": percentage(current_count, previous_count),
            "previous": previous_count,
        }

    grouped_days = {}
    for record in records:
        day = scan_day(record).isoformat()
        counts = grouped_days.setdefault(day, {"messages": 0, "urls": 0})
        counts["messages" if record["scan_type"] == "message" else "urls"] += 1
    first_day = (
        current_start if current_start is not None
        else min((scan_day(record) for record in records), default=None)
    )
    scans_per_day = []
    if first_day:
        day = first_day
        while day <= today:
            counts = grouped_days.get(day.isoformat(), {"messages": 0, "urls": 0})
            scans_per_day.append({
                "date": day.isoformat(),
                "messages": counts["messages"],
                "urls": counts["urls"],
                "total": counts["messages"] + counts["urls"],
            })
            day += timedelta(days=1)

    categories = {
        category: sum(
            1 for record in records if category in record["categories"]
        )
        for category in SCAM_CATEGORIES
    }
    keyword_counts = {}
    for record in records:
        for keyword in record["keywords"]:
            key = keyword.lower()
            keyword_counts[key] = keyword_counts.get(key, 0) + 1

    recent_records = sorted(
        all_records,
        key=lambda record: (scan_day(record), record["id"]),
        reverse=True,
    )[:8]
    return {
        "total_scans": len(records),
        "lifetime_total": len(all_records),
        "range": range_name,
        "messages": len(messages),
        "safe": message_counts["SAFE"],
        "spam": message_counts["SPAM"],
        "suspicious": message_counts["SUSPICIOUS"],
        "urls": len(urls),
        "url_risk_counts": {
            prediction: sum(
                1 for record in urls if record["prediction"] == prediction
            )
            for prediction in ("SAFE", "SUSPICIOUS", "SPAM", "HIGH RISK")
        },
        "scans_per_day": scans_per_day,
        "sources": [
            {"source": source, "count": sum(
                1 for record in records if record["source"] == source
            )}
            for source in sorted({record["source"] for record in records})
        ],
        "categories": [
            {"category": category, "count": count}
            for category, count in categories.items()
        ],
        "top_keywords": [
            {"keyword": keyword, "count": count}
            for keyword, count in sorted(
                keyword_counts.items(), key=lambda item: (-item[1], item[0])
            )[:8]
        ],
        "recent_scans": [
            {
                key: record[key]
                for key in (
                    "id",
                    "scan_type",
                    "content",
                    "source",
                    "prediction",
                    "score",
                    "created_at",
                    "explanation",
                    "flags",
                    "categories",
                    "keywords",
                )
            }
            for record in recent_records
        ],
        "changes": changes,
    }


def require(condition, message):
    """Raise a readable assertion failure when a test condition is false."""
    if not condition:
        raise AssertionError(message)


def run_check(name, check_function):
    """Run one test and print its PASS or FAIL result."""
    try:
        check_function()
    except Exception as error:
        print("FAIL: {} ({})".format(name, error))
        return False
    print("PASS: {}".format(name))
    return True


def main():
    """Run the API checks using a temporary in-memory database substitute."""
    original_functions = {
        "save_scan": spamshield.save_scan,
        "get_history": spamshield.get_history,
        "get_scan_by_id": spamshield.get_scan_by_id,
        "delete_scan": spamshield.delete_scan,
        "clear_history": spamshield.clear_history,
        "get_dashboard_stats": spamshield.get_dashboard_stats,
        "create_user": spamshield.create_user,
        "get_user_by_email": spamshield.get_user_by_email,
        "get_user_by_id": spamshield.get_user_by_id,
        "record_failed_login": spamshield.record_failed_login,
        "reset_failed_logins": spamshield.reset_failed_logins,
    }
    spamshield.save_scan = fake_save_scan
    spamshield.get_history = fake_get_history
    spamshield.get_scan_by_id = fake_get_scan_by_id
    spamshield.delete_scan = fake_delete_scan
    spamshield.clear_history = fake_clear_history
    spamshield.get_dashboard_stats = fake_get_dashboard_stats
    spamshield.create_user = fake_create_user
    spamshield.get_user_by_email = fake_get_user_by_email
    spamshield.get_user_by_id = fake_get_user_by_id
    spamshield.record_failed_login = fake_record_failed_login
    spamshield.reset_failed_logins = fake_reset_failed_logins
    spamshield.app.config["TESTING"] = True
    spamshield.app.config["SECRET_KEY"] = "test-secret"

    checks_passed = 0
    checks_total = 0

    try:
        TEST_SCANS.clear()
        TEST_USERS.clear()
        global NEXT_SCAN_ID, NEXT_USER_ID
        NEXT_SCAN_ID = 1
        NEXT_USER_ID = 1
        with spamshield.app.test_client() as client:

            def check_weak_password_rejected():
                response = client.post(
                    "/register",
                    json={
                        "name": "Test User",
                        "email": "test@example.com",
                        "password": "password",
                    },
                )
                require(response.status_code == 400, "Expected HTTP 400.")
                require(
                    response.get_json()["password_strength"] == "Weak",
                    "Expected the password strength rating to be Weak.",
                )
                require(not TEST_USERS, "A weak password created an account.")
                mismatch = client.post(
                    "/register",
                    json={
                        "name": "Test User",
                        "email": "test@example.com",
                        "password": "SafePass9!",
                        "confirm_password": "DifferentPass9!",
                    },
                )
                require(
                    mismatch.status_code == 400
                    and "Passwords do not match" in mismatch.get_json()["error"],
                    "Mismatched confirmation passwords were accepted.",
                )

            def check_registration_and_duplicate_email():
                for bad_email in (
                    "not-an-email",
                    "bad..dots@example.com",
                    "bad@example..com",
                    "x@y",
                ):
                    invalid = client.post(
                        "/register",
                        json={
                            "name": "Test User",
                            "email": bad_email,
                            "password": "StrongPass9!",
                            "confirm_password": "StrongPass9!",
                        },
                    )
                    require(
                        invalid.status_code == 400
                        and "valid email" in invalid.get_json()["error"],
                        "Invalid email was accepted: {}".format(bad_email),
                    )

                response = client.post(
                    "/register",
                    json={
                        "name": "Test User",
                        "email": "test@example.com",
                        "password": "StrongPass9!",
                        "confirm_password": "StrongPass9!",
                        "remember_me": True,
                    },
                )
                require(response.status_code == 201, "Expected HTTP 201.")
                require(
                    response.get_json()["password_strength"] == "Good",
                    "Expected the valid strong password to be accepted.",
                )
                require(
                    client.get("/api/me").status_code == 401,
                    "Registration should not log in the new account.",
                )
                duplicate = client.post(
                    "/register",
                    json={
                        "name": "Other User",
                        "email": "TEST@example.com",
                        "password": "AnotherPass9!",
                        "confirm_password": "AnotherPass9!",
                    },
                )
                require(duplicate.status_code == 400, "Expected duplicate email rejection.")
                require(
                    "already exists" in duplicate.get_json()["error"],
                    "Expected a clear duplicate email message.",
                )
                form_response = client.post(
                    "/register",
                    data={
                        "name": "Form User",
                        "email": "form@example.com",
                        "password": "StrongPass9!",
                        "confirm_password": "StrongPass9!",
                    },
                )
                require(
                    form_response.status_code == 302
                    and form_response.location.endswith("/login"),
                    "Successful form registration should redirect to login.",
                )

            def check_account_lockout():
                with client.session_transaction() as session_data:
                    session_data.clear()
                for _ in range(5):
                    response = client.post(
                        "/login",
                        json={"email": "test@example.com", "password": "wrong"},
                    )
                    require(response.status_code == 400, "Expected generic login error.")
                    require(
                        response.get_json()["error"] == "Incorrect email or password",
                        "Expected a generic login error.",
                    )
                user = TEST_USERS["test@example.com"]
                require(
                    user["failed_attempts"] == 5 and user["locked_until"] is not None,
                    "Five failed attempts did not lock the account.",
                )
                locked = client.post(
                    "/login",
                    json={"email": "test@example.com", "password": "StrongPass9!"},
                )
                require(
                    locked.get_json()["error"] == "Incorrect email or password",
                    "A locked account accepted a valid password.",
                )

            def check_login_resets_failures():
                fake_reset_failed_logins(TEST_USERS["test@example.com"]["id"])
                response = client.post(
                    "/login",
                    json={
                        "email": "test@example.com",
                        "password": "StrongPass9!",
                        "remember_me": True,
                    },
                )
                require(response.status_code == 200, "Expected successful login.")
                require(
                    TEST_USERS["test@example.com"]["failed_attempts"] == 0,
                    "Successful login did not reset failed attempts.",
                )
                with client.session_transaction() as session_data:
                    require(
                        session_data.permanent,
                        "Remember me did not create a permanent session.",
                    )
                current_user = client.get("/api/me").get_json()
                require(
                    current_user["email"] == "test@example.com"
                    and "password_hash" not in current_user,
                    "The current-user API returned unexpected account data.",
                )
                require(
                    client.get("/login").location.endswith("/dashboard")
                    and client.get("/register").location.endswith("/dashboard"),
                    "Logged-in users should be redirected from auth pages.",
                )

            def check_protected_routes_require_login():
                with client.session_transaction() as session_data:
                    session_data.clear()
                pages = [
                    client.get("/dashboard"),
                    client.get("/message-scanner"),
                    client.get("/url-scanner"),
                    client.get("/urlscanner"),
                    client.get("/history"),
                ]
                api_responses = [
                    client.get("/api/me"),
                    client.get("/api/history"),
                    client.get("/api/history/test-scan-1"),
                    client.get("/api/report/test-scan-1"),
                    client.get("/api/dashboard"),
                    client.get("/api/dashboard-stats"),
                    client.post("/api/analyze/message", json={"message": "test"}),
                    client.post("/api/analyze-message", json={"message": "test"}),
                    client.post("/api/analyze/url", json={"url": "https://example.com"}),
                    client.post("/api/analyze-url", json={"url": "https://example.com"}),
                    client.delete("/api/history"),
                    client.delete("/api/history/test-scan-1"),
                ]
                require(
                    all(
                        page.status_code == 302
                        and page.location.endswith("/login")
                        for page in pages
                    ),
                    "Expected all protected pages to redirect to login.",
                )
                require(
                    all(
                        response.status_code == 401
                        and response.get_json()
                        == {"error": "Authentication required."}
                        for response in api_responses
                    ),
                    "Expected protected APIs to return a JSON 401.",
                )
                with client.session_transaction() as session_data:
                    session_data["user_id"] = "test-user-1"
                    session_data["user_name"] = "Test User"

            def check_public_pages():
                with client.session_transaction() as session_data:
                    session_data.clear()
                for path in ("/", "/about", "/login", "/register", "/scam-awareness"):
                    response = client.get(path)
                    require(
                        response.status_code == 200,
                        "{} should be public.".format(path),
                    )
                with client.session_transaction() as session_data:
                    session_data["user_id"] = "test-user-1"
                    session_data["user_name"] = "Test User"
                awareness_page = client.get("/scam-awareness")
                dashboard_page = client.get("/dashboard")
                require(
                    b"scam_awareness.js" in awareness_page.data
                    and b'href="/scam-awareness"' in dashboard_page.data,
                    "The awareness guide should load publicly and link from the app sidebar.",
                )

            def check_scan_ownership():
                other_user_id = fake_create_user(
                    "Other User",
                    "other@example.com",
                    generate_password_hash("OtherPass9!"),
                )
                other_scan_id = fake_save_scan(
                    other_user_id,
                    "message",
                    "private other user's scan",
                    "test",
                    "SAFE",
                    1,
                    [],
                    [],
                )
                history = client.get("/api/history").get_json()["history"]
                require(
                    all(scan["id"] != other_scan_id for scan in history),
                    "Another account's scan appeared in history.",
                )
                require(
                    client.get("/api/history/{}".format(other_scan_id)).status_code == 404,
                    "Another account's scan was accessible by ID.",
                )
                require(
                    client.delete("/api/history/{}".format(other_scan_id)).status_code == 404,
                    "Another account's scan could be deleted.",
                )
                client.delete("/api/history")
                require(
                    other_scan_id in TEST_SCANS,
                    "Clearing history removed another account's scan.",
                )
                user_one_scan_id = fake_save_scan(
                    "test-user-1",
                    "message",
                    "private first user's scan",
                    "test",
                    "SAFE",
                    1,
                    [],
                    [],
                )
                with client.session_transaction() as session_data:
                    session_data["user_id"] = other_user_id
                    session_data["user_name"] = "Other User"
                other_history = client.get("/api/history").get_json()["history"]
                require(
                    [scan["id"] for scan in other_history] == [other_scan_id]
                    and client.get(
                        "/api/history/{}".format(user_one_scan_id)
                    ).status_code == 404
                    and client.delete(
                        "/api/history/{}".format(user_one_scan_id)
                    ).status_code == 404,
                    "The second account could access or delete the first account's scan.",
                )
                with client.session_transaction() as session_data:
                    session_data["user_id"] = "test-user-1"
                    session_data["user_name"] = "Test User"
                require(
                    user_one_scan_id in TEST_SCANS
                    and other_scan_id in TEST_SCANS,
                    "A cross-account delete changed another user's scan.",
                )

            def check_personal_message():
                response = client.post(
                    "/api/analyze-message",
                    json={
                        "message": "Hey Maya, are we still meeting for coffee at 6? See you soon!",
                        "source": "WhatsApp",
                    },
                )
                require(response.status_code == 200, "Expected HTTP 200.")
                require(
                    response.get_json()["classification"] == "SAFE",
                    "Expected the personal message to be classified SAFE.",
                )

            def check_promotional_spam():
                response = client.post(
                    "/api/analyze-message",
                    json={
                        "message": (
                            "Weekend sale! Get 80% off on all products. Buy now "
                            "and claim your free gift today!"
                        ),
                        "source": "SMS",
                    },
                )
                require(response.status_code == 200, "Expected HTTP 200.")
                require(
                    response.get_json()["classification"] in ("SPAM", "SUSPICIOUS"),
                    "Expected promotional spam to be flagged.",
                )

            def check_banking_phishing():
                response = client.post(
                    "/api/analyze-message",
                    json={
                        "message": (
                            "Your SBI account will be blocked today due to "
                            "incomplete KYC. Verify your account immediately at "
                            "http://sbi-kyc-check.example.com to avoid suspension."
                        ),
                        "source": "SMS",
                    },
                )
                require(response.status_code == 200, "Expected HTTP 200.")
                require(
                    response.get_json()["classification"] in ("SPAM", "SUSPICIOUS"),
                    "Expected banking phishing to be flagged.",
                )

            def check_lottery_scam():
                response = client.post(
                    "/api/analyze-message",
                    json={
                        "message": (
                            "Congratulations! You have won Rs. 25 lakh in our "
                            "lucky draw. Pay the processing fee now to claim your prize."
                        ),
                        "source": "WhatsApp",
                    },
                )
                require(response.status_code == 200, "Expected HTTP 200.")
                require(
                    response.get_json()["classification"] in ("SPAM", "SUSPICIOUS"),
                    "Expected the lottery message to be flagged.",
                )

            def check_suspicious_url():
                response = client.post(
                    "/api/analyze-url",
                    json={"url": "http://192.0.2.10/login"},
                )
                require(response.status_code == 200, "Expected HTTP 200.")
                result = response.get_json()
                require(
                    result["classification"] in ("SUSPICIOUS", "HIGH RISK"),
                    "Expected the IP-based login URL to be flagged.",
                )
                require(
                    result["language"] == "en"
                    and TEST_SCANS[result["id"]]["language"] == "en",
                    "URL scan language was not saved.",
                )

            def check_empty_inputs():
                empty_message = client.post(
                    "/api/analyze-message",
                    json={"message": "", "source": "SMS"},
                )
                empty_url = client.post("/api/analyze-url", json={"url": ""})
                require(
                    empty_message.status_code == 400,
                    "Expected an empty message to return HTTP 400.",
                )
                require(
                    empty_url.status_code == 400,
                    "Expected an empty URL to return HTTP 400.",
                )
                require(
                    "error" in empty_message.get_json()
                    and "error" in empty_url.get_json(),
                    "Expected validation error responses.",
                )

            def check_malformed_url():
                response = client.post(
                    "/api/analyze-url",
                    json={"url": "http://["},
                )
                require(
                    response.status_code == 400,
                    "Expected malformed URL syntax to return HTTP 400.",
                )
                require(
                    response.get_json() == {"error": "Enter a valid URL to analyze."},
                    "Expected a clean malformed URL validation response.",
                )

            def check_history_filter_validation():
                invalid_type = client.get("/api/history?scan_type=unknown")
                invalid_prediction = client.get(
                    "/api/history?prediction=UNCLASSIFIED"
                )
                require(
                    invalid_type.status_code == 400
                    and invalid_prediction.status_code == 400,
                    "Expected unsupported history filters to return HTTP 400.",
                )
                require(
                    "error" in invalid_type.get_json()
                    and "error" in invalid_prediction.get_json(),
                    "Expected clean history filter validation errors.",
                )

            def check_long_message():
                response = client.post(
                    "/api/analyze-message",
                    json={"message": "a" * 5001, "source": "SMS"},
                )
                require(
                    response.status_code == 400,
                    "Expected a message over 5000 characters to return HTTP 400.",
                )

            saved_scan_id = {"value": None}

            def check_history_and_dashboard_increase():
                before_total = client.get("/api/dashboard-stats").get_json()[
                    "total_scans"
                ]
                response = client.post(
                    "/api/analyze-message",
                    json={
                        "message": "I will call you after work. See you at home.",
                        "source": "SMS",
                    },
                )
                require(response.status_code == 200, "Expected HTTP 200.")
                saved_scan_id["value"] = response.get_json()["id"]
                history = client.get("/api/history").get_json()["history"]
                after_total = client.get("/api/dashboard-stats").get_json()[
                    "total_scans"
                ]
                require(
                    any(scan["id"] == saved_scan_id["value"] for scan in history),
                    "The saved scan was not returned in history.",
                )
                require(
                    after_total == before_total + 1,
                    "The dashboard total did not increase by one.",
                )
                stats = client.get("/api/dashboard-stats?range=7d").get_json()
                require(
                    stats["range"] == "7d"
                    and stats["messages"] >= 1
                    and stats["scans_per_day"][-1]["total"] >= 1
                    and len(stats["categories"]) == len(SCAM_CATEGORIES)
                    and any(
                        scan["id"] == saved_scan_id["value"]
                        for scan in stats["recent_scans"]
                    ),
                    "Dashboard stats omitted current user activity or chart data.",
                )

            def check_delete_and_dashboard_decrease():
                scan_id = saved_scan_id["value"]
                require(scan_id is not None, "No saved scan ID is available.")
                before_total = client.get("/api/dashboard-stats").get_json()[
                    "total_scans"
                ]
                response = client.delete("/api/history/{}".format(scan_id))
                require(response.status_code == 200, "Expected HTTP 200.")
                history = client.get("/api/history").get_json()["history"]
                after_total = client.get("/api/dashboard-stats").get_json()[
                    "total_scans"
                ]
                require(
                    all(scan["id"] != scan_id for scan in history),
                    "The deleted scan still appears in history.",
                )
                require(
                    after_total == before_total - 1,
                    "The dashboard total did not decrease by one.",
                )

            def check_clear_history():
                for message in (
                    "A separate test record for clearing history.",
                    "Another separate record for the clear test.",
                ):
                    response = client.post(
                        "/api/analyze-message",
                        json={"message": message, "source": "SMS"},
                    )
                    require(response.status_code == 200, "Expected HTTP 200.")
                clear_response = client.delete("/api/history")
                require(clear_response.status_code == 200, "Expected HTTP 200.")
                history = client.get("/api/history").get_json()["history"]
                total = client.get("/api/dashboard-stats").get_json()["total_scans"]
                require(not history and total == 0, "Test history was not cleared.")

            def check_invalid_scan_id():
                response = client.get("/api/history/not-a-valid-id")
                require(
                    response.status_code == 404,
                    "Expected an invalid scan ID to return HTTP 404, not crash.",
                )
                require(
                    response.get_json() == {"error": "Scan not found."},
                    "Expected a clean not-found error response.",
                )

            def check_dashboard_range_validation():
                all_time = client.get("/api/dashboard-stats?range=all")
                thirty_days = client.get("/api/dashboard-stats?range=30d")
                invalid = client.get("/api/dashboard-stats?range=90d")
                require(
                    all_time.status_code == 200
                    and all_time.get_json()["range"] == "all",
                    "Expected the all-time dashboard range to be available.",
                )
                require(
                    thirty_days.status_code == 200
                    and thirty_days.get_json()["range"] == "30d"
                    and len(thirty_days.get_json()["scans_per_day"]) == 30,
                    "The 30-day range did not return 30 days of chart data.",
                )
                require(
                    invalid.status_code == 400,
                    "Expected an unsupported dashboard range to return HTTP 400.",
                )

            def check_scam_categories_are_saved():
                examples = (
                    ("Your bank account KYC needs an update.", "banking"),
                    ("You won a prize in our lucky draw.", "lottery"),
                    ("Share your OTP verification code.", "otp"),
                    ("Click this link: https://example.com/verify", "phishing"),
                    ("Work from home job hiring with a daily salary.", "fake_job"),
                    ("Your parcel delivery tracking is delayed.", "delivery"),
                    ("Use this discount coupon for our special offer.", "promotional"),
                )
                for message, category in examples:
                    response = client.post(
                        "/api/analyze-message",
                        json={"message": message, "source": "SMS"},
                    )
                    require(response.status_code == 200, "Expected HTTP 200.")
                    result = response.get_json()
                    require(
                        category in result["categories"],
                        "Expected the {} category.".format(category),
                    )
                    saved_scan = TEST_SCANS[result["id"]]
                    require(
                        category in saved_scan["categories"]
                        and saved_scan["keywords"] == result["suspicious_keywords"],
                        "Detector categories or keywords were not saved with the scan.",
                    )

            def check_language_detection_and_persistence():
                examples = (
                    (
                        "Aapka bank khata band ho jayega, KYC turant update karein: "
                        "https://example.com/kyc",
                        "hinglish",
                        "account_warning",
                    ),
                    (
                        "आपका बैंक खाता आज बंद हो जाएगा, अभी केवाईसी करें।",
                        "hi",
                        "account_warning",
                    ),
                    (
                        "आपने ₹5,000 का इनाम जीता है! रिफंड पाने के लिए ओटीपी और "
                        "यूपीआई पिन भेजें।",
                        "hi",
                        "payment_request",
                    ),
                    (
                        "Aapne lottery me inaam jeeta, paise paane ke liye fee bhejo.",
                        "hinglish",
                        "payment_request",
                    ),
                )
                for message, language, expected_check in examples:
                    response = client.post(
                        "/api/analyze-message",
                        json={"message": message, "source": "SMS"},
                    )
                    require(response.status_code == 200, "Expected HTTP 200.")
                    result = response.get_json()
                    require(
                        result["language"] == language
                        and expected_check in result["supplementary_checks"],
                        "Expected language detection and localized rule checks.",
                    )
                    saved_scan = TEST_SCANS[result["id"]]
                    require(
                        saved_scan["language"] == language,
                        "Detected language was not saved with the scan.",
                    )

            def check_detector_localizations():
                message_response = client.post(
                    "/api/analyze-message",
                    json={
                        "message": "Your bank account is blocked. Update KYC now.",
                        "source": "SMS",
                        "lang": "hi",
                    },
                )
                require(message_response.status_code == 200, "Expected HTTP 200.")
                message_result = message_response.get_json()
                require(
                    message_result["explanation"]
                    == message_result["localizations"]["hi"]["explanation"]
                    and message_result["recommended_action"]
                    == message_result["localizations"]["hi"]["recommended_action"]
                    and any(
                        "\u0900" <= character <= "\u097f"
                        for character in message_result["recommended_action"]
                    ),
                    "Message results did not return Hindi explanations and actions.",
                )
                url_response = client.post(
                    "/api/analyze-url",
                    json={"url": "http://127.0.0.1/verify", "lang": "hi"},
                )
                require(url_response.status_code == 200, "Expected HTTP 200.")
                url_result = url_response.get_json()
                require(
                    url_result["reasons"] == url_result["localizations"]["hi"]["reasons"]
                    and url_result["reasons"]
                    != url_result["localizations"]["en"]["reasons"]
                    and url_result["recommendation"]
                    == url_result["localizations"]["hi"]["recommendation"],
                    "URL results did not return both language variants.",
                )

            def check_localized_message_classifications():
                examples = (
                    (
                        "Aapka bank khata block ho jayega, KYC turant update karein "
                        "aur OTP bhejein.",
                        "Hinglish bank scam",
                    ),
                    (
                        "आपका बैंक खाता आज बंद हो जाएगा, अभी KYC करें और OTP बताएं।",
                        "Hindi bank scam",
                    ),
                )
                for message, label in examples:
                    response = client.post(
                        "/api/analyze-message",
                        json={"message": message, "source": "SMS"},
                    )
                    require(response.status_code == 200, "Expected HTTP 200.")
                    result = response.get_json()
                    require(
                        result["classification"] != "SAFE",
                        "{} was classified SAFE.".format(label),
                    )

                personal = client.post(
                    "/api/analyze-message",
                    json={
                        "message": (
                            "Aap ghar aa gaye? Main aapke liye chai bana raha hoon, "
                            "shaam ko milte hain."
                        ),
                        "source": "WhatsApp",
                    },
                )
                require(personal.status_code == 200, "Expected HTTP 200.")
                require(
                    personal.get_json()["classification"] != "SPAM",
                    "A normal personal Hinglish message was classified SPAM.",
                )

            check_functions = [
                ("Weak registration passwords are rejected", check_weak_password_rejected),
                ("Registration succeeds and duplicate emails are rejected", check_registration_and_duplicate_email),
                ("Five failed logins lock the account", check_account_lockout),
                ("Successful login resets failed attempts", check_login_resets_failures),
                ("Protected pages and APIs require login", check_protected_routes_require_login),
                ("Public pages are available without login", check_public_pages),
                ("Scan records are isolated by user", check_scan_ownership),
                ("Personal message returns SAFE", check_personal_message),
                ("Promotional spam is flagged", check_promotional_spam),
                ("Banking phishing is flagged", check_banking_phishing),
                ("Lottery scam is flagged", check_lottery_scam),
                ("IP-based login URL is flagged", check_suspicious_url),
                ("Empty message and URL return validation errors", check_empty_inputs),
                ("Malformed URL returns a validation error", check_malformed_url),
                (
                    "Unsupported history filters return validation errors",
                    check_history_filter_validation,
                ),
                ("Message over 5000 characters is rejected", check_long_message),
                (
                    "Saved scan appears in history and dashboard total increases",
                    check_history_and_dashboard_increase,
                ),
                (
                    "Deleting a scan removes it and dashboard total decreases",
                    check_delete_and_dashboard_decrease,
                ),
                ("Clearing history leaves zero test records", check_clear_history),
                ("Invalid scan ID returns a clean error", check_invalid_scan_id),
                ("Dashboard ranges and aggregation response are validated", check_dashboard_range_validation),
                ("Detector categories and keywords are saved with scans", check_scam_categories_are_saved),
                (
                    "Message languages and localized rules are detected and saved",
                    check_language_detection_and_persistence,
                ),
                ("Message and URL results include bilingual localized text", check_detector_localizations),
                (
                    "Hinglish and Hindi scams are flagged while personal Hinglish is not spam",
                    check_localized_message_classifications,
                ),
                (
                    "Removed model-performance endpoint returns 404",
                    lambda: require(
                        client.get("/model-performance").status_code == 404,
                        "The removed endpoint should return HTTP 404.",
                    ),
                ),
            ]
            checks_total = len(check_functions)

            for check_name, check_function in check_functions:
                if run_check(check_name, check_function):
                    checks_passed += 1
    finally:
        TEST_SCANS.clear()
        TEST_USERS.clear()
        for function_name, original_function in original_functions.items():
            setattr(spamshield, function_name, original_function)

    print("Passed {}/{} checks.".format(checks_passed, checks_total))
    return checks_passed == checks_total


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
