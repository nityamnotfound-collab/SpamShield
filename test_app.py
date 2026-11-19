"""Exercise SpamShield API routes with Flask's test client and isolated storage."""

from datetime import datetime

import app as spamshield


TEST_SCANS = {}
NEXT_SCAN_ID = 1


def fake_save_scan(scan_type, content, source, prediction, score, explanation, flags):
    """Save a scan in memory so tests never write to the configured database."""
    global NEXT_SCAN_ID
    scan_id = "test-scan-{}".format(NEXT_SCAN_ID)
    NEXT_SCAN_ID += 1
    TEST_SCANS[scan_id] = {
        "id": scan_id,
        "scan_type": scan_type,
        "content": content,
        "source": source,
        "prediction": prediction,
        "score": score,
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "explanation": explanation,
        "flags": flags,
    }
    return scan_id


def fake_get_history(search=None, scan_type=None, prediction=None):
    """Return in-memory scans using the filters accepted by the real function."""
    records = list(TEST_SCANS.values())
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


def fake_get_scan_by_id(scan_id):
    """Look up a test scan by its string ID."""
    return TEST_SCANS.get(str(scan_id))


def fake_delete_scan(scan_id):
    """Delete one in-memory scan."""
    return TEST_SCANS.pop(str(scan_id), None) is not None


def fake_clear_history():
    """Clear only the isolated in-memory test records."""
    TEST_SCANS.clear()


def fake_get_dashboard_stats():
    """Build the dashboard response from the in-memory test records."""
    records = list(TEST_SCANS.values())
    safe_count = sum(1 for record in records if record["prediction"] == "SAFE")
    spam_count = sum(1 for record in records if record["prediction"] == "SPAM")
    return {
        "total_scans": len(records),
        "messages": sum(1 for record in records if record["scan_type"] == "message"),
        "safe": safe_count,
        "spam": spam_count,
        "suspicious": sum(
            1 for record in records if record["prediction"] == "SUSPICIOUS"
        ),
        "urls": sum(1 for record in records if record["scan_type"] == "url"),
        "spam_vs_safe": [
            {"prediction": "SAFE", "count": safe_count},
            {"prediction": "SPAM", "count": spam_count},
        ],
        "last_five": [
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
                )
            }
            for record in reversed(records[-5:])
        ],
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
    }
    spamshield.save_scan = fake_save_scan
    spamshield.get_history = fake_get_history
    spamshield.get_scan_by_id = fake_get_scan_by_id
    spamshield.delete_scan = fake_delete_scan
    spamshield.clear_history = fake_clear_history
    spamshield.get_dashboard_stats = fake_get_dashboard_stats
    spamshield.app.config["TESTING"] = True

    checks_passed = 0
    checks_total = 13

    try:
        fake_clear_history()
        with spamshield.app.test_client() as client:

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
                require(
                    response.get_json()["classification"]
                    in ("SUSPICIOUS", "HIGH RISK"),
                    "Expected the IP-based login URL to be flagged.",
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

            check_functions = [
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
            ]

            for check_name, check_function in check_functions:
                if run_check(check_name, check_function):
                    checks_passed += 1
    finally:
        fake_clear_history()
        for function_name, original_function in original_functions.items():
            setattr(spamshield, function_name, original_function)

    print("Passed {}/{} checks.".format(checks_passed, checks_total))
    return checks_passed == checks_total


if __name__ == "__main__":
    raise SystemExit(0 if main() else 1)
