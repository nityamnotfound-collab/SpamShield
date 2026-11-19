"""Populate SpamShield with locally analyzed example scans."""

import argparse

from utils.database import clear_history, init_db, save_scan
from utils.message_detector import analyze_message
from utils.url_detector import analyze_url


DEMO_MESSAGES = [
    (
        "Hey Riya, I will be at the cafe near the station around 6. See you there!",
        "WhatsApp",
    ),
    (
        "Hi team, the project review is moved to 3 PM tomorrow. Please bring the latest slides.",
        "Email",
    ),
    (
        "Mum, I reached home safely. I will call you after dinner.",
        "WhatsApp",
    ),
    (
        "SBI Alert: Rs. 1,250.00 was debited from your account ending 4821 "
        "on 19-Nov. If you did not make this transaction, contact the bank "
        "using the number on your card. Never share your PIN or OTP.",
        "SMS",
    ),
    (
        "Weekend offer! Get 70% off on selected styles and free delivery. "
        "Shop today at the store you already know.",
        "SMS",
    ),
    (
        "Congratulations, your mobile number has won Rs. 25 lakh in the "
        "international lucky draw. Pay a small processing fee now to claim "
        "your prize.",
        "WhatsApp",
    ),
    (
        "Your bank KYC is incomplete and your account will be blocked today. "
        "Verify your account immediately at http://sbi-kyc-check.example.com "
        "to keep access.",
        "SMS",
    ),
    (
        "Your parcel is waiting. Send the OTP you just received to our agent "
        "so we can release the delivery.",
        "SMS",
    ),
    (
        "Work from home! Earn Rs. 8,000 daily with no experience. Pay a "
        "registration fee today and message your Aadhaar and bank details "
        "to reserve the job.",
        "WhatsApp",
    ),
    (
        "Delivery update: your package could not be delivered because the "
        "address was incomplete. Pay Rs. 25 now at "
        "http://parcel-redelivery.example.net to reschedule.",
        "SMS",
    ),
]


DEMO_URLS = [
    "https://www.irctc.co.in/",
    "https://www.wikipedia.org/",
    "http://bit.ly/parcel-update",
    "http://192.0.2.10/login",
    "http://login.verify.bank-alert.example.com/signin",
]


def seed_demo_data(clear_first=False):
    """Analyze and save the fixed demo examples without visiting any URLs."""
    init_db()

    if clear_first:
        clear_history()

    saved_count = 0

    for message, source in DEMO_MESSAGES:
        result = analyze_message(message)
        save_scan(
            "message",
            message,
            source,
            result["classification"].upper(),
            result["confidence"],
            result["explanation"],
            result["suspicious_keywords"],
        )
        saved_count += 1

    for url in DEMO_URLS:
        result = analyze_url(url)
        save_scan(
            "url",
            url,
            "manual",
            result["classification"].upper(),
            result["risk_score"],
            result["reasons"],
            result["reasons"],
        )
        saved_count += 1

    return saved_count


def main():
    argument_parser = argparse.ArgumentParser(
        description="Analyze and save example messages and URLs for SpamShield."
    )
    argument_parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all existing scan history before adding the demo scans.",
    )
    arguments = argument_parser.parse_args()

    saved_count = seed_demo_data(clear_first=arguments.clear)
    print("Saved {} demo scans.".format(saved_count))


if __name__ == "__main__":
    main()
