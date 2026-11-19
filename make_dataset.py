import csv
import os
import random

import pandas as pd


RANDOM_SEED = 42
DATASET_SIZE = 600
BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DATASET_DIRECTORY = os.path.join(BASE_DIRECTORY, "dataset")
DATASET_PATH = os.path.join(DATASET_DIRECTORY, "spam_dataset.csv")


def random_combination(generator, items):
    return items[generator.randrange(len(items))]


def build_dataset():
    random_generator = random.Random(RANDOM_SEED)
    names = ["Amit", "Priya", "Rahul", "Sneha", "Vikram", "Neha", "Rohan", "Kavya"]
    amounts = ["499", "1,250", "2,999", "5,000", "12,499", "25,000"]
    banks = ["SBI", "HDFC", "ICICI", "Axis", "Bank of Baroda"]
    brands = ["Paytm", "Amazon", "Flipkart", "Myntra", "Jio", "FedEx"]
    links = ["bit.ly/freegift", "claim-prize.in", "secure-update.net", "kfcashback.xyz"]
    companies = ["TCS", "Infosys", "Wipro", "Accenture", "Reliance"]
    rows = []

    ham_count = DATASET_SIZE // 2
    spam_count = DATASET_SIZE - ham_count

    ham_templates = [
        ("legitimate", "{name}, are you free for dinner tonight?"),
        ("legitimate", "Please send the project file when you reach office."),
        ("legitimate", "Mom: {name}, call me after reaching home."),
        ("legitimate", "Happy birthday! Hope you have a wonderful day."),
        ("legitimate", "Team meeting is moved to 4 PM tomorrow."),
        ("legitimate", "Rs. {amount} debited from {bank} account ending 1234. Balance is available."),
        ("legitimate", "Rs. {amount} credited to your {bank} account. Reference 985621."),
        ("legitimate", "Your {bank} debit card was used at a store. Not you? Call the number on the card."),
        ("legitimate", "{brand} delivery update: package out for delivery today."),
        ("legitimate", "{brand} order 4582 has arrived and is ready for pickup."),
        ("legitimate", "OTP 482916 received. Do not share this OTP with anyone."),
        ("legitimate", "Your UPI payment of Rs. {amount} was successful."),
        ("legitimate", "KYC documents can be submitted at your branch during working hours."),
        ("legitimate", "Reminder: electricity bill payment is due on Friday."),
        ("legitimate", "The package arrived safely. Thank you for your order."),
        ("legitimate", "{bank} verification: enter the UPI PIN shown in your app only."),
        ("legitimate", "Security update: your account is safe. Do not reply or send your OTP."),
        ("legitimate", "FedEx tracking: the courier attempted delivery; please collect from the local office."),
        ("legitimate", "Amazon received your return request. Refund will reach the original account."),
        ("legitimate", "{brand} offer details are available inside the official app."),
        ("legitimate", "You received a prize confirmation by email, but no fees are requested."),
        ("legitimate", "A purchase of Rs. {amount} needs OTP approval. Do not share it."),
        ("legitimate", "Your SBI account verification is complete after branch KYC."),
        ("legitimate", "Please update the delivery address from the official Paytm order page."),
        ("legitimate", "Bank alert: login failure detected. We have not asked you to send card details."),
        ("legitimate", "Dear customer, never share OTP or UPI PIN. Bank support will not ask for these."),
        ("legitimate", "We cancelled the suspicious payment request. Check the official {bank} app."),
        ("legitimate", "Your genuine order from {brand} can be tracked only inside the order page."),
        ("legitimate", "The FedEx delivery agent called, but no payment link was sent."),
        ("legitimate", "A prize message arrived by SMS, but we ignored it. No prize fee needed."),
        ("legitimate", "The company HR asked for the interview details, with no joining fee."),
        ("legitimate", "UPI declined: the receiver has not received Rs. {amount}. No OTP was required."),
        ("legitimate", "Your {bank} card is still active. Verify only through the official app."),
        ("legitimate", "This is an official alert. Do not click unknown links or disclose account data."),
    ]

    spam_templates = {
        "banking_fraud": [
            "Your {bank} account is blocked. Verify KYC immediately at {link}",
            "Rs. {amount} refund pending. Share card details and UPI PIN at {link}",
            "Suspicious transaction found. Click {link} to secure your {bank} account",
            "Dear customer, your account will be frozen. Update account details at {link}",
            "Paytm wallet blocked. Enter OTP and password to reactivate",
            "Official bank notice: we will never ask for OTP, but verify now for security",
            "Your genuine {bank} account needs no card details. Update KYC with PIN now",
            "Account-safe reminder: login at {link}, then enter UPI PIN",
            "Bank customer care text: do not share OTP. Send OTP here to unlock",
        ],
        "lottery_scam": [
            "Congratulations {name}! You won Rs. {amount}. Claim prize now at {link}",
            "{brand} lucky draw: selected winner! Pay registration fee to receive Rs. {amount}",
            "Lottery result approved. Send account number to collect your prize",
            "You have won 25 lakh rupees. Call now and share your Aadhaar",
            "Prize notification: send bank details to transfer Rs. {amount}",
            "Lottery winner message: legitimate prize; pay only by UPI to receive cash",
            "This is a real draw result. No bank PIN needed, but share Aadhaar to claim",
            "Congratulations, this prize is genuine. Processing fee can be paid safely",
        ],
        "phishing": [
            "Security alert: confirm password and Aadhaar at {link}",
            "Paytm account suspended. Login immediately through {link}",
            "HDFC customer verification required. Enter card PIN on {link}",
            "Update Paytm KYC in 2 hours or account will close: {link}",
            "{brand} account locked. Verify credentials at {link}",
            "Official security reminder: suspicious link detected. Open {link} to secure account",
            "Bank alert style message: no need to call, enter password at {link}",
        ],
        "fake_job": [
            "Work from home for {company}. Earn Rs. {amount} daily. Pay joining fee",
            "Hiring 100 candidates for online form filling. Send Rs. 500 registration",
            "Immediate job offer: approve offer and deposit refundable amount",
            "{company} vacancy open. WhatsApp resume and processing fee",
            "Earn Rs. 20,000 weekly from Amazon work. Investment required",
        ],
        "delivery_scam": [
            "{brand} parcel is on hold. Pay Rs. 40 redelivery fee at {link}",
            "FedEx shipment fee pending. Update address and pay Rs. {amount}",
            "Courier cannot deliver. Confirm PIN and card details at {link}",
            "Customs charge Rs. {amount} for your Flipkart package",
            "Amazon order address issue. Pay small fee to avoid cancellation",
        ],
        "otp_scam": [
            "We need the OTP you just received to complete verification. Do not share? Share it now",
            "OTP expires in 1 minute. Send 6 digit code to confirm {brand} cashback",
            "Send received OTP and UPI PIN for account refund",
            "Caller asking for OTP: verify it with us immediately",
            "Forward OTP to receive Rs. {amount} reward",
            "Do not share OTP with anyone. Reply with OTP now for cashback",
            "Customer safety notice: OTP is private. Send it to verify the refund",
        ],
        "promotional_spam": [
            "Flash sale: buy now and get 90 percent discount at {link}",
            "Limited period free recharge. Register now for Rs. {amount}",
            "Exclusive loan approved instantly. Apply here and share details",
            "Invest Rs. {amount} today for guaranteed daily returns",
            "Get free {brand} voucher by forwarding this message",
        ],
    }

    while len([row for row in rows if row["label"] == "ham"]) < ham_count:
        category, template = random_combination(random_generator, ham_templates)
        message = template.format(
            name=random_combination(random_generator, names),
            amount=random_combination(random_generator, amounts),
            bank=random_combination(random_generator, banks),
            brand=random_combination(random_generator, brands),
        )
        rows.append({"text": message, "label": "ham", "category": category})

    spam_categories = list(spam_templates.keys())
    while len([row for row in rows if row["label"] == "spam"]) < spam_count:
        category = random_combination(random_generator, spam_categories)
        template = random_combination(random_generator, spam_templates[category])
        message = template.format(
            name=random_combination(random_generator, names),
            amount=random_combination(random_generator, amounts),
            bank=random_combination(random_generator, banks),
            brand=random_combination(random_generator, brands),
            link=random_combination(random_generator, links),
            company=random_combination(random_generator, companies),
        )
        rows.append({"text": message, "label": "spam", "category": category})

    random_generator.shuffle(rows)
    dataset = pd.DataFrame(rows, columns=["text", "label", "category"])
    os.makedirs(DATASET_DIRECTORY, exist_ok=True)
    dataset.to_csv(DATASET_PATH, index=False, quoting=csv.QUOTE_MINIMAL)
    print("Created", DATASET_PATH, "with", len(dataset), "messages")


if __name__ == "__main__":
    build_dataset()
