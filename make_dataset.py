import csv
import os
import random

import pandas as pd


RANDOM_SEED = 42
DATASET_SIZE = 600
ADDITIONAL_MESSAGES_PER_LANGUAGE = 150
BASE_DIRECTORY = os.path.dirname(os.path.abspath(__file__))
DATASET_DIRECTORY = os.path.join(BASE_DIRECTORY, "dataset")
DATASET_PATH = os.path.join(DATASET_DIRECTORY, "spam_dataset.csv")


def random_combination(generator, items):
    return items[generator.randrange(len(items))]


LOCALIZED_TEMPLATES = {
    "hinglish": {
        "ham": [
            ("legitimate", "Maa, main ghar pahunch gaya hu. Ab chinta mat karo."),
            ("legitimate", "Aaj shaam ko baat karenge, tum dawa le lena."),
            ("legitimate", "Bhai, photo bhej di hai. Time mile to dekh lena."),
            ("legitimate", "Kal office ki meeting 4 baje hai, reminder bhej raha hu."),
            ("legitimate", "Happy birthday! Shaam ko milte hain aur cake saath kaatenge."),
            ("legitimate", "SBI alert: Rs. {amount} aapke account se debit hue. Details app me dekhein."),
            ("legitimate", "Aapke {bank} account me Rs. {amount} credit hue hain."),
            ("legitimate", "Aapki UPI payment Rs. {amount} ki successful hui. OTP kisi ko na batayein."),
            ("legitimate", "Aapka {brand} parcel aaj delivery ke liye nikal gaya hai."),
            ("legitimate", "Order {amount} pickup point par aa gaya hai, jab convenient ho le lena."),
            ("legitimate", "Courier kal aayega; delivery status official order page par dekhein."),
            ("legitimate", "Aapka refund original payment method me bhej diya gaya hai."),
            ("legitimate", "Aaj bijli ka bill due hai, official app se pay kar dena."),
            ("legitimate", "OTP {amount} aaya hai, ise kisi ke saath share mat karna."),
            ("legitimate", "Parcel mil gaya, packing achchi thi. Thanks!"),
            ("legitimate", "Bank kabhi OTP ya UPI PIN nahi maangta; app ke andar hi check karein."),
            ("legitimate", "Ghar pahunch kar message kar dena, dinner saath karenge."),
            ("legitimate", "Aapka order dispatch ho gaya hai; tracking app me update hogi."),
            ("legitimate", "UPI transfer fail hua, paise account me hi hain. Bank app check karo."),
            ("legitimate", "Aapka KYC branch me complete ho gaya, koi link open karne ki zarurat nahi."),
        ],
        "spam": [
            ("banking_fraud", "Aapka bank khata band ho jayega, KYC turant update karein: {link}"),
            ("banking_fraud", "Aapka {bank} khata block ho gaya hai. Abhi link par click karein: {link}"),
            ("banking_fraud", "KYC abhi complete karo warna account aaj band hoga: {link}"),
            ("banking_fraud", "Khata chalu karne ke liye OTP aur UPI PIN bhejein."),
            ("banking_fraud", "Bank account verify karne ke liye card details aur PIN abhi bhejo."),
            ("banking_fraud", "Aapka khata band hone wala hai, kripya turant is link par login karein: {link}"),
            ("otp_scam", "Refund paane ke liye OTP batao, paise turant account me aayenge."),
            ("otp_scam", "Aapka OTP expire ho raha hai, verification ke liye code abhi bhejein."),
            ("otp_scam", "Inaam bhejne ke liye OTP aur UPI PIN share karein."),
            ("otp_scam", "UPI refund ke liye request approve karo aur apna PIN daalo."),
            ("lottery_scam", "Aapne lottery me Rs. {amount} jeeta! Inaam paane ke liye fee jama karein."),
            ("lottery_scam", "Badhai ho, aapka inaam nikal gaya! Claim ke liye abhi {link} kholein."),
            ("lottery_scam", "Aap lucky draw me jeete hain, inaam transfer ke liye processing charge bhejein."),
            ("fake_job", "Ghar baithe job, roz Rs. {amount} kamao. Registration fee pehle bhejein."),
            ("fake_job", "{company} me naukri pakki, joining ke liye refundable fee jama karein."),
            ("fake_job", "Online form filling job chahiye? Aaj hi paise bhejo aur kaam shuru karo."),
            ("delivery_scam", "Aapka parcel ruk gaya hai, redelivery ke liye chhota charge pay karein: {link}"),
            ("delivery_scam", "Address galat hai, parcel release karne ko card number aur OTP bhejo."),
            ("delivery_scam", "Courier delivery fail hui. Fee turant jama karein warna order cancel hoga."),
            ("electricity_scam", "Bijli connection aaj kat jayega, bill abhi is link par pay karo: {link}"),
            ("electricity_scam", "Aapka bijli bill pending hai, connection band hone se pehle payment karein."),
            ("promotional_spam", "Free recharge aur cashback paane ke liye link par click karein: {link}"),
            ("promotional_spam", "Sirf aaj, {brand} par bada discount. Offer claim karne ko register karo."),
            ("promotional_spam", "Guaranteed daily return ke liye Rs. {amount} invest karo, abhi join karein."),
            ("promotional_spam", "Mubarak ho! Free voucher mila hai, claim karne ke liye {link} par jao."),
            ("promotional_spam", "Loan turant approve, bas apna bank account aur PIN share karo."),
            ("banking_fraud", "Khata block hone se bachane ke liye KYC link abhi kholo: {link}"),
            ("lottery_scam", "Aapne inaam jeeta hai! Prize lene ke liye pehle tax aur fee jama karein."),
            ("fake_job", "Part-time job me Rs. {amount} roz, seat reserve karne ke paise bhejo."),
            ("delivery_scam", "Parcel ka address verify karne ke liye login aur UPI PIN daalein: {link}"),
        ],
    },
    "hi": {
        "ham": [
            ("legitimate", "माँ, मैं घर पहुँच गया हूँ। अब चिंता मत करना।"),
            ("legitimate", "आज शाम बात करेंगे, आप दवा समय पर ले लेना।"),
            ("legitimate", "भैया, तस्वीर भेज दी है। समय मिले तो देख लेना।"),
            ("legitimate", "कल कार्यालय की बैठक चार बजे है, याद दिला रहा हूँ।"),
            ("legitimate", "जन्मदिन की बहुत शुभकामनाएँ, शाम को मिलते हैं।"),
            ("legitimate", "{bank} बैंक सूचना: आपके खाते से ₹{amount} डेबिट हुए हैं।"),
            ("legitimate", "आपके {bank} खाते में ₹{amount} जमा हुए हैं।"),
            ("legitimate", "आपका यूपीआई भुगतान सफल हुआ। ओटीपी किसी को न बताएं।"),
            ("legitimate", "आपका {brand} पार्सल आज डिलीवरी के लिए निकल चुका है।"),
            ("legitimate", "आपका ऑर्डर नज़दीकी केंद्र पर पहुँच गया है, सुविधा से ले लें।"),
            ("legitimate", "कूरियर कल आएगा; ऑर्डर की स्थिति आधिकारिक ऐप में देखें।"),
            ("legitimate", "आपका रिफंड मूल भुगतान खाते में भेज दिया गया है।"),
            ("legitimate", "बिजली बिल शुक्रवार तक जमा करना है, आधिकारिक ऐप में भुगतान करें।"),
            ("legitimate", "आपका ओटीपी आया है, इसे किसी के साथ साझा न करें।"),
            ("legitimate", "पार्सल मिल गया, पैकिंग अच्छी थी। धन्यवाद!"),
            ("legitimate", "बैंक कभी ओटीपी या यूपीआई पिन नहीं माँगता; ऐप में ही जाँचें।"),
            ("legitimate", "घर पहुँचकर संदेश कर देना, रात का खाना साथ खाएँगे।"),
            ("legitimate", "आपका ऑर्डर भेज दिया गया है; ट्रैकिंग ऐप में अपडेट होगी।"),
            ("legitimate", "यूपीआई भुगतान असफल हुआ, पैसे खाते में ही हैं। बैंक ऐप देखें।"),
            ("legitimate", "आपका केवाईसी शाखा में पूरा हो गया है; किसी लिंक की ज़रूरत नहीं।"),
        ],
        "spam": [
            ("banking_fraud", "आपका बैंक खाता आज बंद हो जाएगा, अभी केवाईसी करें: {link}"),
            ("banking_fraud", "आपका {bank} खाता ब्लॉक है। तुरंत इस लिंक पर क्लिक करें: {link}"),
            ("banking_fraud", "केवाईसी अधूरी है, आपका खाता रोक दिया जाएगा। अभी अपडेट करें।"),
            ("banking_fraud", "खाता चालू करने के लिए ओटीपी और यूपीआई पिन भेजें।"),
            ("banking_fraud", "बैंक खाता सत्यापित करने के लिए कार्ड नंबर और पिन अभी भेजें।"),
            ("banking_fraud", "खाता बंद होने से पहले कृपया इस लिंक पर लॉगिन करें: {link}"),
            ("otp_scam", "रिफंड पाने के लिए ओटीपी बताएं, पैसे तुरंत खाते में आएँगे।"),
            ("otp_scam", "आपका ओटीपी समाप्त हो रहा है, कोड अभी भेजकर सत्यापन करें।"),
            ("otp_scam", "इनाम भेजने के लिए ओटीपी और यूपीआई पिन साझा करें।"),
            ("otp_scam", "यूपीआई रिफंड के लिए अनुरोध स्वीकार करें और अपना पिन डालें।"),
            ("lottery_scam", "आपने ₹{amount} की लॉटरी जीती! इनाम पाने के लिए शुल्क जमा करें।"),
            ("lottery_scam", "बधाई हो, आपका इनाम निकला है! दावा करने के लिए {link} खोलें।"),
            ("lottery_scam", "आप लकी ड्रॉ में जीते हैं, इनाम के लिए प्रोसेसिंग शुल्क भेजें।"),
            ("fake_job", "घर बैठे नौकरी, रोज़ ₹{amount} कमाएँ। पंजीकरण शुल्क पहले जमा करें।"),
            ("fake_job", "{company} में नौकरी पक्की, नियुक्ति के लिए वापस होने वाला शुल्क भेजें।"),
            ("fake_job", "ऑनलाइन फॉर्म भरने का काम चाहिए? आज ही पैसे भेजकर काम शुरू करें।"),
            ("delivery_scam", "आपका पार्सल रुका है, दोबारा डिलीवरी के लिए शुल्क दें: {link}"),
            ("delivery_scam", "पता गलत है, पार्सल पाने के लिए कार्ड नंबर और ओटीपी भेजें।"),
            ("delivery_scam", "कूरियर नहीं पहुँच पाया। तुरंत शुल्क दें वरना ऑर्डर रद्द होगा।"),
            ("electricity_scam", "बिजली आज काट दी जाएगी, बिल अभी इस लिंक पर जमा करें: {link}"),
            ("electricity_scam", "आपका बिजली बिल बकाया है, कनेक्शन बंद होने से पहले भुगतान करें।"),
            ("promotional_spam", "मुफ्त रिचार्ज और कैशबैक के लिए लिंक पर क्लिक करें: {link}"),
            ("promotional_spam", "आज ही {brand} पर भारी छूट, ऑफर पाने के लिए अभी पंजीकरण करें।"),
            ("promotional_spam", "गारंटीशुदा मुनाफे के लिए ₹{amount} निवेश करें, अभी जुड़ें।"),
            ("promotional_spam", "आपको मुफ्त वाउचर मिला है, पाने के लिए {link} पर जाएँ।"),
            ("promotional_spam", "तुरंत मंजूर ऋण, बस अपना बैंक खाता और पिन साझा करें।"),
            ("banking_fraud", "खाता ब्लॉक होने से बचाने के लिए केवाईसी लिंक अभी खोलें: {link}"),
            ("lottery_scam", "आपने इनाम जीता है! पुरस्कार लेने से पहले कर और शुल्क जमा करें।"),
            ("fake_job", "अंशकालिक नौकरी में रोज़ ₹{amount}, जगह पक्की करने के पैसे भेजें।"),
            ("delivery_scam", "पार्सल का पता देखने के लिए लॉगिन और यूपीआई पिन डालें: {link}"),
        ],
    },
}


def append_localized_messages(rows, language, templates, count, generator, values):
    """Append balanced safe and scam samples for one language."""
    for label, message_count in (
        ("ham", count // 2),
        ("spam", count - count // 2),
    ):
        for _ in range(message_count):
            category, template = random_combination(generator, templates[label])
            rows.append(
                {
                    "text": template.format(**values(generator)),
                    "label": label,
                    "category": category,
                    "language": language,
                }
            )


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
        rows.append(
            {"text": message, "label": "ham", "category": category, "language": "en"}
        )

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
        rows.append(
            {"text": message, "label": "spam", "category": category, "language": "en"}
        )

    def localized_values(generator, names):
        return {
            "name": random_combination(generator, names),
            "amount": random_combination(generator, amounts),
            "bank": random_combination(generator, banks),
            "brand": random_combination(generator, brands),
            "link": random_combination(generator, links),
            "company": random_combination(generator, companies),
        }

    for language, names in (
        ("hinglish", ["Amit", "Priya", "Rahul", "Sneha", "Vikram", "Neha"]),
        ("hi", ["अमित", "प्रिया", "राहुल", "स्नेहा", "विक्रम", "नेहा"]),
    ):
        append_localized_messages(
            rows,
            language,
            LOCALIZED_TEMPLATES[language],
            ADDITIONAL_MESSAGES_PER_LANGUAGE,
            random_generator,
            lambda generator, names=names: localized_values(generator, names),
        )

    random_generator.shuffle(rows)
    dataset = pd.DataFrame(rows, columns=["text", "label", "category", "language"])
    os.makedirs(DATASET_DIRECTORY, exist_ok=True)
    dataset.to_csv(DATASET_PATH, index=False, quoting=csv.QUOTE_MINIMAL)
    print("Created", DATASET_PATH, "with", len(dataset), "messages")


if __name__ == "__main__":
    build_dataset()
