import os
import re

import joblib

from utils.preprocessing import clean_text
from utils.scam_categories import SCAM_CATEGORIES


# Thresholds for converting the spam probability into a public classification.
SAFE_PROBABILITY_LIMIT = 0.35
SUSPICIOUS_PROBABILITY_LIMIT = 0.65


MODEL_DIRECTORY = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "models",
)
MODEL_PATH = os.path.join(MODEL_DIRECTORY, "spam_model.pkl")


def load_spam_model():
    """Load the trained model once, and raise a clear internal error if missing."""
    if not os.path.isfile(MODEL_PATH):
        raise FileNotFoundError(
            "Spam model file is missing. Run python make_dataset.py and "
            "python train_model.py to create models/spam_model.pkl."
        )

    loaded_model = joblib.load(MODEL_PATH)
    if not isinstance(loaded_model, dict):
        raise ValueError("The spam model file has an unexpected format.")
    if "vectorizer" not in loaded_model or "classifier" not in loaded_model:
        raise ValueError("The spam model file must contain a vectorizer and classifier.")
    return loaded_model


# Loading here keeps the model in memory for every later message analysis.
SPAM_MODEL = load_spam_model()
VECTORIZER = SPAM_MODEL["vectorizer"]
CLASSIFIER = SPAM_MODEL["classifier"]


def find_actual_match(text, pattern):
    """Return the exact text matched by a regular expression, preserving display text."""
    match = re.search(pattern, text, flags=re.IGNORECASE)
    if match:
        return match.group(0).strip()
    return None


def detect_language(text):
    """Detect Hindi script or common Hindi words written with Latin letters."""
    text = str(text)
    letters = [character for character in text if character.isalpha()]
    if letters:
        devanagari_letters = sum(
            character.isalpha() and "\u0900" <= character <= "\u097f"
            for character in letters
        )
        if devanagari_letters / len(letters) > 0.30:
            return "hi"

    latin_words = re.findall(r"[a-z]+", text.lower())
    common_hindi_words = {
        "abhi",
        "aap",
        "aapka",
        "aapke",
        "aapki",
        "hai",
        "hain",
        "band",
        "bhejo",
        "bhejein",
        "inaam",
        "inam",
        "jeeta",
        "ka",
        "karein",
        "ki",
        "ko",
        "ke",
        "khata",
        "kripya",
        "mein",
        "nahi",
        "nahin",
        "paise",
        "turant",
    }
    if len(set(latin_words).intersection(common_hindi_words)) >= 2:
        return "hinglish"
    return "en"


RULE_DESCRIPTIONS = {
    "urgency": {
        "en": "Urgent language",
        "hi": "जल्द कार्रवाई का दबाव",
    },
    "account_warning": {
        "en": "Account or KYC warning",
        "hi": "खाते या KYC से जुड़ी चेतावनी",
    },
    "reward": {
        "en": "Prize or lottery claim",
        "hi": "इनाम या लॉटरी का दावा",
    },
    "secret_details": {
        "en": "Sensitive verification information",
        "hi": "संवेदनशील सत्यापन जानकारी",
    },
    "click": {
        "en": "Request to open a link or take action",
        "hi": "लिंक खोलने या कार्रवाई करने का अनुरोध",
    },
    "call": {
        "en": "Request to contact someone",
        "hi": "किसी से संपर्क करने का अनुरोध",
    },
    "link": {
        "en": "Website link",
        "hi": "वेबसाइट लिंक",
    },
    "shortened_link": {
        "en": "Shortened link",
        "hi": "छोटा किया गया लिंक",
    },
    "fake_job": {
        "en": "Job or recruitment offer",
        "hi": "नौकरी या भर्ती का प्रस्ताव",
    },
    "delivery": {
        "en": "Delivery or parcel message",
        "hi": "डिलीवरी या पार्सल का संदेश",
    },
    "promotional": {
        "en": "Promotional offer",
        "hi": "प्रचार या ऑफर",
    },
    "payment_request": {
        "en": "Payment or refund request",
        "hi": "भुगतान या रिफंड का अनुरोध",
    },
    "electricity_threat": {
        "en": "Electricity disconnection warning",
        "hi": "बिजली काटने की चेतावनी",
    },
}

RULE_EXPLANATIONS_HI = {
    "urgency": "संदेश में जल्द कार्रवाई का दबाव है:",
    "account_warning": "खाते या KYC से जुड़ी चेतावनी है:",
    "reward": "इनाम या लॉटरी का दावा है:",
    "secret_details": "संवेदनशील सत्यापन जानकारी माँगी गई है:",
    "click": "लिंक खोलने या कार्रवाई करने को कहा गया है:",
    "call": "किसी से संपर्क करने को कहा गया है:",
    "link": "संदेश में वेबसाइट लिंक है:",
    "shortened_link": "संदेश में छोटा किया गया लिंक है:",
    "fake_job": "नौकरी या भर्ती का प्रस्ताव है:",
    "delivery": "डिलीवरी या पार्सल से जुड़ा संदेश है:",
    "promotional": "प्रचार या ऑफर का संदेश है:",
    "payment_request": "भुगतान या रिफंड की कार्रवाई माँगी गई है:",
    "electricity_threat": "बिजली काटने की चेतावनी है:",
}


def get_rule_checks(text, lang="en"):
    """Run supplementary keyword and regex checks; these do not control ML confidence."""
    original_text = str(text)
    lower_text = original_text.lower()
    suspicious_keywords = []
    explanations = []
    supplementary_checks = []

    rule_groups = [
        (
            "urgency",
            (
                r"\b(urgent|immediately|right now|act now|last chance|within "
                r"\d+ (?:minute|hour)s?|abhi|turant|jaldi|aaj hi|der na karein|"
                r"last mauka)\b|अभी|तुरंत|तुरन्त|जल्दी|अंतिम मौका|देरी न करें|वरना"
            ),
            "Urgency language is present:",
        ),
        (
            "account_warning",
            (
                r"\b(kyc|account blocked|account suspended|account will be "
                r"(?:blocked|closed|suspended)|verify (?:your )?(?:account|kyc)|"
                r"update kyc|khata band|khata bandh|khata block|khata rok|"
                r"account band|account block|khata chalu|khata verify)\b"
                r"|खाता बंद|खाता ब्लॉक|खाता रोक|खाते का सत्यापन|खाता सत्यापित|"
                r"बैंक खाता|केवाईसी"
            ),
            "An account or KYC warning is present:",
        ),
        (
            "reward",
            (
                r"\b(prize|lottery|winner|won|reward|lucky draw|cashback|gift|"
                r"inaam|inam|jeeta|jeet gaye|puraskar|inaam paane)\b"
                r"|इनाम|ईनाम|जीता|जीत गए|पुरस्कार|लॉटरी|लकी ड्रॉ|उपहार"
            ),
            "A reward or lottery claim is present:",
        ),
        (
            "secret_details",
            (
                r"\b(otp|upi pin|pin|password|card details|card number|bank "
                r"details|aadhar|aadhaar|otp batao|otp bhejo|otp bhejein|"
                r"pin batao|code bhejo)\b|ओटीपी|एक बार का पासवर्ड|यूपीआई पिन|"
                r"पिन|पासवर्ड|कार्ड विवरण|बैंक विवरण|आधार"
            ),
            "The message requests sensitive verification information:",
        ),
        (
            "click",
            (
                r"\b(click|tap|open|visit|link par click karein|link par click "
                r"karo|link kholo|link kholein|link par jao|website par jao)\b"
                r"|लिंक पर क्लिक करें|लिंक खोलें|यहाँ क्लिक करें|यहां क्लिक करें|"
                r"वेबसाइट पर जाएं"
            ),
            "The message asks the reader to take an action:",
        ),
        (
            "call",
            (
                r"\b(call|phone|dial|contact|sampark karein|call karein)\b"
                r"|संपर्क करें|फोन करें|कॉल करें"
            ),
            "The message asks the reader to call or contact someone:",
        ),
        (
            "link",
            r"(https?://|www\.)\S+",
            "A full or website link is present:",
        ),
        (
            "shortened_link",
            r"\b(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|cutt\.ly)/[a-z0-9_-]+\b",
            "A shortened link is present:",
        ),
        (
            "fake_job",
            (
                r"\b(job|hiring|recruit(?:ment)?|work from home|salary|vacancy|"
                r"employment|career|placement|naukri|ghar baithe(?: kaam)?|"
                r"registration fee|joining fee)\b|नौकरी|भर्ती|घर बैठे काम|वेतन|"
                r"पंजीकरण शुल्क|नियुक्ति"
            ),
            "A job or recruitment offer is present:",
        ),
        (
            "delivery",
            (
                r"\b(parcel|delivery|shipment|courier|package|tracking|"
                r"consignment|redelivery|address issue)\b|पार्सल|डिलीवरी|कूरियर|"
                r"पता अधूरा|पता गलत|दोबारा डिलीवरी"
            ),
            "A delivery or parcel message is present:",
        ),
        (
            "promotional",
            (
                r"\b(discount|deal|coupon|clearance sale|special offer|cashback|"
                r"promotion(?:al)?|free recharge|muft|chhoot|offer)\b"
                r"|मुफ्त|छूट|विशेष ऑफर|कैशबैक|रिचार्ज|वाउचर"
            ),
            "A promotional offer is present:",
        ),
        (
            "payment_request",
            (
                r"\b(pay|payment|refund|fee|processing charge|deposit|money|"
                r"paise bhejo|paisa bhejo|paise jama|shulk|bhugtan|upi refund|"
                r"request approve|amount bhejo)\b|भुगतान|रिफंड|शुल्क|पैसे भेजें|"
                r"पैसे भेजो|पैसा जमा|यूपीआई रिफंड|राशि भेजें"
            ),
            "The message requests a payment or refund action:",
        ),
        (
            "electricity_threat",
            (
                r"\b(electricity|bijli|connection|bill pending|connection cut)\b"
                r"|बिजली|कनेक्शन काट|बिजली काट|बिल बकाया"
            ),
            "An electricity disconnection warning is present:",
        ),
    ]

    for rule_name, pattern, sentence_prefix in rule_groups:
        actual_match = find_actual_match(original_text, pattern)
        if actual_match:
            suspicious_keywords.append(actual_match)
            prefix = (
                RULE_EXPLANATIONS_HI[rule_name]
                if lang == "hi"
                else sentence_prefix
            )
            explanations.append(prefix + ' "' + actual_match + '"')
            supplementary_checks.append(rule_name)

    # A URL written without a protocol is still worth checking.
    bare_link_match = re.search(
        r"\b[\w.-]+\.(com|in|net|org|xyz)\b(?:/[^\s]*)?",
        lower_text,
        flags=re.IGNORECASE,
    )
    if bare_link_match and "link" not in supplementary_checks:
        actual_match = bare_link_match.group(0).strip()
        suspicious_keywords.append(actual_match)
        prefix = (
            RULE_EXPLANATIONS_HI["link"]
            if lang == "hi"
            else "A website-style link is present:"
        )
        explanations.append(prefix + ' "' + actual_match + '"')
        supplementary_checks.append("link")

    unique_keywords = []
    for keyword in suspicious_keywords:
        if keyword.lower() not in [item.lower() for item in unique_keywords]:
            unique_keywords.append(keyword)

    return unique_keywords, explanations, supplementary_checks


def classify_message_categories(text, supplementary_checks):
    """Map detected message patterns to the dashboard's fixed scam categories."""
    lower_text = str(text).lower()
    checks = set(supplementary_checks)
    matches = {
        "banking": bool(
            re.search(
                r"\b(bank(?:ing)?|account|kyc|aadhar|aadhaar|upi|debit|credit card|khata)\b|बैंक|खाता|केवाईसी|यूपीआई",
                lower_text,
            )
        ),
        "lottery": "reward" in checks,
        "otp": bool(
            re.search(
                r"\b(?:otp|one[- ]time password|verification code|pin)\b|ओटीपी|पिन|कोड",
                lower_text,
            )
        ),
        "phishing": bool(checks.intersection({"link", "shortened_link"})),
        "fake_job": "fake_job" in checks,
        "delivery": "delivery" in checks,
        "promotional": "promotional" in checks,
    }
    return [category for category in SCAM_CATEGORIES if matches[category]]


def analyze_message(text, lang="en"):
    """Analyze one message using ML probability and clearly separate rule checks."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Message text must not be empty.")
    lang = lang if lang in ("en", "hi") else "en"

    cleaned_text = clean_text(text)
    text_features = VECTORIZER.transform([cleaned_text])
    probability_by_class = dict(
        zip(CLASSIFIER.classes_, CLASSIFIER.predict_proba(text_features)[0])
    )
    spam_probability = float(probability_by_class.get("spam", 0.0))

    if spam_probability < SAFE_PROBABILITY_LIMIT:
        ml_prediction = "SAFE"
    elif spam_probability <= SUSPICIOUS_PROBABILITY_LIMIT:
        ml_prediction = "SUSPICIOUS"
    else:
        ml_prediction = "SPAM"

    suspicious_keywords, _, supplementary_checks = get_rule_checks(text, "en")
    categories = classify_message_categories(text, supplementary_checks)
    detected_language = detect_language(text)

    # Supplementary rules can upgrade the final result, but never replace ML classification.
    classification = ml_prediction
    rule_upgrade_applied = False
    high_risk_checks = {
        "urgency",
        "account_warning",
        "reward",
        "secret_details",
        "shortened_link",
    }
    triggered_high_risk_count = sum(
        1 for check_name in supplementary_checks if check_name in high_risk_checks
    )

    if classification == "SAFE" and triggered_high_risk_count >= 2:
        classification = "SUSPICIOUS"
        rule_upgrade_applied = True
    elif classification == "SUSPICIOUS" and triggered_high_risk_count >= 4:
        classification = "SPAM"
        rule_upgrade_applied = True

    explanations = {}
    for language in ("en", "hi"):
        _, language_explanations, _ = get_rule_checks(text, language)
        if rule_upgrade_applied:
            language_explanations.append(
                "This final result was raised by several supplementary rule checks, "
                "not by the ML model alone."
                if language == "en"
                else "कई अतिरिक्त नियम जाँचों के कारण अंतिम परिणाम बदला गया है; "
                "यह केवल ML मॉडल का परिणाम नहीं है।"
            )
        if not language_explanations:
            language_explanations.append(
                "No strong spam warning patterns were found in the message."
                if language == "en"
                else "संदेश में स्पैम के कोई स्पष्ट चेतावनी संकेत नहीं मिले।"
            )
        explanations[language] = language_explanations

    if classification == "SPAM":
        risk_level = "High"
        recommended_actions = {
            "en": "Do not share personal details or money; verify the request through an official known channel.",
            "hi": "निजी जानकारी या पैसे साझा न करें; अनुरोध की पुष्टि किसी आधिकारिक और ज्ञात माध्यम से करें।",
        }
    elif classification == "SUSPICIOUS":
        risk_level = "Medium"
        recommended_actions = {
            "en": "Treat the message cautiously and verify its request using an official known channel.",
            "hi": "संदेश के साथ सावधानी बरतें और अनुरोध की पुष्टि आधिकारिक व ज्ञात माध्यम से करें।",
        }
    else:
        risk_level = "Low"
        recommended_actions = {
            "en": "No strong warning was found, but continue to verify unusual requests independently.",
            "hi": "कोई स्पष्ट चेतावनी नहीं मिली, फिर भी अनोखे अनुरोधों की अलग से पुष्टि करें।",
        }

    keyword_descriptions = {
        language: [
            RULE_DESCRIPTIONS[check_name][language]
            for check_name in supplementary_checks
        ]
        for language in ("en", "hi")
    }
    localizations = {
        language: {
            "explanation": explanations[language],
            "keyword_descriptions": keyword_descriptions[language],
            "recommended_action": recommended_actions[language],
        }
        for language in ("en", "hi")
    }

    return {
        "classification": classification,
        "language": detected_language,
        "confidence": round(spam_probability * 100, 2),
        "risk_level": risk_level,
        "ml_prediction": ml_prediction,
        "explanation": localizations[lang]["explanation"],
        "suspicious_keywords": suspicious_keywords,
        "categories": categories,
        "supplementary_checks": supplementary_checks,
        "keyword_descriptions": localizations[lang]["keyword_descriptions"],
        "recommended_action": localizations[lang]["recommended_action"],
        "localizations": localizations,
    }