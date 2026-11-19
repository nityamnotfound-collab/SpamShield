import os
import re

import joblib

from utils.preprocessing import clean_text


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


def get_rule_checks(text):
    """Run supplementary keyword and regex checks; these do not control ML confidence."""
    original_text = str(text)
    lower_text = original_text.lower()
    suspicious_keywords = []
    explanations = []
    supplementary_checks = []

    rule_groups = [
        (
            "urgency",
            r"\b(urgent|immediately|right now|act now|last chance|within \d+ (?:minute|hour)s?)\b",
            "Urgency language is present:",
        ),
        (
            "account_warning",
            r"\b(kyc|account blocked|account suspended|account will be (?:blocked|closed|suspended)|verify (?:your )?(?:account|kyc)|update kyc)\b",
            "An account or KYC warning is present:",
        ),
        (
            "reward",
            r"\b(prize|lottery|winner|won|reward|lucky draw|cashback|gift)\b",
            "A reward or lottery claim is present:",
        ),
        (
            "secret_details",
            r"\b(otp|upi pin|pin|password|card details|card number|bank details|aadhar|aadhaar)\b",
            "The message requests sensitive verification information:",
        ),
        (
            "click",
            r"\b(click|tap|open|visit)\b",
            "The message asks the reader to take an action:",
        ),
        (
            "call",
            r"\b(call|phone|dial|contact)\b",
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
    ]

    for rule_name, pattern, sentence_prefix in rule_groups:
        actual_match = find_actual_match(original_text, pattern)
        if actual_match:
            suspicious_keywords.append(actual_match)
            explanations.append(sentence_prefix + ' "' + actual_match + '"')
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
        explanations.append('A website-style link is present: "' + actual_match + '"')
        supplementary_checks.append("link")

    unique_keywords = []
    for keyword in suspicious_keywords:
        if keyword.lower() not in [item.lower() for item in unique_keywords]:
            unique_keywords.append(keyword)

    return unique_keywords, explanations, supplementary_checks


def analyze_message(text):
    """Analyze one message using ML probability and clearly separate rule checks."""
    if not isinstance(text, str) or not text.strip():
        raise ValueError("Message text must not be empty.")

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

    suspicious_keywords, explanations, supplementary_checks = get_rule_checks(text)

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

    if rule_upgrade_applied:
        explanations.append(
            "This final result was raised by several supplementary rule checks, "
            "not by the ML model alone."
        )

    if not explanations:
        explanations.append("No strong spam warning patterns were found in the message.")

    if classification == "SPAM":
        risk_level = "High"
        recommended_action = "Do not share personal details or money; verify the request through an official known channel."
    elif classification == "SUSPICIOUS":
        risk_level = "Medium"
        recommended_action = "Treat the message cautiously and verify its request using an official known channel."
    else:
        risk_level = "Low"
        recommended_action = "No strong warning was found, but continue to verify unusual requests independently."

    return {
        "classification": classification,
        "confidence": round(spam_probability * 100, 2),
        "risk_level": risk_level,
        "ml_prediction": ml_prediction,
        "explanation": explanations,
        "suspicious_keywords": suspicious_keywords,
        "supplementary_checks": supplementary_checks,
        "recommended_action": recommended_action,
    }