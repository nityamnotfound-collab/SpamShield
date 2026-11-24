import ipaddress
import re
from urllib.parse import urlparse


# Named risk boundaries keep classification rules easy to understand and update.
SAFE_RISK_LIMIT = 30
SUSPICIOUS_RISK_LIMIT = 60


# Point values are deliberately simple because this is a pattern-based estimate.
URL_LENGTH_LONG = 75
URL_LENGTH_POINTS = 10
IP_ADDRESS_POINTS = 25
SPECIAL_AT_POINTS = 15
SPECIAL_DOUBLE_SLASH_POINTS = 8
SPECIAL_HYPHEN_POINTS = 12
SPECIAL_ENCODED_POINTS = 12
SUBDOMAIN_POINTS = 15
SHORTENER_POINTS = 20
HTTP_POINTS = 15
SUSPICIOUS_KEYWORD_POINTS = 8


SHORTENER_DOMAINS = (
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
)

SUSPICIOUS_KEYWORDS = (
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "bank",
    "kyc",
    "free",
    "prize",
)


def is_ip_address(hostname):
    """Check whether the URL hostname is an IPv4 or IPv6 address."""
    if not hostname:
        return False
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        return True
    except ValueError:
        return False


def analyze_url(url, lang="en"):
    """Analyze URL text locally using urllib.parse and regular expressions."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL text must not be empty.")
    lang = lang if lang in ("en", "hi") else "en"

    original_url = url.strip()
    url_for_parsing = original_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url_for_parsing):
        url_for_parsing = "http://" + url_for_parsing

    try:
        parsed_url = urlparse(url_for_parsing)
        hostname = (parsed_url.hostname or "").lower()
    except ValueError as error:
        raise ValueError("URL text could not be parsed.") from error
    scheme = parsed_url.scheme.lower()
    risk_score = 0
    reason_localizations = []

    def add_reason(english, hindi):
        reason_localizations.append({"en": english, "hi": hindi})

    # URL length is a weak signal, so it receives only a small point value.
    if len(original_url) > URL_LENGTH_LONG:
        risk_score += URL_LENGTH_POINTS
        add_reason(
            "The URL is unusually long, with more than "
            + str(URL_LENGTH_LONG)
            + " characters.",
            str(URL_LENGTH_LONG)
            + " अक्षरों से अधिक होने के कारण URL असामान्य रूप से लंबा है।",
        )

    if is_ip_address(hostname):
        risk_score += IP_ADDRESS_POINTS
        add_reason(
            "The URL uses an IP address instead of a domain name.",
            "URL में डोमेन नाम के बजाय IP पता है।",
        )

    if "@" in original_url:
        risk_score += SPECIAL_AT_POINTS
        add_reason(
            "The URL contains an @ character that may obscure its destination.",
            "URL में @ चिह्न है, जो उसके गंतव्य को छिपा सकता है।",
        )

    # Count // after the scheme as a special-character pattern in the rest of the URL.
    after_scheme = original_url.split("://", 1)[1] if "://" in original_url else original_url
    if "//" in after_scheme:
        risk_score += SPECIAL_DOUBLE_SLASH_POINTS
        add_reason(
            "The URL contains repeated forward slashes.",
            "URL में लगातार कई स्लैश हैं।",
        )

    if original_url.count("-") >= 3:
        risk_score += SPECIAL_HYPHEN_POINTS
        add_reason("The URL contains many hyphens.", "URL में कई हाइफ़न हैं।")

    if re.search(r"%[0-9a-fA-F]{2}", original_url):
        risk_score += SPECIAL_ENCODED_POINTS
        add_reason(
            "The URL contains encoded percent characters.",
            "URL में प्रतिशत चिह्न के एन्कोड किए गए वर्ण हैं।",
        )

    if hostname:
        subdomain_count = len([part for part in hostname.split(".") if part]) - 2
        if subdomain_count > 2:
            risk_score += SUBDOMAIN_POINTS
            add_reason(
                "The domain has many subdomains, which can be used to make a URL look unfamiliar.",
                "डोमेन में कई सबडोमेन हैं, जिससे URL अपरिचित दिख सकता है।",
            )

    if hostname in SHORTENER_DOMAINS:
        risk_score += SHORTENER_POINTS
        add_reason(
            "The URL uses a known URL-shortening domain.",
            "URL में एक ज्ञात लिंक छोटा करने वाली सेवा का उपयोग है।",
        )

    if scheme == "http":
        risk_score += HTTP_POINTS
        add_reason(
            "The URL uses HTTP instead of HTTPS.",
            "URL में HTTPS के बजाय HTTP का उपयोग है।",
        )

    lower_url = original_url.lower()
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if re.search(r"\b" + re.escape(keyword) + r"\b", lower_url):
            found_keywords.append(keyword)

    if found_keywords:
        risk_score += SUSPICIOUS_KEYWORD_POINTS
        keyword_list = ", ".join(found_keywords)
        add_reason(
            "Suspicious keyword(s) found: "
            + keyword_list
            + ".",
            "संदिग्ध कीवर्ड मिले: " + keyword_list + "।",
        )

    if risk_score >= SUSPICIOUS_RISK_LIMIT:
        classification = "HIGH RISK"
        recommendation = {
            "en": "Do not open or share this URL. Verify the sender and destination "
            "through an official known channel.",
            "hi": "इस URL को न खोलें और न साझा करें। भेजने वाले और गंतव्य की पुष्टि "
            "किसी आधिकारिक व ज्ञात माध्यम से करें।",
        }
    elif risk_score >= SAFE_RISK_LIMIT:
        classification = "SUSPICIOUS"
        recommendation = {
            "en": "Exercise caution. Check the destination through an official known "
            "channel before opening it.",
            "hi": "सावधानी बरतें। खोलने से पहले आधिकारिक और ज्ञात माध्यम से "
            "गंतव्य की जाँच करें।",
        }
    else:
        classification = "SAFE"
        recommendation = {
            "en": "No strong URL patterns were detected, but verify unfamiliar sources independently.",
            "hi": "URL में कोई स्पष्ट चेतावनी संकेत नहीं मिला, फिर भी अपरिचित स्रोतों "
            "की अलग से पुष्टि करें।",
        }

    if not reason_localizations:
        add_reason(
            "No suspicious URL pattern checks were triggered.",
            "URL में कोई संदिग्ध पैटर्न नहीं मिला।",
        )

    localizations = {
        language: {
            "reasons": [reason[language] for reason in reason_localizations],
            "recommendation": recommendation[language],
            "note": (
                "This is a pattern-based check, not a threat-intelligence lookup."
                if language == "en"
                else "यह पैटर्न पर आधारित जाँच है, खतरे की जानकारी वाले डेटाबेस से "
                "मिलान नहीं।"
            ),
        }
        for language in ("en", "hi")
    }

    return {
        "classification": classification,
        "risk_score": min(risk_score, 100),
        "suspicious_keywords": found_keywords,
        "reasons": localizations[lang]["reasons"],
        "recommendation": localizations[lang]["recommendation"],
        "note": localizations[lang]["note"],
        "localizations": localizations,
    }