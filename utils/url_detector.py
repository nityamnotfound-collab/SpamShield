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


def analyze_url(url):
    """Analyze URL text locally using urllib.parse and regular expressions."""
    if not isinstance(url, str) or not url.strip():
        raise ValueError("URL text must not be empty.")

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
    reasons = []

    # URL length is a weak signal, so it receives only a small point value.
    if len(original_url) > URL_LENGTH_LONG:
        risk_score += URL_LENGTH_POINTS
        reasons.append(
            "The URL is unusually long, with more than "
            + str(URL_LENGTH_LONG)
            + " characters."
        )

    if is_ip_address(hostname):
        risk_score += IP_ADDRESS_POINTS
        reasons.append("The URL uses an IP address instead of a domain name.")

    if "@" in original_url:
        risk_score += SPECIAL_AT_POINTS
        reasons.append("The URL contains an @ character that may obscure its destination.")

    # Count // after the scheme as a special-character pattern in the rest of the URL.
    after_scheme = original_url.split("://", 1)[1] if "://" in original_url else original_url
    if "//" in after_scheme:
        risk_score += SPECIAL_DOUBLE_SLASH_POINTS
        reasons.append("The URL contains repeated forward slashes.")

    if original_url.count("-") >= 3:
        risk_score += SPECIAL_HYPHEN_POINTS
        reasons.append("The URL contains many hyphens.")

    if re.search(r"%[0-9a-fA-F]{2}", original_url):
        risk_score += SPECIAL_ENCODED_POINTS
        reasons.append("The URL contains encoded percent characters.")

    if hostname:
        subdomain_count = len([part for part in hostname.split(".") if part]) - 2
        if subdomain_count > 2:
            risk_score += SUBDOMAIN_POINTS
            reasons.append(
                "The domain has many subdomains, which can be used to make a URL look unfamiliar."
            )

    if hostname in SHORTENER_DOMAINS:
        risk_score += SHORTENER_POINTS
        reasons.append("The URL uses a known URL-shortening domain.")

    if scheme == "http":
        risk_score += HTTP_POINTS
        reasons.append("The URL uses HTTP instead of HTTPS.")

    lower_url = original_url.lower()
    found_keywords = []
    for keyword in SUSPICIOUS_KEYWORDS:
        if re.search(r"\b" + re.escape(keyword) + r"\b", lower_url):
            found_keywords.append(keyword)

    if found_keywords:
        risk_score += SUSPICIOUS_KEYWORD_POINTS
        reasons.append(
            "Suspicious keyword(s) found: "
            + ", ".join(found_keywords)
            + "."
        )

    if risk_score >= SUSPICIOUS_RISK_LIMIT:
        classification = "HIGH RISK"
        recommendation = (
            "Do not open or share this URL. Verify the sender and destination "
            "through an official known channel."
        )
    elif risk_score >= SAFE_RISK_LIMIT:
        classification = "SUSPICIOUS"
        recommendation = (
            "Exercise caution. Check the destination through an official known "
            "channel before opening it."
        )
    else:
        classification = "SAFE"
        recommendation = (
            "No strong URL patterns were detected, but verify unfamiliar sources independently."
        )

    if not reasons:
        reasons.append("No suspicious URL pattern checks were triggered.")

    return {
        "classification": classification,
        "risk_score": min(risk_score, 100),
        "reasons": reasons,
        "recommendation": recommendation,
        "note": "This is a pattern-based check, not a threat-intelligence lookup.",
    }