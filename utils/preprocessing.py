import re
import unicodedata


def clean_text(text):
    """Clean message text consistently for both training and prediction."""
    text = unicodedata.normalize("NFKC", str(text)).lower()

    # Replace links first so URL punctuation does not create extra tokens.
    text = re.sub(r"(https?://|www\.)\S+", " urltoken ", text)
    text = re.sub(r"\b[\w.-]+\.(com|in|net|org|xyz)\b(?:/\S*)?", " urltoken ", text)

    # Replace phone numbers and long digit strings, including formatted numbers.
    text = re.sub(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)", " numtoken ", text)
    text = re.sub(r"\b\d{5,}\b", " numtoken ", text)

    # Keep text readable while preserving Rs and INR as meaningful currency words.
    text = re.sub(r"[^a-z0-9\s.]", " ", text)
    text = re.sub(r"\b(rs\.?|inr)\b", " rs ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()