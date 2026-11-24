import re
import unicodedata


def clean_text(text):
    """Clean message text consistently for both training and prediction."""
    text = unicodedata.normalize("NFKC", str(text))
    text = "".join(
        character.lower()
        if "LATIN" in unicodedata.name(character, "")
        else character
        for character in text
    )

    # Replace links first so URL punctuation does not create extra tokens.
    text = re.sub(r"(https?://|www\.)\S+", " urltoken ", text)
    text = re.sub(r"\b[\w.-]+\.(com|in|net|org|xyz)\b(?:/\S*)?", " urltoken ", text)

    # Replace phone numbers and long digit strings, including formatted numbers.
    text = re.sub(r"(?<!\d)(?:\+?\d[\d\s().-]{7,}\d)(?!\d)", " numtoken ", text)
    text = re.sub(r"\b\d{5,}\b", " numtoken ", text)

    # Keep Unicode letters and marks so Devanagari words survive preprocessing.
    text = "".join(
        character
        if character == "."
        or character.isspace()
        or unicodedata.category(character)[0] in ("L", "M", "N")
        else " "
        for character in text
    )
    text = re.sub(r"\b(rs\.?|inr)\b", " rs ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()