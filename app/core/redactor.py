import re
import spacy

# Load spaCy model for names, organizations, locations
try:
    nlp = spacy.load("en_core_web_sm")
except OSError:
    raise RuntimeError("spaCy model not found. Run: python -m spacy download en_core_web_sm")


# --- Regex patterns for structured PII ---
REGEX_PATTERNS = [
    # API Keys
    (r'sk-[A-Za-z0-9]{20,}', '[API_KEY_REDACTED]'),
    (r'gsk_[A-Za-z0-9]{20,}', '[API_KEY_REDACTED]'),        # Groq
    (r'AIza[A-Za-z0-9\-_]{30,}', '[API_KEY_REDACTED]'),     # Google
    (r'ghp_[A-Za-z0-9]{30,}', '[API_KEY_REDACTED]'),        # GitHub

    # Indian mobile numbers (10 digits starting with 6-9)
    (r'\b[6-9]\d{9}\b', '[PHONE_REDACTED]'),

    # Email addresses
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[EMAIL_REDACTED]'),

    # Aadhaar number (12 digits, optionally space/dash separated)
    (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', '[AADHAAR_REDACTED]'),

    # PAN card (Indian tax ID: 5 letters, 4 digits, 1 letter)
    (r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', '[PAN_REDACTED]'),

    # Generic passwords in text
    (r'(password|passwd|pwd)\s*[:=]\s*\S+', '[PASSWORD_REDACTED]'),

    # IPv4 addresses
    (r'\b(?:\d{1,3}\.){3}\d{1,3}\b', '[IP_REDACTED]'),
]

# Indian cities spaCy's small model often misses
INDIAN_LOCATIONS = {
    "pune", "mumbai", "delhi", "bangalore", "bengaluru", "hyderabad",
    "chennai", "kolkata", "ahmedabad", "surat", "jaipur", "lucknow",
    "nagpur", "indore", "bhopal", "patna", "vadodara", "ludhiana",
    "agra", "nashik", "pimpri", "chinchwad", "thane", "navi mumbai"
}

# Common words spaCy wrongly tags as entities — never redact these
FALSE_POSITIVES = {
    "api", "key", "groq", "openai", "pii", "test", "normal",
    "message", "call", "email", "my", "me", "the", "a", "an",
    "llm", "ai", "url", "http", "https", "json", "python"
}


def redact(text: str) -> str:
    """
    Scan text and replace all detected PII with redaction placeholders.
    Runs regex patterns first, then spaCy NER for names/orgs/locations,
    then a manual check for Indian cities spaCy misses.

    Applied to BOTH user input and LLM output.
    """
    if not text or not text.strip():
        return text

    # Step 1 — Apply all regex patterns
    for pattern, replacement in REGEX_PATTERNS:
        text = re.sub(pattern, replacement, text)

    # Step 2 — spaCy NER for names, organizations, locations
    doc = nlp(text)
    redactions = []

    for ent in doc.ents:
        # Skip short or whitelisted words
        if ent.text.lower() in FALSE_POSITIVES:
            continue
        if len(ent.text.strip()) < 3:
            continue

        if ent.label_ == "PERSON":
            redactions.append((ent.start_char, ent.end_char, "[NAME_REDACTED]"))
        elif ent.label_ == "ORG":
            redactions.append((ent.start_char, ent.end_char, "[ORG_REDACTED]"))
        elif ent.label_ == "GPE":
            redactions.append((ent.start_char, ent.end_char, "[LOCATION_REDACTED]"))

    # Apply NER redactions in reverse order so char positions stay valid
    for start, end, replacement in sorted(redactions, reverse=True):
        text = text[:start] + replacement + text[end:]

    # Step 3 — Manually catch Indian cities spaCy misses
    words = text.split()
    for i, word in enumerate(words):
        if word.lower().rstrip(".,!?") in INDIAN_LOCATIONS:
            words[i] = "[LOCATION_REDACTED]"
    text = " ".join(words)

    return text