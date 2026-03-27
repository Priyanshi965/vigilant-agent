import re
import logging

logger = logging.getLogger(__name__)

try:
    import spacy
    nlp = spacy.load("en_core_web_sm")
except (OSError, ImportError):
    logger.warning("spaCy model not found — NER redaction disabled, regex-only mode active")
    nlp = None

# ── REGEX PATTERNS ─────────────────────────────────────
REGEX_PATTERNS = [
    (r'sk-[A-Za-z0-9]{20,}', '[API_KEY_REDACTED]'),
    (r'gsk_[A-Za-z0-9]{20,}', '[API_KEY_REDACTED]'),
    (r'AIza[A-Za-z0-9\-_]{30,}', '[API_KEY_REDACTED]'),
    (r'ghp_[A-Za-z0-9]{30,}', '[API_KEY_REDACTED]'),
    (r'\b[6-9]\d{9}\b', '[PHONE_REDACTED]'),
    (r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b', '[EMAIL_REDACTED]'),
    (r'\b\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', '[AADHAAR_REDACTED]'),
    (r'\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b', '[PAN_REDACTED]'),
    (r'(password|passwd|pwd)\s*[:=]\s*\S+', '[PASSWORD_REDACTED]'),
]

# ── NEVER redact these — public figures, places, tech terms ──
SAFE_ENTITIES = {
    # Tech
    "api", "openai", "groq", "anthropic", "google", "microsoft", "apple",
    "python", "fastapi", "llm", "ai", "ml", "gpt", "llama", "claude",
    # Common words spaCy wrongly tags
    "pii", "test", "normal", "message", "call", "email", "key",
    "my", "me", "the", "a", "an", "llm", "url", "http", "https",
    "json", "sql", "db", "server", "client", "user", "admin",
    # Famous people/places that are PUBLIC knowledge (not PII)
    "edgar", "poe", "shakespeare", "einstein", "newton", "darwin",
    "india", "america", "europe", "asia", "africa",
    "monday", "tuesday", "wednesday", "thursday", "friday",
    "january", "february", "march", "april", "june", "july",
    "august", "september", "october", "november", "december",
}

# Indian cities
INDIAN_LOCATIONS = {
    "pune", "mumbai", "delhi", "bangalore", "bengaluru", "hyderabad",
    "chennai", "kolkata", "ahmedabad", "surat", "jaipur", "lucknow",
    "nagpur", "indore", "bhopal", "patna", "vadodara", "thane",
    "agra", "nashik", "pimpri", "chinchwad", "navi mumbai",
}

# Context phrases that indicate REAL personal PII
PII_CONTEXT_PATTERNS = [
    r"my name is",
    r"i am called",
    r"call me",
    r"i'm ([\w]+)",
    r"contact (me|us) at",
    r"reach me at",
    r"my (phone|mobile|number|email|address) is",
    r"i live in",        
    r"i am from",        
    r"i'm from", 
]


def _has_pii_context(text: str, entity_start: int) -> bool:
    """Check if the entity appears near a PII-indicating phrase."""
    surrounding = text[max(0, entity_start-60):entity_start].lower()
    for pattern in PII_CONTEXT_PATTERNS:
        if re.search(pattern, surrounding):
            return True
    return False


def redact(text: str) -> str:
    """
    Smart PII redaction:
    - Always redacts: API keys, phone numbers, emails, Aadhaar, PAN
    - Contextually redacts: names/orgs ONLY when near PII phrases
    - Never redacts: public figures, famous names, tech terms, places
    """
    if not text or not text.strip():
        return text

    # Step 1 — Regex patterns (always apply — these are always PII)
    for pattern, replacement in REGEX_PATTERNS:
        text = re.sub(pattern, replacement, text)

    # Step 2 — spaCy NER with smart context checking (skipped if model unavailable)
    if nlp is None:
        redactions = []
    else:
        doc = nlp(text)
        redactions = []

    for ent in (doc.ents if nlp else []):
        ent_lower = ent.text.lower().strip()

        # Skip whitelisted entities
        if ent_lower in SAFE_ENTITIES:
            continue

        # Skip short words
        if len(ent.text.strip()) < 3:
            continue

        # Skip if any word in entity is in safe list
        if any(w.lower() in SAFE_ENTITIES for w in ent.text.split()):
            continue

        if ent.label_ == "PERSON":
            # Only redact persons when near PII context phrases
            if _has_pii_context(text, ent.start_char):
                redactions.append((ent.start_char, ent.end_char, "[NAME_REDACTED]"))

        elif ent.label_ == "ORG":
            # Only redact orgs when near PII context (not general mentions)
            if _has_pii_context(text, ent.start_char):
                redactions.append((ent.start_char, ent.end_char, "[ORG_REDACTED]"))

        elif ent.label_ == "GPE":
            # Only redact locations when near PII context
            if _has_pii_context(text, ent.start_char):
                redactions.append((ent.start_char, ent.end_char, "[LOCATION_REDACTED]"))

    # Apply NER redactions in reverse order
    for start, end, replacement in sorted(redactions, reverse=True):
        text = text[:start] + replacement + text[end:]

    # Step 3 — Indian cities near PII context only
    words = text.split()
    for i, word in enumerate(words):
        clean_word = word.lower().rstrip(".,!?")
        if clean_word in INDIAN_LOCATIONS:
            # Check context — only redact if near PII phrase
            surrounding = " ".join(words[max(0,i-8):i]).lower()
            if any(re.search(p, surrounding) for p in PII_CONTEXT_PATTERNS):
                words[i] = "[LOCATION_REDACTED]"
    text = " ".join(words)

    return text