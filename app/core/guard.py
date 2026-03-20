import re
from app.config import get_settings

settings = get_settings()

# Injection attack patterns — ordered by severity
INJECTION_PATTERNS = [
    # Direct instruction override attempts
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", 0.95),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", 0.95),
    (r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", 0.95),

    # Role/persona hijacking
    (r"you\s+are\s+now\s+(a\s+)?(?!an?\s+ai|an?\s+assistant)([\w\s]+)", 0.85),
    (r"act\s+as\s+(a\s+)?(?!an?\s+ai|an?\s+assistant)([\w\s]+)with\s+no\s+(restrictions?|limits?)", 0.90),
    (r"pretend\s+(you\s+are|to\s+be)\s+.{0,50}no\s+(rules?|restrictions?|limits?)", 0.90),

    # System prompt extraction
    (r"(reveal|show|print|display|tell me)\s+(your\s+)?(system\s+prompt|instructions?|initial prompt)", 0.90),
    (r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt)", 0.85),

    # Jailbreak keywords
    (r"\bdan\b.{0,30}\bjailbreak\b", 0.95),
    (r"jailbreak", 0.75),
    (r"do\s+anything\s+now", 0.80),

    # Override/bypass attempts
    (r"(bypass|override|disable|turn\s+off)\s+(your\s+)?(safety|filter|restriction|rule|guideline)", 0.90),
    (r"new\s+(instructions?|prompt|orders?)\s*:", 0.80),
    (r"###\s*(instruction|system|prompt)", 0.85),

    # Indirect injection markers
    (r"<\s*instructions?\s*>", 0.85),
    (r"\[INST\]", 0.80),
    (r"<<SYS>>", 0.85),
]


def score_prompt(text: str) -> float:
    """
    Score a prompt for injection attempts.
    Returns a float between 0.0 (safe) and 1.0 (definite injection).
    Uses pattern matching — fast, no GPU needed, no API calls.
    """
    if not text or not text.strip():
        return 0.0

    text_lower = text.lower()
    highest_score = 0.0

    for pattern, score in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            if score > highest_score:
                highest_score = score
            # Early exit if we already hit max confidence
            if highest_score >= 0.95:
                break

    return highest_score


def is_suspicious(text: str) -> bool:
    """Returns True if the injection score exceeds the configured threshold."""
    return score_prompt(text) >= settings.injection_threshold