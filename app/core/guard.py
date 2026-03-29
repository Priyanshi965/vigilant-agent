import re
import logging
import httpx
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

HF_MODEL_URL = "https://router.huggingface.co/models/protectai/deberta-v3-base-prompt-injection-v2"

# ── REGEX FALLBACK (always available) ─────────────────
INJECTION_PATTERNS = [
    (r"ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", 0.95),
    (r"disregard\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", 0.95),
    (r"forget\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context)", 0.95),
    (r"forget\s+everything(\s+above)?", 0.90),
    (r"you\s+are\s+now\s+an?\s+unrestricted", 0.95),
    (r"you\s+are\s+now\s+(a\s+)?(?!an?\s+ai|an?\s+assistant)([\w\s]+)", 0.85),
    (r"\bunrestricted\s+ai\b", 0.90),
    (r"act\s+as\s+(a\s+)?(?!an?\s+ai|an?\s+assistant)([\w\s]+)with\s+no\s+(restrictions?|limits?)", 0.90),
    (r"pretend\s+(you\s+are|to\s+be)\s+.{0,50}no\s+(rules?|restrictions?|limits?)", 0.90),
    (r"(reveal|show|print|display|tell me)\s+(your\s+)?(system\s+prompt|instructions?|initial prompt)", 0.90),
    (r"what\s+(are|were)\s+your\s+(original\s+)?(instructions?|system\s+prompt)", 0.85),
    (r"\bdan\b.{0,30}\bjailbreak\b", 0.95),
    (r"you\s+are\s+dan\b", 0.95),
    (r"\bdo\s+anything\s+now\b", 0.95),
    (r"you\s+(have\s+)?(no\s+restrictions?|are\s+unrestricted|are\s+free\s+from)", 0.95),
    (r"jailbreak", 0.80),
    (r"no\s+restrictions?\b", 0.80),
    (r"without\s+(any\s+)?(restrictions?|limits?|rules?|guidelines?)", 0.85),
    (r"(bypass|override|disable|turn\s+off)\s+(your\s+)?(safety|filter|restriction|rule|guideline)", 0.90),
    (r"new\s+(instructions?|prompt|orders?)\s*:", 0.80),
    (r"###\s*(instruction|system|prompt)", 0.85),
    (r"<\s*instructions?\s*>", 0.85),
    (r"\[INST\]", 0.80),
    (r"<<SYS>>", 0.85),
]


def _regex_score(text: str) -> float:
    """Fast regex-based fallback scorer."""
    text_lower = text.lower()
    highest = 0.0
    for pattern, score in INJECTION_PATTERNS:
        if re.search(pattern, text_lower):
            highest = max(highest, score)
            if highest >= 0.95:
                break
    return highest


# ── HF INFERENCE API ───────────────────────────────────
def _ml_score(text: str) -> float | None:
    """
    Score text via HuggingFace Inference API.
    Returns float 0.0-1.0 or None if token missing / API error.
    No local model download — pure HTTP call.
    """
    token = settings.hf_token
    if not token:
        return None

    try:
        resp = httpx.post(
            HF_MODEL_URL,
            headers={"Authorization": f"Bearer {token}"},
            json={"inputs": text},
            timeout=5.0,
        )
        if resp.status_code != 200:
            logger.warning(f"HF API returned {resp.status_code}: {resp.text[:120]}")
            return None

        data = resp.json()
        # Response shape: [[{"label":"INJECTION","score":0.99},{"label":"SAFE","score":0.01}]]
        if isinstance(data, list) and data:
            inner = data[0] if isinstance(data[0], list) else data
            for item in inner:
                if item.get("label", "").upper() == "INJECTION":
                    return round(item["score"], 4)
        return None

    except Exception as e:
        logger.warning(f"HF API error: {e}")
        return None


# ── PUBLIC API ─────────────────────────────────────────
def score_prompt(text: str) -> float:
    """
    Score a prompt for injection attempts.
    Returns float 0.0 (safe) to 1.0 (definite injection).

    Strategy:
    1. Always run regex (fast, no dependencies)
    2. Call HF Inference API if token is set
    3. Take the HIGHER of both scores (fail-safe)
    """
    if not text or not text.strip():
        return 0.0

    regex_s = _regex_score(text)
    ml_s = _ml_score(text)

    if ml_s is not None:
        final = max(regex_s, ml_s)
        logger.debug(f"Score — HF API: {ml_s:.3f} | Regex: {regex_s:.3f} | Final: {final:.3f}")
        return final

    logger.debug(f"Score — Regex only: {regex_s:.3f}")
    return regex_s


def is_suspicious(text: str) -> bool:
    """Returns True if injection score exceeds the configured threshold."""
    return score_prompt(text) >= settings.injection_threshold


def get_classifier_mode() -> str:
    """Returns which classifier is currently active."""
    return "HF Inference API (protectai/deberta-v3-base-prompt-injection-v2)" if settings.hf_token else "Regex Fallback"