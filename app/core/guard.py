import re
import logging
from functools import lru_cache
from app.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

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


# ── ML MODEL ───────────────────────────────────────────
@lru_cache(maxsize=1)
def _load_ml_model():
    """
    Load protectai/deberta-v3-base-prompt-injection-v2 from HuggingFace.
    No gating required — downloads instantly.
    Returns (tokenizer, model) or (None, None) if unavailable.
    Cached — only loads once on first call.
    """
    try:
        from transformers import AutoTokenizer, AutoModelForSequenceClassification

        model_id = "protectai/deberta-v3-base-prompt-injection-v2"

        logger.info(f"Loading ML classifier: {model_id}")

        tokenizer = AutoTokenizer.from_pretrained(model_id)
        model = AutoModelForSequenceClassification.from_pretrained(model_id)
        model.eval()

        logger.info("✅ ML classifier loaded — ML mode active")
        return tokenizer, model

    except Exception as e:
        logger.warning(f"⚠ ML model unavailable: {e}")
        logger.warning("⚠ Falling back to regex classifier")
        return None, None


def _ml_score(text: str) -> float | None:
    """
    Score text using the ML model.
    Returns float 0.0-1.0 or None if model unavailable.
    """
    try:
        import torch
        tokenizer, model = _load_ml_model()

        if tokenizer is None or model is None:
            return None

        inputs = tokenizer(
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        )

        with torch.no_grad():
            outputs = model(**inputs)
            probs = torch.softmax(outputs.logits, dim=-1)

        # protectai model: label 0 = SAFE, label 1 = INJECTION
        injection_prob = probs[0][1].item()
        score = injection_prob

        return round(score, 4)

    except Exception as e:
        logger.error(f"ML scoring error: {e}")
        return None


# ── PUBLIC API ─────────────────────────────────────────
def score_prompt(text: str) -> float:
    """
    Score a prompt for injection attempts.
    Returns float 0.0 (safe) to 1.0 (definite injection).

    Strategy:
    1. Try ML model first (more accurate)
    2. Fall back to regex if ML unavailable
    3. Take the HIGHER of both scores for maximum safety
    """
    if not text or not text.strip():
        return 0.0

    # Always run regex (fast, no dependencies)
    regex_s = _regex_score(text)

    # Try ML model
    ml_s = _ml_score(text)

    if ml_s is not None:
        # Both available — take the higher score (fail safe)
        final = max(regex_s, ml_s)
        logger.debug(f"Score — ML: {ml_s:.3f} | Regex: {regex_s:.3f} | Final: {final:.3f}")
        return final
    else:
        # ML unavailable — regex only
        logger.debug(f"Score — Regex only: {regex_s:.3f}")
        return regex_s


def is_suspicious(text: str) -> bool:
    """Returns True if injection score exceeds the configured threshold."""
    return score_prompt(text) >= settings.injection_threshold


def get_classifier_mode() -> str:
    """Returns which classifier is currently active."""
    tokenizer, model = _load_ml_model()
    return "ML (protectai/deberta-v3-base-prompt-injection-v2)" if model is not None else "Regex Fallback"