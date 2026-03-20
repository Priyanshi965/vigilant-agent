import logging
from fastapi import APIRouter, HTTPException
from app.models.schemas import ChatRequest, ChatResponse
from app.core.llm_client import complete
from app.core.guard import score_prompt, is_suspicious
from app.core.normalizer import normalize
from app.core.redactor import redact
from prometheus_client import Counter

BLOCKED_REQUESTS = Counter("blocked_chat_requests_total", "Blocked chat requests")
PII_REDACTED = Counter("pii_redacted_chat_total", "PII items redacted in chat")

logger = logging.getLogger(__name__)
router = APIRouter()


def count_pii_replacements(original: str, redacted: str) -> int:
    """Count how many PII items were redacted by comparing the two strings."""
    tags = [
        "[PHONE_REDACTED]", "[EMAIL_REDACTED]", "[API_KEY_REDACTED]",
        "[AADHAAR_REDACTED]", "[PAN_REDACTED]", "[PASSWORD_REDACTED]",
        "[IP_REDACTED]", "[NAME_REDACTED]", "[ORG_REDACTED]", "[LOCATION_REDACTED]"
    ]
    return sum(redacted.count(tag) for tag in tags)


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Full security pipeline:
    Normalize → Redact Input → Score → Block/Allow → LLM → Redact Output → Output Filter
    """
    # Step 1 — Normalize (strip invisible chars, fix unicode)
    clean_message = normalize(request.message)

    # Step 2 — Redact PII from input before it reaches the LLM
    redacted_message = redact(clean_message)

    # Count and track PII redactions on input
    input_pii_count = count_pii_replacements(clean_message, redacted_message)
    if input_pii_count > 0:
        PII_REDACTED.inc(input_pii_count)
        logger.info(f"Redacted {input_pii_count} PII item(s) from input of user={request.user_id}")

    clean_message = redacted_message

    # Step 3 — Score the cleaned message
    injection_score = score_prompt(clean_message)
    flagged = is_suspicious(clean_message)

    # Step 4 — Block if flagged
    if flagged:
        BLOCKED_REQUESTS.inc()  # ← increment blocked counter
        logger.warning(
            f"BLOCKED request from user={request.user_id} "
            f"score={injection_score:.2f} "
            f"preview={clean_message[:50]!r}"
        )
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Request blocked by security policy",
                "code": "INJECTION_DETECTED"
            }
        )

    # Step 5 — Safe, send to LLM
    logger.info(
        f"Clean message from user={request.user_id} "
        f"score={injection_score:.2f}"
    )
    reply = await complete(clean_message)

    # Step 6 — Redact PII from LLM output before sending to user
    safe_reply = redact(reply)

    # Count and track PII redactions on output
    output_pii_count = count_pii_replacements(reply, safe_reply)
    if output_pii_count > 0:
        PII_REDACTED.inc(output_pii_count)
        logger.info(f"Redacted {output_pii_count} PII item(s) from output for user={request.user_id}")

    # Step 7 — Output filter: catch leaked system prompts or secrets
    LEAKAGE_PATTERNS = [
        "you are an ai",
        "you are a helpful",
        "my instructions are",
        "my system prompt",
        "i was told to",
        "i am instructed to",
        "as an ai language model",
    ]

    reply_lower = safe_reply.lower()
    for pattern in LEAKAGE_PATTERNS:
        if pattern in reply_lower:
            logger.critical(
                f"OUTPUT FILTER triggered for user={request.user_id} "
                f"pattern={pattern!r}"
            )
            safe_reply = "I'm sorry, I can't help with that."
            break

    return ChatResponse(
        reply=safe_reply,
        flagged=False,
        injection_score=injection_score,
        blocked=False
    )