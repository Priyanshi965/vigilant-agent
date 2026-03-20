import logging
from fastapi import APIRouter, HTTPException
from app.models.schemas import ChatRequest, ChatResponse
from app.core.llm_client import complete
from app.core.guard import score_prompt, is_suspicious
from app.core.normalizer import normalize
from app.core.redactor import redact

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Full security pipeline:
    Normalize → Redact Input → Score → Block/Allow → LLM → Redact Output → Output Filter
    """
    # Step 1 — Normalize (strip invisible chars, fix unicode)
    clean_message = normalize(request.message)

    # Step 2 — Redact PII from input before it reaches the LLM
    clean_message = redact(clean_message)

    # Step 3 — Score the cleaned message
    injection_score = score_prompt(clean_message)
    flagged = is_suspicious(clean_message)

    # Step 4 — Block if flagged
    if flagged:
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