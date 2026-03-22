import logging
import json
from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from app.models.schemas import ChatRequest, ChatResponse
from app.core.llm_client import complete
from app.core.guard import score_prompt, is_suspicious
from app.core.normalizer import normalize
from app.core.redactor import redact
from app.core.auth import get_current_user
from app.database import get_db
from app.models.db_models import Conversation, Message, SecurityEvent
from prometheus_client import Counter

BLOCKED_REQUESTS = Counter("blocked_chat_requests_total", "Blocked chat requests")
PII_REDACTED = Counter("pii_redacted_chat_total", "PII items redacted in chat")

logger = logging.getLogger(__name__)
router = APIRouter(tags=["chat"])


def count_pii_replacements(original: str, redacted: str) -> int:
    tags = [
        "[PHONE_REDACTED]", "[EMAIL_REDACTED]", "[API_KEY_REDACTED]",
        "[AADHAAR_REDACTED]", "[PAN_REDACTED]", "[PASSWORD_REDACTED]",
        "[IP_REDACTED]", "[NAME_REDACTED]", "[ORG_REDACTED]", "[LOCATION_REDACTED]"
    ]
    return sum(redacted.count(tag) for tag in tags)


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> ChatResponse:
    """
    Full security pipeline:
    Normalize → Redact Input → Score → Block/Allow → LLM → Redact Output → Output Filter
    All messages saved to database.
    """
    user_id = current_user["user_id"]
    username = current_user["username"]

    # Step 1 — Normalize
    clean_message = normalize(request.message)

    # Step 2 — Redact PII from input
    redacted_message = redact(clean_message)
    input_pii_count = count_pii_replacements(clean_message, redacted_message)
    if input_pii_count > 0:
        PII_REDACTED.inc(input_pii_count)
        logger.info(f"Redacted {input_pii_count} PII item(s) from input of user={username}")

    clean_message = redacted_message

    # Step 3 — Score the cleaned message
    injection_score = score_prompt(clean_message)
    flagged = is_suspicious(clean_message)

    # Step 4 — Block if flagged
    if flagged:
        BLOCKED_REQUESTS.inc()
        logger.warning(
            f"BLOCKED request from user={username} "
            f"score={injection_score:.2f} "
            f"preview={clean_message[:50]!r}"
        )

        # Save security event to database
        try:
            event = SecurityEvent(
                user_id=user_id,
                event_type="BLOCKED",
                severity="HIGH",
                details=json.dumps({
                    "score": injection_score,
                    "preview": clean_message[:100]
                })
            )
            db.add(event)
            db.commit()
        except Exception as e:
            logger.error(f"Security event DB error: {e}")
            db.rollback()

        raise HTTPException(
            status_code=403,
            detail={
                "error": "Request blocked by security policy",
                "code": "INJECTION_DETECTED"
            }
        )

    # Step 5 — Safe, send to LLM
    logger.info(f"Clean message from user={username} score={injection_score:.2f}")
    reply = await complete(clean_message)

    # Step 6 — Redact PII from output
    safe_reply = redact(reply)
    output_pii_count = count_pii_replacements(reply, safe_reply)
    if output_pii_count > 0:
        PII_REDACTED.inc(output_pii_count)
        logger.info(f"Redacted {output_pii_count} PII item(s) from output for user={username}")

    # Step 7 — Output filter
    LEAKAGE_PATTERNS = [
        "you are an ai", "you are a helpful",
        "my instructions are", "my system prompt",
        "i was told to", "i am instructed to",
        "as an ai language model",
    ]
    reply_lower = safe_reply.lower()
    for pattern in LEAKAGE_PATTERNS:
        if pattern in reply_lower:
            logger.critical(f"OUTPUT FILTER triggered for user={username} pattern={pattern!r}")

            # Log output filter event
            try:
                event = SecurityEvent(
                    user_id=user_id,
                    event_type="OUTPUT_FILTERED",
                    severity="CRITICAL",
                    details=json.dumps({"pattern": pattern})
                )
                db.add(event)
                db.commit()
            except Exception as e:
                logger.error(f"Security event DB error: {e}")
                db.rollback()

            safe_reply = "I'm sorry, I can't help with that."
            break

    # Step 8 — Save conversation + messages to database
    try:
        conv = Conversation(
            user_id=user_id,
            title=request.message[:50]
        )
        db.add(conv)
        db.flush()

        user_msg = Message(
            conversation_id=conv.id,
            role="user",
            content=request.message,
            injection_score=injection_score,
            flagged=False,
            blocked=False,
            pii_items_redacted=input_pii_count
        )
        db.add(user_msg)

        ai_msg = Message(
            conversation_id=conv.id,
            role="assistant",
            content=safe_reply,
            injection_score=0.0,
            flagged=False,
            blocked=False
        )
        db.add(ai_msg)
        db.commit()

    except Exception as e:
        logger.error(f"DB save error: {e}")
        db.rollback()

    return ChatResponse(
        reply=safe_reply,
        flagged=False,
        injection_score=injection_score,
        blocked=False
    )