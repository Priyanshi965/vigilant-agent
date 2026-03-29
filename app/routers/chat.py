import logging
import json
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session
from app.models.schemas import ChatRequest, ChatResponse
from app.core.llm_client import complete, stream_complete
from app.core.guard import score_prompt, is_suspicious
from app.core.normalizer import normalize
from app.core.redactor import redact
from app.core.auth import get_current_user
from app.core.memory import get_history, add_message, new_conversation_id
from app.database import get_db
from app.models.db_models import Conversation, Message, SecurityEvent
from prometheus_client import Counter

BLOCKED_REQUESTS = Counter("blocked_chat_requests_total", "Blocked chat requests")
PII_REDACTED = Counter("pii_redacted_chat_total", "PII items redacted in chat")

logger = logging.getLogger(__name__)
router = APIRouter(tags=["chat"])

LEAKAGE_PATTERNS = [
    "you are an ai", "you are a helpful",
    "my instructions are", "my system prompt",
    "i was told to", "i am instructed to",
    "as an ai language model",
]


def count_pii_replacements(original: str, redacted: str) -> int:
    tags = [
        "[PHONE_REDACTED]", "[EMAIL_REDACTED]", "[API_KEY_REDACTED]",
        "[AADHAAR_REDACTED]", "[PAN_REDACTED]", "[PASSWORD_REDACTED]",
        "[IP_REDACTED]", "[NAME_REDACTED]", "[ORG_REDACTED]", "[LOCATION_REDACTED]"
    ]
    return sum(redacted.count(tag) for tag in tags)


def _run_security_pipeline(message: str, username: str, user_id: str, db: Session):
    clean_message = normalize(message)

    redacted_message = redact(clean_message)
    input_pii_count = count_pii_replacements(clean_message, redacted_message)
    if input_pii_count > 0:
        PII_REDACTED.inc(input_pii_count)
        logger.info(f"Redacted {input_pii_count} PII item(s) from input of user={username}")
    clean_message = redacted_message

    injection_score = score_prompt(clean_message)
    flagged = is_suspicious(clean_message)

    if injection_score > 0.75:
        BLOCKED_REQUESTS.inc()
        logger.warning(
            f"BLOCKED request from user={username} "
            f"score={injection_score:.2f} "
            f"preview={clean_message[:50]!r}"
        )
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

    return clean_message, injection_score, input_pii_count


def _save_conversation(
    db: Session, user_id: str, conv_id: str, original_message: str,
    reply: str, injection_score: float, input_pii_count: int
):
    try:
        # Check if conversation already exists in DB
        conv = db.query(Conversation).filter(Conversation.id == conv_id).first()
        
        if not conv:
            conv = Conversation(id=conv_id, user_id=user_id, title=original_message[:50])
            db.add(conv)
            db.flush()

        user_msg = Message(
            conversation_id=conv.id,
            role="user",
            content=original_message,
            injection_score=injection_score,
            flagged=False,
            blocked=False,
            pii_items_redacted=input_pii_count
        )
        db.add(user_msg)

        ai_msg = Message(
            conversation_id=conv.id,
            role="assistant",
            content=reply,
            injection_score=0.0,
            flagged=False,
            blocked=False
        )
        db.add(ai_msg)
        db.commit()
    except Exception as e:
        logger.error(f"DB save error: {e}")
        db.rollback()


def _apply_output_filter(
    safe_reply: str, username: str, user_id: str, db: Session
) -> str:
    reply_lower = safe_reply.lower()
    for pattern in LEAKAGE_PATTERNS:
        if pattern in reply_lower:
            logger.critical(f"OUTPUT FILTER triggered for user={username} pattern={pattern!r}")
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
            return "I'm sorry, I can't help with that."
    return safe_reply


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> ChatResponse:
    user_id = current_user["user_id"]
    username = current_user["username"]

    conv_id = request.conversation_id or new_conversation_id()

    # 🔐 SECURITY PIPELINE
    clean_message, injection_score, input_pii_count = _run_security_pipeline(
        request.message, username, user_id, db
    )

    # 🧠 Build analysis object
    analysis = {
        "injection_score": round(injection_score, 4),
        "pii_redacted": input_pii_count,
        "risk": "low",
        "blocked": False
    }

    if injection_score > 0.6:
        analysis["risk"] = "high"
    elif injection_score > 0.2:
        analysis["risk"] = "medium"

    history = get_history(conv_id)
    add_message(conv_id, "user", clean_message)

    logger.info(
        f"Message user={username} score={injection_score:.2f} "
        f"risk={analysis['risk']} conv={conv_id[:8]}"
    )

    # 🚀 PROCESS REQUEST — Allow with warnings for suspicious but not blocked
    reply = await complete(clean_message, history=history)

    # ⚠️ Add warning if suspicious but allowed
    if is_suspicious(clean_message) and injection_score > 0.5:
        reply += "\n\n⚠️ _Note: This request contained patterns commonly used for prompt injection. Your request was still processed, but parts may have been ignored for safety._"
    
    # 🔒 OUTPUT SAFETY
    safe_reply = redact(reply)

    output_pii_count = count_pii_replacements(reply, safe_reply)
    if output_pii_count > 0:
        PII_REDACTED.inc(output_pii_count)

    safe_reply = _apply_output_filter(safe_reply, username, user_id, db)

    add_message(conv_id, "assistant", safe_reply)

    _save_conversation(
        db, user_id, conv_id,
        request.message, safe_reply,
        injection_score, input_pii_count
    )

    return ChatResponse(
        reply=safe_reply,
        flagged=is_suspicious(clean_message) and injection_score > 0.5,
        injection_score=injection_score,
        blocked=False,
        conversation_id=conv_id
    )

@router.post("/chat/stream")
async def chat_stream(
    request: ChatRequest,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    user_id = current_user["user_id"]
    username = current_user["username"]

    conv_id = request.conversation_id or new_conversation_id()

    clean_message, injection_score, input_pii_count = _run_security_pipeline(
        request.message, username, user_id, db
    )

    history = get_history(conv_id)
    add_message(conv_id, "user", clean_message)

    logger.info(
        f"STREAM clean message from user={username} "
        f"score={injection_score:.2f} "
        f"conv={conv_id[:8]} "
        f"history_len={len(history)}"
    )

    async def generate():
        full_response = []

        try:
            async for chunk in stream_complete(clean_message, history=history):
                full_response.append(chunk)
                yield f"data: {json.dumps({'t': chunk})}\n\n"

        except Exception as e:
            logger.error(f"Streaming error for user={username}: {e}")
            yield f"data: [ERROR]\n\n"
            return

        complete_text = "".join(full_response)
        safe_reply = redact(complete_text)

        if is_suspicious(clean_message) and injection_score > 0.5:
            safe_reply += "\n\n⚠️ _Note: This request contained patterns commonly used for prompt injection. Your request was still processed, but parts may have been ignored for safety._"

        safe_reply = _apply_output_filter(safe_reply, username, user_id, db)
        add_message(conv_id, "assistant", safe_reply)

        _save_conversation(
            db, user_id, conv_id, request.message,
            safe_reply, injection_score, input_pii_count
        )

        flagged = is_suspicious(clean_message) and injection_score > 0.5
        meta = {
            "injection_score": round(injection_score, 4),
            "pii_items_redacted": input_pii_count,
            "blocked": False,
            "flagged": flagged,
            "conversation_id": conv_id,
        }
        yield f"data: [META:{json.dumps(meta)}]\n\n"
        yield f"data: [DONE]\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        }
    )