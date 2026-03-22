import logging
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from app.database import get_db
from app.core.auth import get_current_user
from app.models.db_models import Conversation, Message, SecurityEvent

logger = logging.getLogger(__name__)
router = APIRouter(tags=["conversations"])


@router.get("/conversations")
async def get_conversations(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns all conversations for the current user, newest first."""
    convs = db.query(Conversation)\
        .filter(Conversation.user_id == current_user["user_id"])\
        .order_by(Conversation.created_at.desc())\
        .limit(50)\
        .all()

    return [
        {
            "id": c.id,
            "title": c.title,
            "created_at": c.created_at.isoformat(),
            "message_count": len(c.messages)
        }
        for c in convs
    ]


@router.get("/conversations/{conv_id}/messages")
async def get_messages(
    conv_id: str,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns all messages in a conversation."""
    conv = db.query(Conversation).filter(
        Conversation.id == conv_id,
        Conversation.user_id == current_user["user_id"]
    ).first()

    if not conv:
        return {"error": "Conversation not found"}

    return [
        {
            "role": m.role,
            "content": m.content,
            "injection_score": m.injection_score,
            "pii_items_redacted": m.pii_items_redacted,
            "created_at": m.created_at.isoformat()
        }
        for m in conv.messages
    ]


@router.get("/security/events")
async def get_security_events(
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Returns all security events.
    Admin sees all events. Others see only their own.
    """
    query = db.query(SecurityEvent)

    if current_user["role"] != "admin":
        query = query.filter(SecurityEvent.user_id == current_user["user_id"])

    events = query.order_by(SecurityEvent.created_at.desc()).limit(100).all()

    return [
        {
            "id": e.id,
            "event_type": e.event_type,
            "severity": e.severity,
            "details": e.details,
            "created_at": e.created_at.isoformat()
        }
        for e in events
    ]