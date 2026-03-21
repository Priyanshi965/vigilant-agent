import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Boolean, Integer, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.database import Base


def now_utc():
    return datetime.now(timezone.utc)


def new_uuid():
    return str(uuid.uuid4())


class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=new_uuid)
    username = Column(String, unique=True, nullable=False, index=True)
    hashed_password = Column(String, nullable=False)
    role = Column(String, default="readonly")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=now_utc)

    # Relationships
    conversations = relationship("Conversation", back_populates="user", cascade="all, delete")
    security_events = relationship("SecurityEvent", back_populates="user", cascade="all, delete")


class Conversation(Base):
    __tablename__ = "conversations"

    id = Column(String, primary_key=True, default=new_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=False)
    title = Column(String, default="New Conversation")
    created_at = Column(DateTime, default=now_utc)
    updated_at = Column(DateTime, default=now_utc, onupdate=now_utc)

    # Relationships
    user = relationship("User", back_populates="conversations")
    messages = relationship("Message", back_populates="conversation", cascade="all, delete", order_by="Message.created_at")


class Message(Base):
    __tablename__ = "messages"

    id = Column(String, primary_key=True, default=new_uuid)
    conversation_id = Column(String, ForeignKey("conversations.id"), nullable=False)
    role = Column(String, nullable=False)          # "user" or "assistant"
    content = Column(Text, nullable=False)
    injection_score = Column(Float, default=0.0)
    flagged = Column(Boolean, default=False)
    blocked = Column(Boolean, default=False)
    pii_items_redacted = Column(Integer, default=0)
    created_at = Column(DateTime, default=now_utc)

    # Relationship
    conversation = relationship("Conversation", back_populates="messages")


class SecurityEvent(Base):
    __tablename__ = "security_events"

    id = Column(String, primary_key=True, default=new_uuid)
    user_id = Column(String, ForeignKey("users.id"), nullable=True)
    event_type = Column(String, nullable=False)    # BLOCKED / REDACTED / VALIDATOR_REJECTED / OUTPUT_FILTERED
    severity = Column(String, default="MEDIUM")    # LOW / MEDIUM / HIGH / CRITICAL
    details = Column(Text, nullable=True)          # JSON string with full context
    ip_address = Column(String, nullable=True)
    created_at = Column(DateTime, default=now_utc)

    # Relationship
    user = relationship("User", back_populates="security_events")