from collections import defaultdict
from typing import List, Dict
import threading

# Thread-safe in-memory store
# Maps conversation_id → list of {role, content} messages
_store: Dict[str, List[dict]] = defaultdict(list)
_lock = threading.Lock()

MAX_MESSAGES = 10  # max messages per conversation (to save tokens)


def get_history(conversation_id: str) -> List[dict]:
    """Return message history for a conversation."""
    with _lock:
        return list(_store[conversation_id])


def add_message(conversation_id: str, role: str, content: str):
    """Append a message to the conversation history."""
    with _lock:
        _store[conversation_id].append({"role": role, "content": content})
        # Keep only the last MAX_MESSAGES to avoid token overflow
        if len(_store[conversation_id]) > MAX_MESSAGES:
            _store[conversation_id] = _store[conversation_id][-MAX_MESSAGES:]


def clear_history(conversation_id: str):
    """Clear history for a conversation (e.g. on new chat)."""
    with _lock:
        _store[conversation_id] = []


def new_conversation_id() -> str:
    """Generate a new unique conversation ID."""
    import uuid
    return str(uuid.uuid4())