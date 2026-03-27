from groq import AsyncGroq
from app.config import get_settings
from typing import AsyncGenerator, List, Optional
import re
import logging

logger = logging.getLogger(__name__)
settings = get_settings()
_client: AsyncGroq | None = None

def _get_client() -> AsyncGroq:
    """Lazy-init the Groq client so a missing key doesn't crash startup."""
    global _client
    if _client is None:
        if not settings.groq_api_key:
            raise RuntimeError("GROQ_API_KEY is not set. Add it as an environment variable on your host.")
        _client = AsyncGroq(api_key=settings.groq_api_key)
    return _client

SYSTEM_PROMPT = """You are Vigilant, a helpful AI assistant.

STRICT FORMAT RULES:
1. Lists MUST use this exact format — each item on its own line:
1. First item
2. Second item
3. Third item

OR bullet format:
- First item
- Second item
- Third item

NEVER put list items on the same line separated by bullets.
ALWAYS put each list item on a NEW LINE.

2. Single questions → 1-2 sentences only.
3. How-to questions → numbered steps, one per line.
4. Jokes/poems/stories → natural format.
5. NO disclaimers. NO "As an AI..." phrases.
6. Public figures like Edgar Allan Poe, Shakespeare, Einstein → discuss freely.
"""


def _format_response(text: str) -> str:
    text = re.sub(r'\s*[•·]\s*', '\n• ', text)
    text = re.sub(r'\n-\s+', '\n- ', text)
    text = re.sub(r'(\d+\.)\s+([^\n]+?)\s+(?=\d+\.)', r'\1 \2\n', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    text = text.strip()
    if text.startswith('\n•'):
        text = text[1:]
    return text


async def complete(
    prompt: str,
    system_prompt: str = None,
    history: Optional[List[dict]] = None
) -> str:
    """
    Send a prompt to the LLM and return the full text response.
    Includes conversation history for multi-turn memory.
    """
    messages = [{"role": "system", "content": system_prompt or SYSTEM_PROMPT}]

    # Inject history before current message
    if history:
        messages.extend(history)

    messages.append({"role": "user", "content": prompt})

    response = await _get_client().chat.completions.create(
        model=settings.model_name,
        messages=messages,
        max_tokens=1000,
        temperature=0.7,
    )

    raw = response.choices[0].message.content.strip()
    return _format_response(raw)


async def stream_complete(
    prompt: str,
    system_prompt: str = None,
    history: Optional[List[dict]] = None
) -> AsyncGenerator[str, None]:
    """
    Stream a prompt to the LLM, yielding text chunks as they arrive.
    Includes conversation history for multi-turn memory.
    NOTE: _format_response is NOT applied per-chunk — the caller must
    buffer the full response and apply it after streaming is complete.
    """
    messages = [{"role": "system", "content": system_prompt or SYSTEM_PROMPT}]

    # Inject history before current message
    if history:
        messages.extend(history)

    messages.append({"role": "user", "content": prompt})

    stream = await _get_client().chat.completions.create(
        model=settings.model_name,
        messages=messages,
        max_tokens=1000,
        temperature=0.7,
        stream=True,
    )

    async for chunk in stream:
        delta = chunk.choices[0].delta.content
        if delta is not None:
            yield delta