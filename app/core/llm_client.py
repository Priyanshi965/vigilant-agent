from groq import AsyncGroq
from app.config import get_settings

settings = get_settings()

_client = AsyncGroq(api_key=settings.groq_api_key)


async def complete(prompt: str, system_prompt: str = None) -> str:
    """
    Send a prompt to the LLM and return the text response.
    This is the ONLY place in the project that talks to the LLM.
    """
    messages = []

    if system_prompt:
        messages.append({"role": "system", "content": system_prompt})

    messages.append({"role": "user", "content": prompt})

    response = await _client.chat.completions.create(
        model=settings.model_name,
        messages=messages,
        max_tokens=1000,
        temperature=0.7,
    )

    return response.choices[0].message.content.strip()