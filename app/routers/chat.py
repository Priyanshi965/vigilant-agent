import logging
from fastapi import APIRouter, HTTPException
from app.models.schemas import ChatRequest, ChatResponse
from app.core.llm_client import complete
from app.core.guard import score_prompt, is_suspicious
from app.core.normalizer import normalize

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Main chat endpoint.
    Pipeline: Normalize → Score → Block/Allow → LLM
    """
    # Step 1 — Normalize (strip invisible chars, fix unicode)
    clean_message = normalize(request.message)

    # Step 2 — Score the cleaned message
    injection_score = score_prompt(clean_message)
    flagged = is_suspicious(clean_message)

    # Step 3 — Block if flagged
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

    # Step 4 — Safe, send cleaned message to LLM
    logger.info(
        f"Clean message from user={request.user_id} "
        f"score={injection_score:.2f}"
    )

    reply = await complete(clean_message)

    return ChatResponse(
        reply=reply,
        flagged=False,
        injection_score=injection_score,
        blocked=False
    )