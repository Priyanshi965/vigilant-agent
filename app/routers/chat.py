import logging
from fastapi import APIRouter, HTTPException
from app.models.schemas import ChatRequest, ChatResponse
from app.core.llm_client import complete
from app.core.guard import score_prompt, is_suspicious

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Main chat endpoint.
    Phase 2: Blocks suspicious messages before they reach the LLM.
    """
    # Step 1 — Score the message
    injection_score = score_prompt(request.message)
    flagged = is_suspicious(request.message)

    # Step 2 — BLOCK if score exceeds threshold
    if flagged:
        logger.warning(
            f"BLOCKED request from user={request.user_id} "
            f"score={injection_score:.2f} "
            f"preview={request.message[:50]!r}"
        )
        # Return 403 — do NOT reveal the score to the caller
        raise HTTPException(
            status_code=403,
            detail={
                "error": "Request blocked by security policy",
                "code": "INJECTION_DETECTED"
            }
        )

    # Step 3 — Safe message, pass to LLM
    logger.info(
        f"Clean message from user={request.user_id} "
        f"score={injection_score:.2f}"
    )

    reply = await complete(request.message)

    return ChatResponse(
        reply=reply,
        flagged=False,
        injection_score=injection_score,
        blocked=False
    )