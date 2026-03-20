import logging
from fastapi import APIRouter
from app.models.schemas import ChatRequest, ChatResponse
from app.core.llm_client import complete
from app.core.guard import score_prompt, is_suspicious

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Main chat endpoint. Receives a message and returns the LLM response.
    Phase 1: Scores every message but does not block yet (log-only mode).
    Phase 2: Blocking will be enabled here.
    """
    # Score the incoming message
    injection_score = score_prompt(request.message)
    flagged = is_suspicious(request.message)

    # Log the score — this is our data collection
    if flagged:
        logger.warning(
            f"SUSPICIOUS message from user={request.user_id} "
            f"score={injection_score:.2f} "
            f"preview={request.message[:50]!r}"
        )
    else:
        logger.info(
            f"Clean message from user={request.user_id} "
            f"score={injection_score:.2f}"
        )

    # Phase 1: Pass ALL messages through (no blocking yet)
    reply = await complete(request.message)

    return ChatResponse(
        reply=reply,
        flagged=flagged,
        injection_score=injection_score,
        blocked=False
    )