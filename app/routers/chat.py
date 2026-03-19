from fastapi import APIRouter
from app.models.schemas import ChatRequest, ChatResponse
from app.core.llm_client import complete

router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
async def chat(request: ChatRequest) -> ChatResponse:
    """
    Main chat endpoint. Receives a message and returns the LLM response.
    Security layers will be added here in Phase 2.
    """
    # Call the LLM
    reply = await complete(request.message)

    return ChatResponse(
        reply=reply,
        flagged=False,
        injection_score=0.0,
        blocked=False
    )