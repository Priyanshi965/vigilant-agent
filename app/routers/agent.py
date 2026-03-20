import logging
from fastapi import APIRouter
from pydantic import BaseModel
from app.agents.guard_agent import run_agent

logger = logging.getLogger(__name__)
router = APIRouter()


class AgentRequest(BaseModel):
    user_request: str
    tool_name: str
    tool_parameters: dict = {}
    user_role: str = "readonly"


class AgentResponse(BaseModel):
    success: bool
    blocked: bool
    reason: str
    output: str | None = None


@router.post("/agent/run", response_model=AgentResponse)
async def agent_run(request: AgentRequest) -> AgentResponse:
    """
    Agentic endpoint with full security enforcement.
    CBAC → Validator → Execute
    """
    result = await run_agent(
        user_request=request.user_request,
        tool_name=request.tool_name,
        tool_parameters=request.tool_parameters,
        user_role=request.user_role
    )

    return AgentResponse(**result)