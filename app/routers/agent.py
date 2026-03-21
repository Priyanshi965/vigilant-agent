import logging
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from app.agents.guard_agent import run_agent
from app.core.auth import get_current_user

logger = logging.getLogger(__name__)
router = APIRouter(tags=["agent"])


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
async def agent_run(
    request: AgentRequest,
    current_user: dict = Depends(get_current_user)
) -> AgentResponse:
    """
    Agentic endpoint with full security enforcement.
    CBAC → Validator → Execute
    Requires: valid JWT token in Authorization header.
    Role is taken from the authenticated token — not the request body.
    """
    # Use role from JWT token — never trust the request body for permissions
    authenticated_role = current_user["role"]
    user_id = current_user["username"]

    logger.info(
        f"Agent request from user={user_id} "
        f"role={authenticated_role} "
        f"tool={request.tool_name}"
    )

    result = await run_agent(
        user_request=request.user_request,
        tool_name=request.tool_name,
        tool_parameters=request.tool_parameters,
        user_role=authenticated_role  # ← from JWT, not request body
    )

    return AgentResponse(**result)