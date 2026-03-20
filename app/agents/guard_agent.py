import logging
from app.agents.action_agent import (
    execute_tool, ToolCall, ToolName,
    SAFE_TOOLS, DANGEROUS_TOOLS, ToolResult
)
from app.core.validator import validate_action

logger = logging.getLogger(__name__)

# Role-based access control
# readonly: can only use safe tools
# operator: can use all tools but dangerous ones need validation
# admin: same as operator for now
ROLE_PERMISSIONS = {
    "readonly": SAFE_TOOLS,
    "operator": SAFE_TOOLS | DANGEROUS_TOOLS,
    "admin": SAFE_TOOLS | DANGEROUS_TOOLS,
}


async def run_agent(
    user_request: str,
    tool_name: str,
    tool_parameters: dict,
    user_role: str = "readonly"
) -> dict:
    """
    Central agent runner with security enforcement.

    Pipeline:
    1. Check role permissions (CBAC)
    2. If dangerous tool → run validator
    3. If approved → execute
    4. If rejected → block
    """
    # Step 1 — Parse tool name
    try:
        tool = ToolName(tool_name)
    except ValueError:
        return {
            "success": False,
            "blocked": True,
            "reason": f"Unknown tool: {tool_name}",
            "output": None
        }

    # Step 2 — Check role permissions (CBAC)
    allowed_tools = ROLE_PERMISSIONS.get(user_role, SAFE_TOOLS)
    if tool not in allowed_tools:
        logger.warning(
            f"CBAC BLOCKED: user_role={user_role!r} "
            f"attempted tool={tool_name!r}"
        )
        return {
            "success": False,
            "blocked": True,
            "reason": f"Role '{user_role}' is not permitted to use '{tool_name}'",
            "output": None
        }

    # Step 3 — If dangerous, run through validator
    if tool in DANGEROUS_TOOLS:
        logger.info(
            f"Dangerous tool requested: {tool_name!r} "
            f"— sending to validator"
        )
        approved, reason = await validate_action(
            original_request=user_request,
            planned_action=tool_name,
            action_details=str(tool_parameters)
        )

        if not approved:
            logger.warning(
                f"VALIDATOR BLOCKED: tool={tool_name!r} "
                f"request={user_request!r} "
                f"reason={reason!r}"
            )
            return {
                "success": False,
                "blocked": True,
                "reason": f"Action blocked by validator: {reason}",
                "output": None
            }

        logger.info(f"Validator APPROVED: tool={tool_name!r}")

    # Step 4 — Execute the tool
    call = ToolCall(tool=tool, parameters=tool_parameters)
    result: ToolResult = execute_tool(call)

    return {
        "success": result.success,
        "blocked": False,
        "reason": "Executed successfully" if result.success else "Tool execution failed",
        "output": result.output
    }