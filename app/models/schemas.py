from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="The user's message to the AI"
    )
    user_id: str = Field(
        default="anonymous",
        description="Identifier for the user sending the message"
    )


class ChatResponse(BaseModel):
    reply: str = Field(description="The AI's response")
    flagged: bool = Field(
        default=False,
        description="True if the message was flagged as suspicious"
    )
    injection_score: float = Field(
        default=0.0,
        description="Suspicion score between 0.0 (safe) and 1.0 (injection)"
    )
    blocked: bool = Field(
        default=False,
        description="True if the request was blocked by security policy"
    )


class ErrorResponse(BaseModel):
    error: str = Field(description="Human-readable error message")
    code: str = Field(description="Machine-readable error code")
    
    