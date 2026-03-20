from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from prometheus_fastapi_instrumentator import Instrumentator
from app.routers import chat, agent
from app.middleware.logging_mw import LoggingMiddleware

app = FastAPI(
    title="Vigilant Agent",
    description="LLM Security Proxy Gateway",
    version="0.1.0"
)

# Allow browser requests from local HTML files
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Expose /metrics endpoint
Instrumentator().instrument(app).expose(app)

# Register middleware
app.add_middleware(LoggingMiddleware)

# Health check
@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Vigilant Agent is running"}

@app.get("/stats")
async def stats():
    from app.routers.chat import BLOCKED_REQUESTS, PII_REDACTED
    return {
        "blocked_requests_total": int(BLOCKED_REQUESTS._value.get()),
        "pii_redacted_total": int(PII_REDACTED._value.get()),
    }

app.include_router(chat.router)
app.include_router(agent.router)