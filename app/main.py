from fastapi import FastAPI
from app.routers import chat
from app.routers import agent
from app.middleware.logging_mw import LoggingMiddleware

app = FastAPI(
    title="Vigilant Agent",
    description="LLM Security Proxy Gateway",
    version="0.1.0"
)

# Register middleware
app.add_middleware(LoggingMiddleware)

# Health check
@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Vigilant Agent is running"}

# Register routers
app.include_router(chat.router)
app.include_router(agent.router)