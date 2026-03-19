from fastapi import FastAPI
from app.routers import chat

app = FastAPI(
    title="Vigilant Agent",
    description="LLM Security Proxy Gateway",
    version="0.1.0"
)

# Health check
@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Vigilant Agent is running"}

# Register routers
app.include_router(chat.router)