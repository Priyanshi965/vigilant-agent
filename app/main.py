from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from prometheus_fastapi_instrumentator import Instrumentator
from app.routers import chat, agent, auth, conversations
from app.middleware.logging_mw import LoggingMiddleware
from app.database import engine, Base
from app.models import db_models

# Create all database tables on startup
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Vigilant Agent",
    description="LLM Security Proxy Gateway",
    version="0.2.0"
)

# CORS — allow browser requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Prometheus metrics
Instrumentator().instrument(app).expose(app)

# Logging middleware
app.add_middleware(LoggingMiddleware)

# Serve chat UI at /
@app.get("/", include_in_schema=False)
async def serve_ui():
    return FileResponse("app/static/index.html")

# Health check
@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Vigilant Agent is running", "version": "0.2.0"}

# Stats
@app.get("/stats")
async def stats():
    from app.routers.chat import BLOCKED_REQUESTS, PII_REDACTED
    return {
        "blocked_requests_total": int(BLOCKED_REQUESTS._value.get()),
        "pii_redacted_total": int(PII_REDACTED._value.get()),
    }

# Classifier mode
@app.get("/classifier-mode")
async def classifier_mode():
    from app.core.guard import get_classifier_mode
    return {"mode": get_classifier_mode()}

# Routers
app.include_router(auth.router)
app.include_router(chat.router, tags=["chat"])
app.include_router(agent.router, tags=["agent"])
app.include_router(conversations.router)