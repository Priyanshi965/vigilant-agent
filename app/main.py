from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from prometheus_fastapi_instrumentator import Instrumentator
from app.routers import chat, agent, auth, conversations
from app.middleware.logging_mw import LoggingMiddleware
from app.middleware.rate_limit import limiter, rate_limit_error_handler
from app.database import engine, Base
from app.models import db_models
from slowapi.errors import RateLimitExceeded
from pathlib import Path

Base.metadata.create_all(bind=engine)

BASE_DIR = Path(__file__).resolve().parent
static_dir = BASE_DIR / "static"

app = FastAPI(title="Vigilant Agent API")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, rate_limit_error_handler)

# Setup CORS so the frontend can communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Instrumentator().instrument(app).expose(app)

app.add_middleware(LoggingMiddleware)

app.include_router(auth.router)
app.include_router(chat.router)
app.include_router(agent.router)
app.include_router(conversations.router)

if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

@app.get("/")
async def root():
    return {"status": "online", "message": "Vigilant Agent Security Proxy V2"}
@app.get("/auth.html", include_in_schema=False)
async def serve_auth():
    return FileResponse(static_dir / "auth.html")

@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(static_dir / "logo.png")

@app.get("/ping")
async def ping():
    return {"status": "ok", "message": "Vigilant Agent is running", "version": "0.3.0"}

@app.get("/stats")
async def stats():
    from app.routers.chat import BLOCKED_REQUESTS, PII_REDACTED
    return {
        "blocked_requests_total": int(BLOCKED_REQUESTS._value.get()),
        "pii_redacted_total": int(PII_REDACTED._value.get()),
    }

@app.get("/classifier-mode")
async def classifier_mode():
    from app.core.guard import get_classifier_mode
    return {"mode": get_classifier_mode()}