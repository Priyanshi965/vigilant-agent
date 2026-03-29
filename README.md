# Vigilant Agent

An intelligent, production-ready AI security gateway. Vigilant Agent is a FastAPI-based proxy for LLMs (Groq) with built-in prompt injection detection, PII redaction, JWT authentication, image understanding, and a full cybersecurity-themed chat UI.

---

## Features

- **Prompt Injection Detection** — regex + ML classifier blocks >0.9-score attacks, flags 0.5–0.9 with a warning, passes everything else cleanly
- **PII Redaction** — detects emails, phone numbers, credit cards, SSNs before they reach the LLM
- **JWT Authentication** — register/login with hashed passwords, Bearer token auth on all endpoints
- **Multimodal Chat** — attach images; automatically routes to `llama-3.2-11b-vision-preview`, text-only uses `llama-3.3-70b-versatile`
- **Conversation History** — SQLite-backed, per-user conversation and message persistence
- **Security Audit Trail** — every request logged with injection score and PII count
- **Rate Limiting & Alert Middleware** — pluggable middleware for request rate limits and security alerts
- **Docker Compose** — app + Prometheus + Grafana in one command
- **Full Chat UI** — ChatGPT-style interface with avatars, collapsible security analysis per message, image preview, session sidebar

---

## Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+, FastAPI, SQLAlchemy, SQLite |
| LLM | Groq Cloud (`llama-3.3-70b-versatile`, `llama-3.2-11b-vision-preview`) |
| Auth | JWT (`python-jose`), bcrypt (`passlib`) |
| Security | `protectai/deberta-v3-base-prompt-injection-v2` (ML), regex fallback |
| Frontend | Tailwind CSS, marked.js, highlight.js, JetBrains Mono |
| DevOps | Docker, Docker Compose, Prometheus |
| Testing | Pytest |

---

## Quick Start

### 1. Clone and install

```bash
git clone https://github.com/Priyanshi965/vigilant-agent.git
cd vigilant-agent
python -m venv venv
# Windows:
.\venv\Scripts\Activate.ps1
# macOS/Linux:
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure environment

Copy `.env.example` to `.env` and fill in your keys:

```env
GROQ_API_KEY=your_groq_key_here
SECRET_KEY=any-long-random-string
TOKEN_EXPIRE_HOURS=24
```

Get a free Groq API key at [console.groq.com](https://console.groq.com).

### 3. Run

```bash
python -m uvicorn main:app --reload --port 8000


## Run with Docker

```bash
docker-compose up --build
```

- App: [http://localhost:8000](http://localhost:8000)
- Prometheus: [http://localhost:9090](http://localhost:9090)
- Grafana: [http://localhost:3000](http://localhost:3000)

---

## Project Structure

```
vigilant-agent/
├── main.py                  # Standalone server (Groq + SQLite, no dependencies)
├── static/
│   └── index.html           # Full chat UI
├── app/
│   ├── main.py              # FastAPI app factory (JWT server)
│   ├── config.py
│   ├── database.py
│   ├── core/
│   │   ├── auth.py          # JWT helpers
│   │   ├── guard.py         # Prompt injection detection
│   │   ├── redactor.py      # PII detection & redaction
│   │   ├── llm_client.py    # Groq client (text + vision)
│   │   ├── alerts.py        # Security alert system
│   │   └── memory.py        # Conversation memory
│   ├── middleware/
│   │   ├── alerts.py        # Request-level alert middleware
│   │   └── rate_limit.py    # Rate limiting middleware
│   ├── models/
│   │   ├── db_models.py     # SQLAlchemy ORM models
│   │   └── schemas.py       # Pydantic request/response schemas
│   └── routers/
│       ├── auth.py          # /auth/register, /auth/login, /auth/me
│       ├── chat.py          # /chat
│       └── conversations.py # /conversations, /chat/history/{id}
├── tests/
│   └── test_chat_endpoint.py
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── .env.example
```

---

## API Endpoints

| Method | Path | Auth | Description |
|---|---|---|---|
| GET | `/ping` | — | Health check |
| POST | `/auth/register` | — | Create account |
| POST | `/auth/login` | — | Get token |
| POST | `/chat?token=` | token | Send message (text or image) |
| GET | `/conversations?token=` | token | List conversations |
| GET | `/chat/history/{id}?token=` | token | Message history |

---

## Environment Variables

| Variable | Required | Description |
|---|---|---|
| `GROQ_API_KEY` | Yes | Groq Cloud API key |
| `SECRET_KEY` | Yes | JWT signing secret |
| `TOKEN_EXPIRE_HOURS` | No | Token lifetime (default 24) |
| `DATABASE_URL` | No | SQLAlchemy URL (default SQLite) |

---

## Running Tests

```bash
pytest tests/ -v
```
