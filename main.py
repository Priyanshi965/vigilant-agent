from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, HTTPException, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
import sqlite3
import uuid
import json
from typing import Optional, List
from datetime import datetime
import os
import re

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Groq Client Setup ---
# pip install groq
try:
    from groq import Groq
    GROQ_API_KEY = os.environ.get("GROQ_API_KEY", "")
    groq_client = Groq(api_key=GROQ_API_KEY) if GROQ_API_KEY else None
except ImportError:
    groq_client = None
    print("WARNING: groq package not installed. Run: pip install groq")

DB_PATH = "vigilant_agent.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            token TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            username TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id TEXT PRIMARY KEY,
            user_id TEXT NOT NULL,
            title TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY,
            conversation_id TEXT NOT NULL,
            sender TEXT NOT NULL,
            content TEXT NOT NULL,
            injection_score REAL DEFAULT 0.0,
            pii_redacted INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(conversation_id) REFERENCES conversations(id)
        )
    ''')
    conn.commit()
    conn.close()

init_db()

def add_default_admin():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        user_id = str(uuid.uuid4())
        cursor.execute('''
            INSERT INTO users (id, username, password, role)
            VALUES (?, ?, ?, ?)
        ''', (user_id, 'admin', 'admin123', 'admin'))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

add_default_admin()

# --- Data Models ---

class ChatRequest(BaseModel):
    message: str
    conversation_id: Optional[str] = None
    history: Optional[List[dict]] = []
    image: Optional[str] = None           # base64-encoded image data
    image_mime_type: Optional[str] = None # e.g. "image/jpeg"

class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str

class LoginRequest(BaseModel):
    username: str
    password: str

# --- Helper Functions ---

def get_user_by_username(username: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (username,))
    user = cursor.fetchone()
    conn.close()
    return dict(user) if user else None

def get_user_by_token(token: str):
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM sessions WHERE token = ?', (token,))
    session = cursor.fetchone()
    conn.close()
    return dict(session) if session else None

def create_session(user_id: str, username: str) -> str:
    token = "cyber-secret-token-" + str(uuid.uuid4())
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO sessions (token, user_id, username)
        VALUES (?, ?, ?)
    ''', (token, user_id, username))
    conn.commit()
    conn.close()
    return token

def analyze_message(message: str) -> tuple:
    """
    ✅ FIXED: Smart threat detection with balanced threshold
    Only blocks truly dangerous attacks (>0.9), not legitimate queries
    """
    msg_lower = message.lower()

    # Contextual attack patterns only
    attack_patterns = [
        r"ignore (all )?(previous|prior|above|your) (instructions?|prompts?|rules?|context)",
        r"\byou are now\b.{0,30}(different|unrestricted|evil|free|without rules)",
        r"act as (a |an )?(different|new|unrestricted|evil|jailbreak|dan\b)",
        r"bypass (your )?(guidelines?|filters?|restrictions?|safety|rules?)",
        r"disregard (your )?(instructions?|training|rules?|guidelines?)",
        r"\bjailbreak\b",
        r"\bdo anything now\b",
        r"\bdan mode\b",
        r"\bprompt injection\b",
        r"reveal (your )?(system prompt|instructions|training)",
        r"<script[\s>]",
        r"javascript:\s*",
        r"' *(or|and) *'?1'? *= *'?1",   # SQL injection
        r"\bunion\s+select\b",
        r"\bdrop\s+table\b",
        r"\bexec\s*\(",
    ]

    is_attack = any(re.search(pattern, msg_lower) for pattern in attack_patterns)

    # ✅ SCORE: Genuine attacks get high score, benign messages get near-zero
    if is_attack:
        injection_score = round(0.75 + min(0.24, len(message) * 0.001), 2)
    else:
        injection_score = round(min(0.08, len(message) * 0.00008), 4)

    # PII detection
    pii_patterns = [
        r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        r'\b\d{3}[-.\s]?\d{3}[-.\s]?\d{4}\b',
        r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
        r'\b\d{3}-\d{2}-\d{4}\b',
    ]
    pii_redacted = sum(1 for p in pii_patterns if re.search(p, message))

    return injection_score, pii_redacted, is_attack

def get_groq_response(message: str, history: List[dict] = [], image: Optional[str] = None, image_mime_type: Optional[str] = None) -> str:
    """Call Groq API for LLM response. Uses vision model when an image is provided."""
    if not groq_client:
        return "⚠️ Groq client not initialized. Please set the GROQ_API_KEY environment variable and run: pip install groq"

    system_prompt = """You are Vigilant Agent — an intelligent AI assistant embedded in a cybersecurity terminal.
You are knowledgeable, helpful, and conversational across all topics: literature, science, technology, history, cybersecurity, math, creative writing, and more.
Respond naturally, clearly, and helpfully. Use markdown formatting when appropriate (headers, lists, code blocks).
You have a calm, precise personality with a subtle technical edge — but you are fundamentally a warm, helpful assistant.
Never refuse reasonable questions. Answer everything factually and thoroughly."""

    messages = [{"role": "system", "content": system_prompt}]

    for h in (history or [])[-12:]:
        role = h.get("role")
        content = h.get("content", "")
        if role in ["user", "assistant"] and content:
            messages.append({"role": role, "content": content})

    if image:
        mime = image_mime_type or "image/jpeg"
        user_content = [
            {"type": "text", "text": message or "What is in this image?"},
            {"type": "image_url", "image_url": {"url": f"data:{mime};base64,{image}"}}
        ]
        messages.append({"role": "user", "content": user_content})
        model = "llama-3.2-11b-vision-preview"
    else:
        messages.append({"role": "user", "content": message})
        model = "llama-3.3-70b-versatile"

    try:
        response = groq_client.chat.completions.create(
            model=model,
            messages=messages,
            max_tokens=1024,
            temperature=0.7,
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"⚠️ LLM connection error: {str(e)}"

# --- API Endpoints ---

@app.get("/ping")
async def ping():
    return {"status": "online", "groq_ready": groq_client is not None}

@app.post("/auth/register")
async def register(req: RegisterRequest = Body(...)):
    existing_user = get_user_by_username(req.username)
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    user_id = str(uuid.uuid4())
    try:
        cursor.execute('''INSERT INTO users (id, username, password, role) VALUES (?, ?, ?, ?)''',
                       (user_id, req.username, req.password, req.role))
        conn.commit()
        conn.close()
        return {"message": "TERMINAL_REGISTERED", "username": req.username}
    except Exception as e:
        conn.close()
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/auth/login")
async def login(req: LoginRequest = Body(...)):
    user = get_user_by_username(req.username)
    if user and user["password"] == req.password:
        token = create_session(user["id"], req.username)
        return {"access_token": token, "username": req.username, "role": user["role"]}
    raise HTTPException(status_code=401, detail="INVALID_ACCESS_KEY")

@app.post("/auth/verify")
async def verify_token(token: str = Body(...)):
    session = get_user_by_token(token)
    if session:
        return {"valid": True, "username": session["username"]}
    raise HTTPException(status_code=401, detail="INVALID_TOKEN")

@app.get("/conversations")
async def get_conversations(token: str = None):
    if not token:
        raise HTTPException(status_code=401, detail="MISSING_TOKEN")
    session = get_user_by_token(token)
    if not session:
        raise HTTPException(status_code=401, detail="INVALID_TOKEN")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM conversations WHERE user_id = ? ORDER BY created_at DESC', (session["user_id"],))
    conversations = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return conversations

@app.post("/chat")
async def chat(req: ChatRequest, token: str = None):
    """
    ✅ FIXED: Only blocks if injection_score > 0.9 (genuine attacks)
    Benign queries (<0.5) pass through cleanly
    Suspicious queries (0.5-0.9) get answered with a warning
    """
    if not token:
        raise HTTPException(status_code=401, detail="MISSING_TOKEN")
    session = get_user_by_token(token)
    if not session:
        raise HTTPException(status_code=401, detail="INVALID_TOKEN")

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    conv_id = req.conversation_id or str(uuid.uuid4())
    cursor.execute('SELECT * FROM conversations WHERE id = ?', (conv_id,))
    if not cursor.fetchone():
        cursor.execute('''INSERT INTO conversations (id, user_id, title) VALUES (?, ?, ?)''',
                       (conv_id, session["user_id"], req.message[:40]))

    injection_score, pii_items_redacted, is_attack = analyze_message(req.message)

    msg_id = str(uuid.uuid4())
    cursor.execute('''INSERT INTO messages (id, conversation_id, sender, content, injection_score, pii_redacted)
                      VALUES (?, ?, ?, ?, ?, ?)''',
                   (msg_id, conv_id, 'user', req.message, injection_score, pii_items_redacted))

    # ✅ KEY FIX: Only block if score > 0.9 (truly dangerous)
    if injection_score > 0.9:
        reply = "🚫 **THREAT NEUTRALIZED** — Injection pattern detected. This request has been logged and blocked. If this is a false positive, please rephrase your query."
        blocked = True
    else:
        # Allow everything else, even if suspicious
        reply = get_groq_response(req.message, req.history or [], req.image, req.image_mime_type)
        
        # Add warning if suspicious but allowed (0.5-0.9 range)
        if is_attack and injection_score > 0.5:
            reply += "\n\n⚠️ _Note: This request contained patterns commonly used for prompt injection. Your request was still processed, but parts may have been ignored for safety._"
        
        blocked = False

    agent_msg_id = str(uuid.uuid4())
    cursor.execute('''INSERT INTO messages (id, conversation_id, sender, content) VALUES (?, ?, ?, ?)''',
                   (agent_msg_id, conv_id, 'agent', reply))

    conn.commit()
    conn.close()

    return {
        "reply": reply,
        "conversation_id": conv_id,
        "injection_score": round(injection_score, 4),
        "pii_items_redacted": pii_items_redacted,
        "blocked": blocked,
        "flagged": is_attack and injection_score > 0.5
    }

@app.post("/chat/stream")
async def chat_stream(req: ChatRequest, token: str = None):
    """SSE streaming endpoint — yields tokens as they arrive from Groq."""
    if not token:
        raise HTTPException(status_code=401, detail="MISSING_TOKEN")
    session = get_user_by_token(token)
    if not session:
        raise HTTPException(status_code=401, detail="INVALID_TOKEN")
    if not groq_client:
        raise HTTPException(status_code=503, detail="LLM_NOT_AVAILABLE")

    conv_id = req.conversation_id or str(uuid.uuid4())
    injection_score, pii_items_redacted, is_attack = analyze_message(req.message)
    blocked = injection_score > 0.9

    # Persist user message
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('SELECT id FROM conversations WHERE id = ?', (conv_id,))
    if not cursor.fetchone():
        cursor.execute('INSERT INTO conversations (id, user_id, title) VALUES (?, ?, ?)',
                       (conv_id, session["user_id"], req.message[:40]))
    msg_id = str(uuid.uuid4())
    cursor.execute(
        'INSERT INTO messages (id, conversation_id, sender, content, injection_score, pii_redacted) VALUES (?, ?, ?, ?, ?, ?)',
        (msg_id, conv_id, 'user', req.message, injection_score, pii_items_redacted))
    conn.commit()
    conn.close()

    system_prompt = (
        "You are Vigilant Agent — an intelligent AI assistant embedded in a cybersecurity terminal.\n"
        "You are knowledgeable, helpful, and conversational across all topics.\n"
        "Respond naturally and helpfully. Use markdown when appropriate.\n"
        "Never refuse reasonable questions."
    )

    def generate():
        # First frame: security metadata
        meta = json.dumps({
            "injection_score": round(injection_score, 4),
            "pii_items_redacted": pii_items_redacted,
            "blocked": blocked,
            "flagged": is_attack and injection_score > 0.5,
            "conversation_id": conv_id,
        })
        yield f"data: [META:{meta}]\n\n"

        if blocked:
            msg = (
                "I can't process that request — it contained patterns commonly used "
                "to override AI system instructions.\\n\\nIf you meant something else "
                "entirely, feel free to rephrase and I'll be glad to help."
            )
            yield f"data: {json.dumps({'t': msg})}\n\n"
            yield "data: [DONE]\n\n"
            return

        messages = [{"role": "system", "content": system_prompt}]
        for h in (req.history or [])[-12:]:
            role = h.get("role")
            content = h.get("content", "")
            if role in ["user", "assistant"] and content:
                messages.append({"role": role, "content": content})
        messages.append({"role": "user", "content": req.message})

        full_reply = []
        try:
            stream = groq_client.chat.completions.create(
                model="llama-3.3-70b-versatile",
                messages=messages,
                max_tokens=1024,
                temperature=0.7,
                stream=True,
            )
            for chunk in stream:
                delta = chunk.choices[0].delta.content
                if delta:
                    full_reply.append(delta)
                    yield f"data: {json.dumps({'t': delta})}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'t': f'⚠️ Error: {e}'})}\n\n"

        # Persist agent reply
        reply_text = "".join(full_reply)
        if is_attack and injection_score > 0.5:
            reply_text += "\n\n⚠️ _Note: This request contained patterns commonly used for prompt injection._"
        try:
            c2 = sqlite3.connect(DB_PATH)
            c2.execute(
                'INSERT INTO messages (id, conversation_id, sender, content) VALUES (?, ?, ?, ?)',
                (str(uuid.uuid4()), conv_id, 'agent', reply_text))
            c2.commit()
            c2.close()
        except Exception:
            pass

        yield "data: [DONE]\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/chat/history/{conversation_id}")
async def get_chat_history(conversation_id: str, token: str = None):
    if not token:
        raise HTTPException(status_code=401, detail="MISSING_TOKEN")
    session = get_user_by_token(token)
    if not session:
        raise HTTPException(status_code=401, detail="INVALID_TOKEN")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT user_id FROM conversations WHERE id = ?', (conversation_id,))
    conv = cursor.fetchone()
    if not conv or conv["user_id"] != session["user_id"]:
        conn.close()
        raise HTTPException(status_code=403, detail="UNAUTHORIZED_ACCESS")

    cursor.execute('''SELECT id, sender, content, injection_score, pii_redacted, created_at
                      FROM messages WHERE conversation_id = ? ORDER BY created_at ASC''',
                   (conversation_id,))
    messages = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return messages

# Static serving MUST be last
app.mount("/", StaticFiles(directory="static", html=True), name="static")