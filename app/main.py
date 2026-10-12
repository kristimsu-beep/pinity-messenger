import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import httpx
from fastapi import FastAPI, HTTPException, Depends, WebSocket, WebSocketDisconnect, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from pymongo import MongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

MONGODB_URI = os.getenv("MONGODB_URI", "")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "pinity_db")
SESSION_SECRET = os.getenv("SESSION_SECRET", "")
JWT_ALGORITHM = "HS256"
TOKEN_DAYS = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
bearer = HTTPBearer(auto_error=False)

app = FastAPI(title="Pinity Messenger API", version="0.1.0")
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

mongo_client = None
db = None
if MONGODB_URI:
    try:
        mongo_client = MongoClient(MONGODB_URI, serverSelectionTimeoutMS=5000)
        db = mongo_client[MONGODB_DATABASE]
        mongo_client.admin.command("ping")
        db.users.create_index("username_lower", unique=True)
        db.messages.create_index([("conversation_id", 1), ("created_at", -1)])
        db.contacts.create_index([("owner_id", 1), ("contact_id", 1)], unique=True)
        db.sessions.create_index("expires_at", expireAfterSeconds=0)
    except Exception as exc:
        print(f"MongoDB startup check failed: {exc}")
        db = None

# In-memory sockets are only for live delivery. Messages are persisted in MongoDB.
active_sockets: dict[str, set[WebSocket]] = {}

def require_db():
    if db is None:
        raise HTTPException(status_code=503, detail="Database unavailable. Set MONGODB_URI in Render.")
    return db

def make_token(user_id: str) -> str:
    if not SESSION_SECRET:
        raise HTTPException(status_code=503, detail="Set SESSION_SECRET in Render environment variables.")
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": user_id, "iat": now, "exp": now + timedelta(days=TOKEN_DAYS)}, SESSION_SECRET, algorithm=JWT_ALGORITHM)

def current_user(credentials: Optional[HTTPAuthorizationCredentials] = Depends(bearer)):
    database = require_db()
    if not credentials or not SESSION_SECRET:
        raise HTTPException(status_code=401, detail="Please sign in.")
    try:
        payload = jwt.decode(credentials.credentials, SESSION_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
    except JWTError:
        raise HTTPException(status_code=401, detail="Session expired. Please sign in again.")
    user = database.users.find_one({"_id": user_id}, {"password_hash": 0})
    if not user:
        raise HTTPException(status_code=401, detail="User not found.")
    return user

def public_user(user):
    return {
        "id": str(user["_id"]),
        "username": user.get("username", "User"),
        "display_name": user.get("display_name") or user.get("username", "User"),
        "avatar_url": user.get("avatar_url", ""),
        "banner_url": user.get("banner_url", ""),
        "status": user.get("status", "online"),
        "bio": user.get("bio", ""),
        "decoration": user.get("decoration", ""),
        "created_at": user.get("created_at", datetime.now(timezone.utc)).isoformat()
    }

class RegisterInput(BaseModel):
    username: str = Field(min_length=3, max_length=24)
    password: str = Field(min_length=8, max_length=128)
    display_name: Optional[str] = Field(default=None, max_length=40)

class LoginInput(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=128)

class MessageInput(BaseModel):
    conversation_id: str = Field(min_length=1, max_length=120)
    content: str = Field(min_length=1, max_length=6000)

class AIInput(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    history: list[dict] = Field(default_factory=list, max_length=20)

@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html")

@app.get("/health")
def health():
    mongo_ok = False
    if mongo_client is not None and db is not None:
        try:
            mongo_client.admin.command("ping")
            mongo_ok = True
        except Exception:
            pass
    return {"status": "ok", "service": "Pinity Messenger", "database": "connected" if mongo_ok else "not_configured_or_unavailable"}

@app.post("/api/auth/register")
def register(data: RegisterInput):
    database = require_db()
    username = data.username.strip()
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,24}", username):
        raise HTTPException(status_code=400, detail="Username may contain letters, numbers, _, . and -.")
    user_id = secrets.token_hex(12)
    now = datetime.now(timezone.utc)
    user = {
        "_id": user_id, "username": username, "username_lower": username.lower(),
        "display_name": (data.display_name or username).strip(),
        "password_hash": pwd_context.hash(data.password),
        "avatar_url": "", "banner_url": "", "bio": "", "status": "online",
        "decoration": "", "created_at": now
    }
    try:
        database.users.insert_one(user)
    except DuplicateKeyError:
        raise HTTPException(status_code=409, detail="That username is already taken.")
    # Each user gets a built-in Pinity AI contact immediately.
    database.contacts.update_one(
        {"owner_id": user_id, "contact_id": "pinity-ai"},
        {"$setOnInsert": {"owner_id": user_id, "contact_id": "pinity-ai", "kind": "bot", "created_at": now}},
        upsert=True
    )
    return {"token": make_token(user_id), "user": public_user(user)}

@app.post("/api/auth/login")
def login(data: LoginInput):
    database = require_db()
    user = database.users.find_one({"username_lower": data.username.strip().lower()})
    if not user or not pwd_context.verify(data.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Incorrect username or password.")
    database.users.update_one({"_id": user["_id"]}, {"$set": {"status": "online", "last_seen": datetime.now(timezone.utc)}})
    return {"token": make_token(str(user["_id"])), "user": public_user(user)}

@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return {"user": public_user(user)}

@app.post("/api/auth/logout")
def logout(user=Depends(current_user)):
    require_db().users.update_one({"_id": user["_id"]}, {"$set": {"status": "offline", "last_seen": datetime.now(timezone.utc)}})
    return {"ok": True}

@app.patch("/api/profile")
def update_profile(data: dict, user=Depends(current_user)):
    allowed = {"display_name", "bio", "avatar_url", "banner_url", "status", "decoration"}
    changes = {key: value for key, value in data.items() if key in allowed and isinstance(value, str)}
    if "display_name" in changes:
        changes["display_name"] = changes["display_name"][:40]
    if "bio" in changes:
        changes["bio"] = changes["bio"][:300]
    if changes:
        require_db().users.update_one({"_id": user["_id"]}, {"$set": changes})
    fresh = require_db().users.find_one({"_id": user["_id"]}, {"password_hash": 0})
    return {"user": public_user(fresh)}

@app.get("/api/contacts")
def contacts(user=Depends(current_user)):
    database = require_db()
    rows = list(database.contacts.find({"owner_id": user["_id"]}).sort("created_at", DESCENDING))
    output = []
    for row in rows:
        if row.get("contact_id") == "pinity-ai":
            output.append({"id": "pinity-ai", "username": "Pinity", "display_name": "Pinity AI", "kind": "bot", "status": "online", "avatar_url": ""})
        else:
            found = database.users.find_one({"_id": row["contact_id"]}, {"password_hash": 0})
            if found:
                output.append({**public_user(found), "kind": row.get("kind", "contact")})
    return {"contacts": output}

@app.get("/api/users/search")
def search_users(q: str = Query(min_length=1, max_length=40), user=Depends(current_user)):
    database = require_db()
    safe_q = re.escape(q.strip())
    rows = database.users.find({
        "username_lower": {"$regex": safe_q.lower()},
        "_id": {"$ne": user["_id"]}
    }, {"password_hash": 0}).limit(20)
    return {"users": [public_user(row) for row in rows]}

@app.post("/api/contacts/{contact_id}")
def add_contact(contact_id: str, user=Depends(current_user)):
    database = require_db()
    if contact_id == user["_id"]:
        raise HTTPException(status_code=400, detail="You cannot add yourself.")
    if contact_id != "pinity-ai" and not database.users.find_one({"_id": contact_id}):
        raise HTTPException(status_code=404, detail="User not found.")
    database.contacts.update_one(
        {"owner_id": user["_id"], "contact_id": contact_id},
        {"$setOnInsert": {"owner_id": user["_id"], "contact_id": contact_id, "kind": "contact", "created_at": datetime.now(timezone.utc)}},
        upsert=True
    )
    return {"ok": True}

@app.get("/api/messages")
def get_messages(conversation_id: str = Query(min_length=1, max_length=120), before: Optional[str] = None, user=Depends(current_user)):
    database = require_db()
    # MVP access rule: personal conversation IDs are sorted user IDs joined with ':'.
    # Server/channel authorization will be enforced by the community module.
    allowed = {user["_id"], "pinity-ai"}
    parts = conversation_id.split(":")
    if not (len(parts) == 2 and set(parts) == allowed):
        if user["_id"] not in parts:
            raise HTTPException(status_code=403, detail="Not allowed to view this conversation.")
    query = {"conversation_id": conversation_id}
    if before:
        query["_id"] = {"$lt": before}
    rows = list(database.messages.find(query).sort("created_at", DESCENDING).limit(60))
    rows.reverse()
    return {"messages": [{
        "id": str(m["_id"]), "conversation_id": m["conversation_id"],
        "sender_id": m["sender_id"], "sender_name": m.get("sender_name", "User"),
        "content": m["content"], "created_at": m["created_at"].isoformat()
    } for m in rows]}

@app.post("/api/messages")
async def send_message(data: MessageInput, user=Depends(current_user)):
    database = require_db()
    parts = data.conversation_id.split(":")
    if user["_id"] not in parts and data.conversation_id != f"{user['_id']}:pinity-ai":
        raise HTTPException(status_code=403, detail="Not allowed to send to this conversation.")
    now = datetime.now(timezone.utc)
    message = {
        "conversation_id": data.conversation_id, "sender_id": user["_id"],
        "sender_name": user.get("display_name") or user["username"],
        "content": data.content.strip(), "created_at": now
    }
    if not message["content"]:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")
    result = database.messages.insert_one(message)
    response = {"id": str(result.inserted_id), "conversation_id": data.conversation_id, "sender_id": user["_id"], "sender_name": message["sender_name"], "content": message["content"], "created_at": now.isoformat()}
    await broadcast(data.conversation_id, {"type": "message", "message": response})
    return response

async def broadcast(room: str, payload: dict):
    dead = []
    for ws in list(active_sockets.get(room, set())):
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        active_sockets.get(room, set()).discard(ws)

@app.websocket("/ws")
async def websocket_endpoint(ws: WebSocket, token: str = Query(default=""), conversation_id: str = Query(default="")):
    await ws.accept()
    try:
        if not token or not SESSION_SECRET or db is None:
            await ws.close(code=1008)
            return
        try:
            payload = jwt.decode(token, SESSION_SECRET, algorithms=[JWT_ALGORITHM])
            user_id = payload.get("sub")
        except JWTError:
            await ws.close(code=1008)
            return
        if not user_id or not conversation_id or user_id not in conversation_id.split(":"):
            await ws.close(code=1008)
            return
        active_sockets.setdefault(conversation_id, set()).add(ws)
        await ws.send_json({"type": "ready"})
        while True:
            # Keepalive only. Messages are sent through authenticated HTTP endpoints.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    finally:
        active_sockets.get(conversation_id, set()).discard(ws)

@app.post("/api/ai/chat")
async def ai_chat(data: AIInput, user=Depends(current_user)):
    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise HTTPException(status_code=503, detail="Pinity AI is not configured yet. Add GROQ_API_KEY in Render.")
    model = os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile")
    history = []
    for item in data.history[-12:]:
        role = item.get("role")
        content = item.get("content")
        if role in {"user", "assistant"} and isinstance(content, str):
            history.append({"role": role, "content": content[:8000]})
    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are Pinity, a friendly and capable assistant inside the Pinity Messenger. Be helpful, clear, and concise. You cannot claim to have generated an image unless the image tool succeeded."},
            *history,
            {"role": "user", "content": data.message}
        ],
        "temperature": 0.7,
        "max_tokens": 1800
    }
    async with httpx.AsyncClient(timeout=60) as client:
        response = await client.post(
            "https://api.groq.com/openai/v1/chat/completions",
            headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
            json=payload
        )
    if response.status_code >= 400:
        print(f"Groq error {response.status_code}: {response.text[:500]}")
        raise HTTPException(status_code=502, detail="Pinity AI could not answer right now.")
    result = response.json()
    answer = result.get("choices", [{}])[0].get("message", {}).get("content", "")
    now = datetime.now(timezone.utc)
    database = require_db()
    database.ai_history.insert_one({"user_id": user["_id"], "role": "user", "content": data.message, "created_at": now})
    database.ai_history.insert_one({"user_id": user["_id"], "role": "assistant", "content": answer, "created_at": now})
    conversation_id = f"{user['_id']}:pinity-ai"
    database.messages.insert_one({
        "conversation_id": conversation_id, "sender_id": "pinity-ai",
        "sender_name": "Pinity AI", "content": answer, "created_at": now
    })
    return {"reply": answer, "model": model}

@app.post("/api/ai/image")
async def ai_image(data: AIInput, user=Depends(current_user)):
    account_id = os.getenv("CLOUDFLARE_ACCOUNT_ID", "")
    api_token = os.getenv("CLOUDFLARE_API_KEY", "")
    if not account_id or not api_token:
        raise HTTPException(status_code=503, detail="Image generation is not configured. Add Cloudflare credentials in Render.")
    model = os.getenv("CLOUDFLARE_IMAGE_MODEL", "@cf/black-forest-labs/flux-1-schnell")
    url = f"https://api.cloudflare.com/client/v4/accounts/{account_id}/ai/run/{model}"
    async with httpx.AsyncClient(timeout=120) as client:
        response = await client.post(url, headers={"Authorization": f"Bearer {api_token}"}, json={"prompt": data.message})
    if response.status_code >= 400:
        print(f"Cloudflare image error {response.status_code}: {response.text[:500]}")
        raise HTTPException(status_code=502, detail="Image generation failed. Check Cloudflare model access and token permissions.")
    content_type = response.headers.get("content-type", "")
    if "image/" not in content_type:
        result = response.json()
        raise HTTPException(status_code=502, detail=result.get("errors", [{"message": "Unexpected image response"}])[0].get("message", "Unexpected image response"))
    # Return the generated image directly; frontend can display it as a blob.
    from fastapi.responses import Response
    return Response(content=response.content, media_type=content_type, headers={"Cache-Control": "no-store"})
