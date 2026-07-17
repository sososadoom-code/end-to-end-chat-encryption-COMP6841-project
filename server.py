"""
COMP6841 Project — Backend (Phase 1: accounts + plaintext relay)

This is a single backend process built with aiohttp, handling three jobs:

  1. POST /api/register  - create an account (username + password)
  2. POST /api/login      - verify credentials, issue a session token
  3. GET  /ws?token=...   - upgrade to a WebSocket once authenticated,
                            and relay chat messages between whichever
                            users are online.


Chat message content  is still NOT encrypted yet (Phase 1). The
server can read every message any user sends.
"""

import hashlib
import json
import logging
import os
import secrets
import time
from pathlib import Path

from aiohttp import web, WSMsgType

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("server")

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
USERS_FILE = BASE_DIR / "users.json"
MESSAGES_FILE = BASE_DIR / "messages.json"

# token -> username
sessions: dict[str, str] = {}
# username -> websocket
online: dict[str, web.WebSocketResponse] = {}


# message history storage

def load_messages() -> list[dict]:
    if MESSAGES_FILE.exists():
        return json.loads(MESSAGES_FILE.read_text())
    return []


def save_messages(messages: list[dict]) -> None:
    MESSAGES_FILE.write_text(json.dumps(messages, indent=2))


def append_message(sender: str, recipient: str, text: str) -> None:
    messages = load_messages()
    messages.append({"from": sender, "to": recipient, "text": text, "time": time.time()})
    save_messages(messages)


def history_for(username: str) -> list[dict]:
    messages = load_messages()
    return [m for m in messages if m["from"] == username or m["to"] == username]


# password storage

def load_users() -> dict:
    if USERS_FILE.exists():
        return json.loads(USERS_FILE.read_text())
    return {}


def save_users(users: dict) -> None:
    USERS_FILE.write_text(json.dumps(users, indent=2))


def hash_password(password: str, salt: bytes | None = None) -> tuple[str, str]:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex(), digest.hex()


def verify_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    salt = bytes.fromhex(salt_hex)
    _, digest_hex = hash_password(password, salt)
    return secrets.compare_digest(digest_hex, hash_hex)


# HTTP handlers 

async def register(request: web.Request) -> web.Response:
    data = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    if not username or not password:
        return web.json_response({"error": "username and password required"}, status=400)

    users = load_users()
    if username in users:
        return web.json_response({"error": "username already taken"}, status=400)

    salt_hex, hash_hex = hash_password(password)
    users[username] = {"salt": salt_hex, "hash": hash_hex, "created": time.time()}
    save_users(users)

    log.info(f"registered new user: {username}")
    return web.json_response({"ok": True})


async def login(request: web.Request) -> web.Response:
    data = await request.json()
    username = data.get("username", "").strip()
    password = data.get("password", "")

    users = load_users()
    user = users.get(username)
    if not user or not verify_password(password, user["salt"], user["hash"]):
        return web.json_response({"error": "invalid username or password"}, status=401)

    token = secrets.token_urlsafe(24)
    sessions[token] = username
    log.info(f"{username} logged in")
    return web.json_response({"ok": True, "token": token, "username": username})


# WebSocket chat relay

async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    token = request.query.get("token", "")
    username = sessions.get(token)

    ws = web.WebSocketResponse()
    await ws.prepare(request)

    if not username:
        await ws.send_json({"type": "error", "message": "invalid or expired session"})
        await ws.close()
        return ws

    online[username] = ws
    log.info(f"{username} connected to chat")

    await ws.send_json({"type": "history", "messages": history_for(username)})
    await broadcast_user_list()

    try:
        async for msg in ws:
            if msg.type == WSMsgType.TEXT:
                data = json.loads(msg.data)
                if data.get("type") == "message":
                    await relay_message(username, data)
    finally:
        if online.get(username) is ws:
            del online[username]
        log.info(f"{username} disconnected")
        await broadcast_user_list()

    return ws


async def relay_message(sender: str, data: dict) -> None:
    recipient = data.get("to")
    text = data.get("text", "")
    target_ws = online.get(recipient)

    log.info(f"relaying message from {sender} to {recipient}: {text}")
    append_message(sender, recipient, text)

    if target_ws is not None:
        await target_ws.send_json({"type": "message", "from": sender, "to": recipient, "text": text})
    else:
        sender_ws = online.get(sender)
        if sender_ws is not None:
            await sender_ws.send_json({"type": "system", "message": f"{recipient} is not online right now, but they'll see it once they log in."})


async def broadcast_user_list() -> None:
    payload = {"type": "user_list", "users": list(online.keys())}
    for ws in list(online.values()):
        await ws.send_json(payload)


# static frontend

async def index(request: web.Request) -> web.FileResponse:
    return web.FileResponse(STATIC_DIR / "login.html")


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_post("/api/register", register)
    app.router.add_post("/api/login", login)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/", index)
    app.router.add_static("/", STATIC_DIR, show_index=False)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="localhost", port=8765)
