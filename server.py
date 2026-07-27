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


def append_message(sender: str, recipient: str, ciphertext: str, iv: str) -> None:
    messages = load_messages()
    messages.append({"from": sender, "to": recipient, 
                     "ciphertext": ciphertext, "iv": iv,
                     "time": time.time()})
    save_messages(messages)


def history_for(username: str) -> list[dict]:
    messages = load_messages()
    return [m for m in messages if m["from"] == username or m["to"] == username]

# key transparency log
MERKLE_LOG_FILE = BASE_DIR / "merkle_log.json"

def load_merkle_log() -> list[dict]:
    if MERKLE_LOG_FILE.exists():
        return json.loads(MERKLE_LOG_FILE.read_text())
    return []

def save_merkle_log(entries: list[dict]) -> None:
    MERKLE_LOG_FILE.write_text(json.dumps(entries, indent=2))

def leaf_hash(username: str, public_key_b64: str, timestamp: float) -> str:
    return hashlib.sha256(f"{username}:{public_key_b64}:{timestamp}".encode()).hexdigest()

def combine_hash(left_hex: str, right_hex: str) -> str:
    return hashlib.sha256((left_hex + right_hex).encode()).hexdigest()

def build_merkle_levels(leaves: list[str]) -> list[list[str]]:
    if not leaves:
        return [[hashlib.sha256(b"").hexdigest()]]
    levels = [leaves[:]]
    current = leaves[:]
    while len(current) > 1:
        if len(current) % 2 == 1:
            current = current + [current[-1]]
        current = [combine_hash(current[i], current[i + 1]) for i in range(0, len(current), 2)]
        levels.append(current)
    return levels

def get_merkle_proof(levels: list[list[str]], leaf_index: int) -> list[dict]:
    proof = []
    index = leaf_index
    for level in levels[:-1]:
        padded = level if len(level) % 2 == 0 else level + [level[-1]]
        sibling_index = index ^ 1
        proof.append({"hash": padded[sibling_index], "isRight": sibling_index % 2 == 1})
        index //= 2
    return proof

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


async def publish_key(request: web.Request) -> web.Response:
    data = await request.json()
    token = data.get("token", "")
    username = sessions.get(token)
    if not username:
        return web.json_response({"error": "invalid token"}, status=401)
    public_key = data.get("publicKey", "")
    entries = load_merkle_log()
    entries.append({"username": username, "publicKey": public_key, "time": time.time()})
    save_merkle_log(entries)
    log.info(f"published key to transparency log for {username} (log now has {len(entries)} entries)")
    return web.json_response({"ok": True})

async def key_proof(request: web.Request) -> web.Response:
    username = request.query.get("username", "")
    entries = load_merkle_log()
    if not entries:
        return web.json_response({"error": "log is empty"}, status=404)
    matching_indices = [i for i, e in enumerate(entries) if e["username"] == username]
    if not matching_indices:
        return web.json_response({"error": "no key published for this user"}, status=404)
    leaf_index = matching_indices[-1]
    entry = entries[leaf_index]
    leaves = [leaf_hash(e["username"], e["publicKey"], e["time"]) for e in entries]
    levels = build_merkle_levels(leaves)
    proof = get_merkle_proof(levels, leaf_index)
    return web.json_response({
        "publicKey": entry["publicKey"], "timestamp": entry["time"],
        "proof": proof, "root": levels[-1][0], "treeSize": len(entries),
    })
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
                msg_type = data.get("type")
                if msg_type == "message":
                    await relay_message(username, data)
                elif msg_type in ("pubkey", "session_key"):
                    await relay_ephemeral(username, data)
    finally:
        if online.get(username) is ws:
            del online[username]
        log.info(f"{username} disconnected")
        await broadcast_user_list()

    return ws


async def relay_message(sender: str, data: dict) -> None:
    recipient = data.get("to")
    ciphertext = data.get("ciphertext", "")
    iv = data.get("iv", "")
    target_ws = online.get(recipient)

    log.info(f"relaying message from {sender} to {recipient}: {ciphertext}")
    append_message(sender, recipient, ciphertext, iv)

    if target_ws is not None:
        await target_ws.send_json({
            "type": "message", "from": sender, "to": recipient, 
            "ciphertext": ciphertext, "iv": iv})
    else:
        sender_ws = online.get(sender)
        if sender_ws is not None:
            await sender_ws.send_json({"type": "system", "message": f"{recipient} is not online right now, but they'll see it once they log in."})

async def relay_ephemeral(sender: str, data: dict) -> None:
    """Relays pubkey/session_key handshake messages. Blind relay - the server
    does not (and at this layer, cannot) verify these belong to who they claim."""
    recipient = data.get("to")
    target_ws = online.get(recipient)
    if target_ws is not None:
        data["from"] = sender
        await target_ws.send_json(data)

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
    app.router.add_post("/api/publish_key", publish_key)
    app.router.add_get("/api/key_proof", key_proof)
    app.router.add_get("/ws", ws_handler)
    app.router.add_get("/", index)
    app.router.add_static("/", STATIC_DIR, show_index=False)
    return app


if __name__ == "__main__":
    web.run_app(create_app(), host="localhost", port=8765)
