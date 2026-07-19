// NEW FILE (Layer 1). Pure crypto helper functions using the browser's built-in
// Web Crypto API (window.crypto.subtle) - no external libraries. Nothing in this
// file ever sends a private key anywhere; only chat.js decides what gets sent.
 
// ---------- base64 helpers (Web Crypto works in ArrayBuffers, WebSockets need text) ----------
 
function bufferToBase64(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}
 
function base64ToBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
 
// ---------- RSA keypair (persisted locally per user, see persistence helpers below - never sent to the server) ----------
 
async function generateRSAKeyPair() {
  return crypto.subtle.generateKey(
    { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true, // extractable - needed so we can export the PUBLIC key to send it. Private key still never leaves this function's caller.
    ["encrypt", "decrypt"]
  );
}
 
async function exportPublicKey(publicKey) {
  const raw = await crypto.subtle.exportKey("spki", publicKey);
  return bufferToBase64(raw);
}
 
async function importPublicKey(base64) {
  return crypto.subtle.importKey(
    "spki", base64ToBuffer(base64),
    { name: "RSA-OAEP", hash: "SHA-256" },
    true, ["encrypt"]
  );
}
 
// ---------- AES-GCM session key (one per conversation) ----------
 
async function generateAESKey() {
  return crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
}
 
// Wrap (encrypt) an AES session key using the peer's RSA public key, so only
// they can unwrap it with their matching private key.
async function wrapAESKey(aesKey, peerPublicKey) {
  const raw = await crypto.subtle.exportKey("raw", aesKey);
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, peerPublicKey, raw);
  return bufferToBase64(wrapped);
}
 
// Unwrap (decrypt) an AES session key using our own RSA private key.
async function unwrapAESKey(wrappedBase64, myPrivateKey) {
  const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, myPrivateKey, base64ToBuffer(wrappedBase64));
  return crypto.subtle.importKey("raw", raw, { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}
 
// ---------- persistence helpers (Layer 1 fix) ----------
// JWK is a JSON-friendly key format, unlike the raw ArrayBuffers above -
// this makes it easy to JSON.stringify() a key and store it in localStorage.
 
async function exportKeyJWK(key) {
  return crypto.subtle.exportKey("jwk", key);
}
 
async function importRSAPublicKeyJWK(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["encrypt"]);
}
 
async function importRSAPrivateKeyJWK(jwk) {
  return crypto.subtle.importKey("jwk", jwk, { name: "RSA-OAEP", hash: "SHA-256" }, true, ["decrypt"]);
}
 
async function exportAESKeyBase64(key) {
  const raw = await crypto.subtle.exportKey("raw", key);
  return bufferToBase64(raw);
}
 
async function importAESKeyBase64(base64) {
  return crypto.subtle.importKey("raw", base64ToBuffer(base64), { name: "AES-GCM" }, true, ["encrypt", "decrypt"]);
}
 
// ---------- message encryption ----------
// AES-GCM needs a fresh random IV (12 bytes) per message. It is not secret -
// it's sent alongside the ciphertext - but it must never be reused with the
// same key. The GCM auth tag is appended automatically inside the ciphertext
// by the browser; if a single bit is altered, decrypt() below will throw.
 
async function encryptMessage(aesKey, plaintext) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encoded = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, aesKey, encoded);
  return { ciphertext: bufferToBase64(ciphertext), iv: bufferToBase64(iv) };
}
 
async function decryptMessage(aesKey, ciphertextBase64, ivBase64) {
  const iv = new Uint8Array(base64ToBuffer(ivBase64));
  const decrypted = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, aesKey, base64ToBuffer(ciphertextBase64)
  );
  return new TextDecoder().decode(decrypted);
}