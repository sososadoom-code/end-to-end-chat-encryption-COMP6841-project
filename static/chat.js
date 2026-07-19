// FRONTEND logic for chat.html (runs in the browser, not on the server). It authenticates
// the WebSocket connection using the token/username from login, then handles sending
// messages, receiving them, and rendering the contact list and conversation UI.

const token = sessionStorage.getItem("token");
const myUsername = sessionStorage.getItem("username");

if (!token || !myUsername) {
  window.location.href = "login.html";
}

let socket;
let onlineUsers = [];
let activeContact = null;

const conversations = {};

// crypto state
let myKeyPair;
let myPublicKeyExported;
const peerPublicKeys = {};
const sessionKeys = {};
const pubkeySentTo = new Set();

async function initCrypto() {
  const identityStorageKey = `rsa_identity:${myUsername}`;
  const stored = localStorage.getItem(identityStorageKey);
  if (stored) {
    const { publicJwk, privateJwk } = JSON.parse(stored);
    myKeyPair = {
      publicKey: await importRSAPublicKeyJWK(publicJwk),
      privateKey: await importRSAPrivateKeyJWK(privateJwk),
    };
  } else {
    myKeyPair = await generateRSAKeyPair();
    const publicJwk = await exportKeyJWK(myKeyPair.publicKey);
    const privateJwk = await exportKeyJWK(myKeyPair.privateKey);
    localStorage.setItem(identityStorageKey, JSON.stringify({ publicJwk, privateJwk }));
  }
  myPublicKeyExported = await exportPublicKey(myKeyPair.publicKey);
  const prefix = `session_key:${myUsername}:`;
  for (let i = 0; i < localStorage.length; i++) {
    const storageKey = localStorage.key(i);
    if (storageKey.startsWith(prefix)) {
      const peer = storageKey.slice(prefix.length);
      sessionKeys[peer] = await importAESKeyBase64(localStorage.getItem(storageKey));
    }
  }
}

function persistSessionKey(peer, aesKey) {
  exportAESKeyBase64(aesKey).then((b64) => {
    localStorage.setItem(`session_key:${myUsername}:${peer}`, b64);
  });
}

function ensureSecureChannel(peer) {
  if (sessionKeys[peer]) return;
  if (!pubkeySentTo.has(peer)) {
    socket.send(JSON.stringify({ type: "pubkey", to: peer, publicKey: myPublicKeyExported }));
    pubkeySentTo.add(peer);
  }
  if (peerPublicKeys[peer] && myUsername < peer) {
    generateAndSendSessionKey(peer);
  }
  updateSecureStatus();
}

async function generateAndSendSessionKey(peer) {
  if (sessionKeys[peer]) return;
  const aesKey = await generateAESKey();
  sessionKeys[peer] = aesKey;
  persistSessionKey(peer, aesKey);
  const wrappedKey = await wrapAESKey(aesKey, peerPublicKeys[peer]);
  socket.send(JSON.stringify({ type: "session_key", to: peer, wrappedKey }));
  updateSecureStatus();
}

function updateSecureStatus() {
  const statusEl = document.getElementById("secure-status");
  const input = document.getElementById("input");
  if (!activeContact || !statusEl) return;
  if (sessionKeys[activeContact]) {
    statusEl.textContent = "🔒 Encrypted (AES-GCM)";
    statusEl.style.color = "var(--accent)";
    input.disabled = false;
    input.placeholder = "Type a message...";
  } else {
    statusEl.textContent = "🔓 Establishing secure connection...";
    statusEl.style.color = "var(--red)";
    input.disabled = true;
    input.placeholder = "Waiting for secure channel...";
  }
}

function connect() {
  socket = new WebSocket(`ws://${location.host}/ws?token=${encodeURIComponent(token)}`);

  socket.onopen = () => console.log(`[${myUsername}] connected`);

  socket.onclose = () => setTimeout(connect, 1500);

  socket.onmessage = async (event) => {
    const data = JSON.parse(event.data);

    if (data.type === "history") {
      for (const m of data.messages) {
        const counterpart = m.from === myUsername ? m.to : m.from;
        if (!conversations[counterpart]) conversations[counterpart] = [];
        const key = sessionKeys[counterpart];
        if (key) {
          try {
            const plaintext = await decryptMessage(key, m.ciphertext, m.iv);
            conversations[counterpart].push({ text: plaintext, mine: m.from === myUsername, time: new Date(m.time * 1000) });
            continue;
          } catch (e) {}
        }
        conversations[counterpart].push({
          text: null,
          undecryptable: true,
          mine: m.from === myUsername,
          time: new Date(m.time * 1000),
        });
      }
      if (activeContact) renderMessages();
    } else if (data.type === "user_list") {
      onlineUsers = data.users.filter((u) => u !== myUsername);
      renderContacts();
    } else if (data.type === "pubkey") {
      peerPublicKeys[data.from] = await importPublicKey(data.publicKey);
      ensureSecureChannel(data.from);
    } else if (data.type === "session_key") {
      sessionKeys[data.from] = await unwrapAESKey(data.wrappedKey, myKeyPair.privateKey);
      persistSessionKey(data.from, sessionKeys[data.from]);
      updateSecureStatus();
    } else if (data.type === "message") {
      const from = data.from;
      if (!conversations[from]) conversations[from] = [];
      const key = sessionKeys[from];
      if (key) {
        try {
          const plaintext = await decryptMessage(key, data.ciphertext, data.iv);
          conversations[from].push({ text: plaintext, mine: false, time: new Date() });
        } catch (e) {
          conversations[from].push({ text: null, undecryptable: true, mine: false, time: new Date() });
        }
      } else {
        conversations[from].push({ text: null, undecryptable: true, mine: false, time: new Date() });
      }
      if (activeContact === from) renderMessages();
    } else if (data.type === "error") {
      alert(data.message);
      sessionStorage.clear();
      window.location.href = "login.html";
    }
  };
}

function renderContacts() {
  const container = document.getElementById("contacts");
  const emptyNote = document.getElementById("empty-note");
  container.innerHTML = "";

  const pastContacts = Object.keys(conversations);
  const allContacts = [...new Set([...onlineUsers, ...pastContacts])];

  if (allContacts.length === 0) {
    emptyNote.style.display = "block";
  } else {
    emptyNote.style.display = "none";
  }

  allContacts.forEach((user) => {
    const isOnline = onlineUsers.includes(user);
    const el = document.createElement("div");
    el.className = "contact" + (user === activeContact ? " active" : "");
    el.style.opacity = isOnline ? "1" : "0.55";
    el.innerHTML = `<span class="contact-dot" style="${isOnline ? "" : "background:var(--line);"}"></span>${escapeHtml(user)}`;
    el.onclick = () => selectContact(user);
    container.appendChild(el);
  });
}

function selectContact(user) {
  activeContact = user;
  document.getElementById("chat-header-name").textContent = user;
  document.getElementById("messages").style.display = "flex";
  document.getElementById("empty-state").style.display = "none";
  document.getElementById("composer").style.display = "flex";
  if (!conversations[user]) conversations[user] = [];
  renderContacts();
  renderMessages();
  ensureSecureChannel(user);
  document.getElementById("input").focus();
}

function renderMessages() {
  const container = document.getElementById("messages");
  container.innerHTML = "";
  (conversations[activeContact] || []).forEach((m) => {
    const bubble = document.createElement("div");
    bubble.className = `bubble ${m.mine ? "mine" : "theirs"}`;
    const time = m.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    const body = m.undecryptable
      ? `<em>🔒 Encrypted message - no longer able to decrypt (session key not available)</em>`
      : escapeHtml(m.text);
    const tag = m.undecryptable ? "unreadable to us too" : "AES-GCM encrypted";
    bubble.innerHTML = `${body}<span class="meta">${m.mine ? "you" : activeContact} · ${time} · ${tag}</span>`;
    container.appendChild(bubble);
  });
  container.scrollTop = container.scrollHeight;
  updateSecureStatus();
}

async function sendMessage() {
  const input = document.getElementById("input");
  const text = input.value.trim();
  if (!text || !activeContact) return;

  const key = sessionKeys[activeContact];
  if (!key) return;

  const { ciphertext, iv } = await encryptMessage(key, text);
  socket.send(JSON.stringify({ type: "message", to: activeContact, ciphertext, iv }));

  if (!conversations[activeContact]) conversations[activeContact] = [];
  conversations[activeContact].push({ text, mine: true, time: new Date() });
  renderMessages();
  input.value = "";
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function initials(name) {
  return name.slice(0, 2).toUpperCase();
}

document.addEventListener("DOMContentLoaded", async () => {
  document.getElementById("my-avatar").textContent = initials(myUsername);
  document.getElementById("my-name").textContent = myUsername;
  document.getElementById("input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });
  await initCrypto();
  connect();
});
