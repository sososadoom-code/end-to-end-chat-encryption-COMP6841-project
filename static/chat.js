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

function connect() {
  socket = new WebSocket(`ws://${location.host}/ws?token=${encodeURIComponent(token)}`);

  socket.onopen = () => console.log(`[${myUsername}] connected`);

  socket.onclose = () => setTimeout(connect, 1500);

  socket.onmessage = (event) => {
    const data = JSON.parse(event.data);

    if (data.type === "history") {
      data.messages.forEach((m) => {
        const counterpart = m.from === myUsername ? m.to : m.from;
        if (!conversations[counterpart]) conversations[counterpart] = [];
        conversations[counterpart].push({
          text: m.text,
          mine: m.from === myUsername,
          time: new Date(m.time * 1000),
        });
      });
      if (activeContact) renderMessages();
    } else if (data.type === "user_list") {
      onlineUsers = data.users.filter((u) => u !== myUsername);
      renderContacts();
    } else if (data.type === "message") {
      const from = data.from;
      if (!conversations[from]) conversations[from] = [];
      conversations[from].push({ text: data.text, mine: false, time: new Date() });
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
  document.getElementById("input").focus();
}

function renderMessages() {
  const container = document.getElementById("messages");
  container.innerHTML = "";
  (conversations[activeContact] || []).forEach((m) => {
    const bubble = document.createElement("div");
    bubble.className = `bubble ${m.mine ? "mine" : "theirs"}`;
    const time = m.time.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
    bubble.innerHTML = `${escapeHtml(m.text)}<span class="meta">${m.mine ? "you" : activeContact} · ${time} · plaintext</span>`;
    container.appendChild(bubble);
  });
  container.scrollTop = container.scrollHeight;
}

function sendMessage() {
  const input = document.getElementById("input");
  const text = input.value.trim();
  if (!text || !activeContact) return;

  socket.send(JSON.stringify({ type: "message", to: activeContact, text }));

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

document.addEventListener("DOMContentLoaded", () => {
  document.getElementById("my-avatar").textContent = initials(myUsername);
  document.getElementById("my-name").textContent = myUsername;
  document.getElementById("input").addEventListener("keydown", (e) => {
    if (e.key === "Enter") sendMessage();
  });
  connect();
});
