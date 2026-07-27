# End-to-end encrypted chat 

# how to run
insall aiohttp cryptography 
run server.py, then open http://localhost:8765 .register 2 or more accounts to chat between each other.

# running the attack
set MODE = "eavesdrop" for key substituin attack or MODE = "tamper" for tampering attack (it flips one bit of ciphertext)

the attack is a simulation of a victim already in a compromised network position. since netwrok compromise is outside of scope 
the attack need menual redirection of the users. 

after loging in users run mitm_proxy.py then redirect both tabs by pasting the script in attackScripts/redirect_to_proxy.js" to the console in DevTools 

# structure
server.py - backend
static - frontend and client side encryption
attackScripts - standalone attack scripts
