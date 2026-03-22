# e2hat

End-to-end encrypted chat built on elliptic curve mathematics.

## Why

People deserve privacy in their communications. Tools for this exist, but they tend to be complex — complex to use, complex to understand, complex to audit.

e2hat exists because encrypted messaging shouldn't require a PhD to verify. The entire codebase is intentionally small and readable. There are no layers of abstraction hiding what happens to your messages. If you can read code, you can verify that e2hat does exactly what it claims: encrypt your messages so that only you and your recipient can read them.

## What it is

A messaging application with end-to-end encryption based on solid mathematical principles:

- **Koblitz encoding** converts text into points on an elliptic curve
- **Diffie-Hellman key exchange** creates a shared secret between two people without ever transmitting the secret itself
- **Massey-Omura three-pass protocol** relays encrypted messages through the server without the server ever seeing the plaintext
- **ECDSA digital signatures** authenticate every message — the receiver can verify that a message truly came from the stated sender
- **Challenge-response authentication** proves identity to the relay server during handshake using ECDSA

All operations use the **secp521r1** curve — a well-established, peer-reviewed standard.

The server is a relay. It moves encrypted points between users. It cannot decrypt anything because it never holds the keys needed to do so. This isn't a policy decision — it's a mathematical guarantee.

## How it works

```
Alice                         Server                          Bob
  |                              |                              |
  |  1. Koblitz: text -> point   |                              |
  |  2. DH: encrypt with shared  |                              |
  |  3. ECDSA: sign E.x          |                              |
  |  4. MO: encrypt for transit  |                              |
  |  ---encrypted point + sig--> |                              |
  |                              | (server cannot read this)    |
  |                              | ---encrypted point + sig---> |
  |                              |                              |
  |                              |  5. MO: decrypt transit layer |
  |                              |  6. ECDSA: verify signature   |
  |                              |  7. DH: decrypt with shared   |
  |                              |  8. Koblitz: point -> text    |
```

The Massey-Omura protocol adds a three-step exchange so that even the transit encryption doesn't require pre-shared keys between the client and server. The ECDSA signature travels alongside the encrypted message through the relay, allowing the receiver to verify that the message genuinely came from the claimed sender.

## Design principles

**Simple code.** The frontend is a single Vue.js application. The backend is a single Python WebSocket server. The binary protocol is ~15 message types. Anyone can read and understand the entire system.

**No accounts.** Your identity is your elliptic curve public key. There are no emails, phone numbers, or passwords tied to a central authority. You generate your keys locally and share your public key with whoever you want to talk to.

**Your choice of server.** Use a community server, self-host your own, or connect to multiple servers simultaneously. The server is a commodity — it relays encrypted data it cannot read. Switching servers doesn't compromise your security.

**Open source.** All code is public. The cryptographic operations use [ecutils](https://pypi.org/project/ecutils/) (Python) and [js-ecutils](https://www.npmjs.com/package/js-ecutils) (JavaScript) — open-source libraries that implement the mathematical primitives directly.

## Running

### With Docker Compose

```bash
docker compose up -d
```

This starts three relay servers and the frontend:

| Service  | Port | Description       |
|----------|------|-------------------|
| Mango    | 8080 | Relay server      |
| Papaya   | 8081 | Relay server      |
| Guava    | 8082 | Relay server      |
| Frontend | 3000 | Web application   |

Open `http://localhost:3000` in your browser.

### Server only

```bash
pip install aiohttp ecutils
python -m server.app
```

The server listens on port 8080 by default. It exposes a single WebSocket endpoint at `/ws`.

### Frontend only

The frontend is static HTML/CSS/JS. Serve it from any web server, CDN, or open `index.html` directly. It loads Vue.js and js-ecutils from CDN — no build step required.

## Project structure

```
server/
  app.py          WebSocket relay server
  protocol.py     Binary protocol pack/unpack
  session.py      Massey-Omura session management

frontend/
  index.html      Application shell
  app.js          Vue.js application logic and cryptography
  protocol.js     Binary protocol (mirrors server/protocol.py)
  style.css       Interface styles
  manifest.json   PWA manifest
  sw.js           Service worker for offline support
  icon.svg        Application icon
```

## Contributing

Contributions are welcome! Please read our [contributing guidelines](https://github.com/isakruas/e2hat/blob/master/CONTRIBUTING.md) to get started.

## License

This project is licensed under the [MIT License](https://opensource.org/licenses/MIT).