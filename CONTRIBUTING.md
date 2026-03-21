# Contributing to e2hat

Thank you for your interest in contributing. e2hat values simplicity and readability above all else. Every contribution should preserve these qualities.

## Philosophy

e2hat exists so that anyone can read and understand how their messages are being encrypted. Before contributing, please keep in mind:

- **Simplicity is a feature.** If a change makes the code harder to read, it needs a very good reason.
- **Less code is better.** Solve the problem with the minimum amount of code necessary.
- **No unnecessary dependencies.** The frontend has two external libraries (Vue.js and js-ecutils). The backend has two (aiohttp and ecutils). Adding a new dependency requires strong justification.
- **The server must remain a blind relay.** It must never be able to read message content. This is a mathematical guarantee, not a policy. Any change that weakens this guarantee will be rejected.

## How to contribute

### Reporting issues

Open an issue describing:

1. What you expected to happen
2. What actually happened
3. Steps to reproduce the problem

### Proposing changes

1. Fork the repository
2. Create a branch for your change
3. Make your changes
4. Test locally with Docker Compose (`docker compose up -d`)
5. Open a pull request

### What makes a good pull request

- **Small and focused.** One change per PR. A bug fix is separate from a feature.
- **Tested.** Open two browser tabs, generate keys, exchange messages. Verify the change works end-to-end.
- **Readable.** If someone else can't understand your code without comments, simplify the code rather than adding comments.

## Project structure

```
server/
  app.py          WebSocket relay and connection management
  protocol.py     Binary protocol serialization/deserialization
  session.py      Massey-Omura session state management

frontend/
  index.html      HTML shell with Vue.js template
  app.js          Application logic, cryptography, WebSocket handling
  protocol.js     Binary protocol (mirrors server/protocol.py)
  style.css       Styles
```

The frontend and backend protocol implementations must stay in sync. If you change a message type or payload format in `server/protocol.py`, the same change must be reflected in `frontend/protocol.js`.

## Development setup

### With Docker Compose

```bash
docker compose up -d --build
```

Frontend at `http://localhost:3000`. Servers at ports 8080, 8081, 8082.

### Without Docker

```bash
# Backend
pip install aiohttp ecutils
python -m server.app

# Frontend
# Serve the frontend/ directory with any HTTP server
python -m http.server 3000 -d frontend
```

## Areas where help is welcome

- **Security review.** More eyes on the cryptographic implementation are always valuable.
- **Accessibility.** Screen reader support, keyboard navigation, color contrast.
- **Internationalization.** Translating the interface to other languages.
- **Testing.** Automated tests for the protocol layer and session management.
- **Documentation.** Clearer explanations of the cryptographic flow for non-technical readers.

