# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.1.0] - 2026-03-21

### Added

- End-to-end encrypted messaging using elliptic curve cryptography (secp521r1)
- Koblitz encoding for text-to-curve-point conversion
- Diffie-Hellman key exchange for shared secret derivation
- Massey-Omura three-pass protocol for secure message relay
- Custom binary protocol with 15 message types
- Multi-server support — connect to multiple relay servers simultaneously
- Three pre-configured relay servers (Mango, Papaya, Guava)
- Contact management — add, edit, rename, delete contacts
- Auto-add unknown senders as contacts
- Message delivery status indicators (sending, sent, delivered, queued)
- Offline message queue — server holds messages until recipient reconnects
- Password-based key encryption for local storage persistence
- Encrypted message history in localStorage
- Peer online/offline presence notifications
- Resizable log panel with full protocol step tracing
- Progressive Web App (PWA) with service worker and offline support
- Mobile-first responsive design with desktop side-by-side layout
- Clipboard copy for public keys
- Docker Compose setup for easy deployment
