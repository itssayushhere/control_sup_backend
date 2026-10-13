# Project Map

## Purpose
ControlSup: cross-platform remote screen viewing/control with voice, clipboard, file transfer, and optional shell, between two paired devices. This directory is the signaling backend.

## Requirements
From the user's architecture brief:
- Transport between peers: WebRTC (STUN, TURN via coturn, DTLS-SRTP). Media/input/files never go through the signaling server.
- Pairing codes expire; explicit consent; permissions enforced on host (client) side.
- Clients: Rust core + Flutter UI (Android, Windows, Linux, macOS). No iOS.

## Confirmed design (2026-10-12, implemented same day)
- Language: Go. Single server instance.
- Identity: client Ed25519 keypair; deviceId derived from public key; server challenge-signature on every WS connect. Socket map keyed by deviceId only after auth.
- Two access modes (hybrid consent): stranger = 9-digit one-time code (10 min, single use) + consent prompt on A every session; trusted device = A's long-lived secret, unattended. A can "Trust this device" after accepting a stranger.
- A grants per-device perms at consent; saved on server with the trusted entry and returned in `session` (A enforces).
- Server verifies codes/secrets and stores trusted list (diverges from brief's "stores nothing else" — accepted).
- Long-lived secret stored as argon2 hash.
- No lockouts. 5 wrong guesses (any device) against a one-time code -> code replaced and pushed to A.
- Relay: SDP/ICE forwarded only within an approved active session.
- Storage: SQLite (devices, secret hashes, trusted pairs); online sockets + sessions in memory.
- Transport: JSON over WSS.
- Out of scope: TURN credentials, horizontal scaling.

## Main Flow
Client --WSS (auth by signature)--> Go signaling server <--WSS-- Client
Client A <==== WebRTC (direct or via TURN) ====> Client B

## Build and Deployment
Go 1.27.2 at ~/.local/go/bin. Run: `go test -race ./...`, `go run .` (env ADDR, DB_PATH). Files: main.go (routes), auth.go (handshake), store.go (SQLite), hub.go (live state + routing), server_test.go.

## Unknowns
- Exact message protocol field names (to be proposed at implementation checkpoint)
- Deployment target, TLS termination
- TURN credential handling
