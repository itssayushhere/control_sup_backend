# Learning Progress

## Pending decision
Decision: none pending. Possible next topics: editing saved perms later (set_perms), alert A on repeated wrong secrets, B->A grants (bidirectional), TLS/deployment, client protocol.

## auth.go walkthrough (2026-10-13)
- Learner asked what each part of auth.go does; AI explained (deviceID, handshake steps, authPrefix, timeout). Explanation only, not demonstrated understanding.

## Trust powers (2026-10-12, implemented)
- Learner decided: A chooses what powers to give the connecting device at consent time; if trusted, choice is saved and not asked again. Saved on the server.
- Implemented: consent carries perms (view, voice, control, clipboard, files_send, files_receive, terminal); trusted table stores perms JSON; session message carries perms to both sides; unknown perm -> error, request stays pending. 8 tests pass with -race.
- Granularity (tick each vs presets) not explicitly chosen; implemented as individual perms (presets can be a UI concern).
## Lockout change (2026-10-12, implemented on learner's explicit "change the code")
- Learner decided: no lockouts at all; instead, when wrong guesses hit a limit, change the code.
- Implemented: 5 wrong guesses against a code (from any device) -> server issues a new code and pushes it to A. Lockout + secret revocation removed. Test TestCodeChangesAfterWrongGuesses; 7 tests pass with -race.
- Known risk told to learner: a stolen trusted device can guess the secret without limit (argon2 cost is the only brake).
- Earlier: line-by-line walkthrough delivered; .env.example created.
## Implementation (2026-10-12)
- Learner approved "Implement this step". Go 1.27.2 installed to ~/.local/go.
- Implemented main.go, auth.go, store.go, hub.go, server_test.go. 7 tests pass with -race; binary /health smoke-checked.
- Deviation from confirmed additions: no `devices` table (deviceId derives from pubkey; nothing to store).

## Pairing flow (history)
Original Build checkpoint: Signaling server pairing + relay flow.
Asked learner to describe, in their own words, the end-to-end flow from "device B wants to connect to A" to "WebRTC connected", including who generates the code, what the server keeps in memory, and when the code dies. No approach proposed by AI.

Learner's first answer (2026-10-12):
- Server generates deviceId + code using client details (name, user id).
- Code = long-lived secret ("if you know it you can connect"), must not leak — conflicts with brief's expiring one-time code.
- WebSocket mapped by deviceId (learner unsure).
- Wants to use a hardware/OS internal device ID to distinguish device vs user.
- Knowing B's code = allowed to connect and control; no consent prompt mentioned (brief requires one).
- Not yet addressed: expiry, wrong-guess limits, how server verifies a socket really owns a deviceId, relay authorization.
Open follow-ups asked: secret-vs-one-time, consent, socket identity proof, hardware ID trust.

Learner's second answer (2026-10-12):
- Accepts codes must be random (not derived from client details).
- Chooses long-lived secret (unattended access, "connect any time") plus limited wrong attempts.
- Consent "only at start" — ambiguous (first pairing vs. each session); conflicts with unattended access when nobody is present. Clarification asked.
- Asked for help on socket identity proof → AI offered options (server-issued token vs client keypair); decision left to learner.

Learner's third answer (2026-10-12) — decisions (not yet confirmed at Design/Implementation checkpoint):
- Consent: hybrid, per peer. Strangers → one-time code + consent each session. Trusted/important devices → unattended "any time" access. Rationale (learner): depends on who is connecting.
- Identity: Option B, client keypair; deviceId derived from public key; server challenge-signature on connect. (Rationale not given.)
Open: who verifies codes + where trusted list lives (server vs device A), attempt-limit numbers, Node vs Go.

Learner's fourth answer (2026-10-12):
- Server verifies codes and holds the trusted-device list (learner: "server should know who has rights, not client"). Consequence flagged: server now persists data, diverging from brief's "stores nothing else".
- Attempt limits: both lockout and revocation (numbers proposed by AI, pending confirmation).
- Language: asked AI to recommend Node vs Go; learner knows one of them (message ambiguous). AI gave facts; choice pending.
Design checkpoint presented with Proposed additions.
- Learner chose Go (after AI noted speed is not a differentiator for signaling).
- Learner confirmed design + all Proposed additions ("Confirm and continue"). Confirmation = readiness, not demonstrated understanding.

## Signaling
- Introduced (AI explained): role of signaling — peers exchange SDP offer/answer and ICE candidates via a third party before WebRTC can connect; server never sees media.
