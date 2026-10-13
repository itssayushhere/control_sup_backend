package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// Clients sign this prefix + nonce, never a bare nonce, so the signature
// can't be replayed as a signature over anything else.
const authPrefix = "controlsup-auth-v1:"

// deviceID is derived from the public key: whoever holds the private key owns the ID.
func deviceID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:16])
}

// handshake runs hello -> challenge -> auth and returns the proven device ID.
func handshake(ctx context.Context, conn *websocket.Conn) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	var hello msg
	if err := wsjson.Read(ctx, conn, &hello); err != nil {
		return "", err
	}
	pub, err := base64.StdEncoding.DecodeString(hello.Pubkey)
	if hello.Type != "hello" || err != nil || len(pub) != ed25519.PublicKeySize {
		return "", errors.New("bad hello")
	}

	nonce := make([]byte, 32)
	rand.Read(nonce)
	if err := wsjson.Write(ctx, conn, out{"type": "challenge", "nonce": base64.StdEncoding.EncodeToString(nonce)}); err != nil {
		return "", err
	}

	var auth msg
	if err := wsjson.Read(ctx, conn, &auth); err != nil {
		return "", err
	}
	sig, err := base64.StdEncoding.DecodeString(auth.Sig)
	if auth.Type != "auth" || err != nil || !ed25519.Verify(pub, append([]byte(authPrefix), nonce...), sig) {
		return "", errors.New("bad signature")
	}
	return deviceID(pub), nil
}
