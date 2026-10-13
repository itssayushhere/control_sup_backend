package main

import (
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

// testServer starts a real server on an in-memory DB with a clock tests can advance.
func testServer(t *testing.T) (*hub, string, func(time.Duration)) {
	st, err := openStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	h := newHub(st)
	var mu sync.Mutex
	offset := time.Duration(0)
	h.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return time.Now().Add(offset) }
	srv := httptest.NewServer(newServer(h))
	t.Cleanup(srv.Close)
	advance := func(d time.Duration) { mu.Lock(); offset += d; mu.Unlock() }
	return h, "ws" + strings.TrimPrefix(srv.URL, "http") + "/ws", advance
}

type tclient struct {
	t    *testing.T
	conn *websocket.Conn
	id   string
}

func dialRaw(t *testing.T, url string) *websocket.Conn {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, url, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

// device connects with a fresh keypair and completes the handshake.
func device(t *testing.T, url string) *tclient {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	c := &tclient{t: t, conn: dialRaw(t, url)}
	c.write(out{"type": "hello", "pubkey": base64.StdEncoding.EncodeToString(pub)})
	ch := c.read("challenge")
	nonce, _ := base64.StdEncoding.DecodeString(ch["nonce"].(string))
	c.write(out{"type": "auth", "sig": base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(authPrefix), nonce...)))})
	c.id = c.read("authed")["deviceId"].(string)
	if c.id != deviceID(pub) {
		t.Fatalf("device id mismatch")
	}
	return c
}

func (c *tclient) write(m out) {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := wsjson.Write(ctx, c.conn, m); err != nil {
		c.t.Fatal(err)
	}
}

// read returns the next message and fails the test if its type isn't want.
func (c *tclient) read(want string) map[string]any {
	c.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var m map[string]any
	if err := wsjson.Read(ctx, c.conn, &m); err != nil {
		c.t.Fatalf("waiting for %q: %v", want, err)
	}
	if m["type"] != want {
		c.t.Fatalf("want %q, got %v", want, m)
	}
	return m
}

func (c *tclient) newCode() string {
	c.write(out{"type": "new_code"})
	return c.read("code")["code"].(string)
}

func TestBadSignatureRejected(t *testing.T) {
	_, url, _ := testServer(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	c := &tclient{t: t, conn: dialRaw(t, url)}
	c.write(out{"type": "hello", "pubkey": base64.StdEncoding.EncodeToString(pub)})
	c.read("challenge")
	c.write(out{"type": "auth", "sig": base64.StdEncoding.EncodeToString(make([]byte, 64))})
	var m map[string]any
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := wsjson.Read(ctx, c.conn, &m); websocket.CloseStatus(err) != websocket.StatusPolicyViolation {
		t.Fatalf("want policy-violation close, got %v %v", m, err)
	}
}

func TestStrangerCodeConsentAndRelay(t *testing.T) {
	_, url, _ := testServer(t)
	a, b := device(t, url), device(t, url)
	code := a.newCode()

	b.write(out{"type": "connect", "to": a.id, "code": code})
	in := a.read("incoming")
	if in["needsConsent"] != true || in["from"] != b.id {
		t.Fatalf("bad incoming %v", in)
	}
	a.write(out{"type": "consent", "requestId": in["requestId"], "accept": true})
	sb, sa := b.read("session"), a.read("session")
	if sb["initiator"] != true || sa["initiator"] != false || sb["sessionId"] != sa["sessionId"] {
		t.Fatalf("bad session %v %v", sb, sa)
	}

	b.write(out{"type": "signal", "sessionId": sb["sessionId"], "data": json.RawMessage(`{"sdp":"offer"}`)})
	if got := a.read("signal"); got["data"].(map[string]any)["sdp"] != "offer" || got["from"] != b.id {
		t.Fatalf("bad relay %v", got)
	}

	// The code worked once; it must not work again.
	b.write(out{"type": "connect", "to": a.id, "code": code})
	if r := b.read("rejected"); r["reason"] != "denied" {
		t.Fatalf("code reused: %v", r)
	}
}

func TestDecline(t *testing.T) {
	_, url, _ := testServer(t)
	a, b := device(t, url), device(t, url)
	b.write(out{"type": "connect", "to": a.id, "code": a.newCode()})
	a.write(out{"type": "consent", "requestId": a.read("incoming")["requestId"], "accept": false})
	if r := b.read("rejected"); r["reason"] != "declined" {
		t.Fatalf("got %v", r)
	}
}

func TestExpiredCode(t *testing.T) {
	_, url, advance := testServer(t)
	a, b := device(t, url), device(t, url)
	code := a.newCode()
	advance(codeTTL + time.Second)
	b.write(out{"type": "connect", "to": a.id, "code": code})
	if r := b.read("rejected"); r["reason"] != "denied" {
		t.Fatalf("expired code accepted: %v", r)
	}
}

func TestSignalOutsideSessionBlocked(t *testing.T) {
	_, url, _ := testServer(t)
	a, b := device(t, url), device(t, url)
	b.write(out{"type": "connect", "to": a.id, "code": a.newCode()})
	a.write(out{"type": "consent", "requestId": a.read("incoming")["requestId"], "accept": true})
	sid := b.read("session")["sessionId"]
	a.read("session")

	// A third device that knows the session ID still can't inject into it.
	c := device(t, url)
	c.write(out{"type": "signal", "sessionId": sid, "data": json.RawMessage(`{}`)})
	c.read("error")
	c.write(out{"type": "signal", "sessionId": "made-up", "data": json.RawMessage(`{}`)})
	c.read("error")
}

func TestTrustedSecretSkipsConsent(t *testing.T) {
	_, url, _ := testServer(t)
	a, b, stranger := device(t, url), device(t, url), device(t, url)
	a.write(out{"type": "set_secret", "secret": "correct horse"})
	a.read("secret_set")

	// First visit: B uses a code, A accepts and ticks "trust this device".
	b.write(out{"type": "connect", "to": a.id, "code": a.newCode()})
	a.write(out{"type": "consent", "requestId": a.read("incoming")["requestId"], "accept": true, "trust": true, "perms": []string{"view", "control"}})
	sid := b.read("session")["sessionId"]
	a.read("session")
	b.write(out{"type": "end", "sessionId": sid})
	b.read("ended")
	a.read("ended")

	// Later: B connects with the secret alone, and A just gets told.
	b.write(out{"type": "connect", "to": a.id, "secret": "correct horse"})
	if in := a.read("incoming"); in["needsConsent"] != false {
		t.Fatalf("got %v", in)
	}
	// The powers A chose the first time come back without asking again.
	if p := fmt.Sprint(b.read("session")["perms"]); p != "[view control]" {
		t.Fatalf("saved perms not applied: %s", p)
	}
	a.read("session")

	// The secret alone isn't enough for a device A never trusted.
	stranger.write(out{"type": "connect", "to": a.id, "secret": "correct horse"})
	if r := stranger.read("rejected"); r["reason"] != "denied" {
		t.Fatalf("untrusted device got in: %v", r)
	}
}

func TestCodeChangesAfterWrongGuesses(t *testing.T) {
	_, url, _ := testServer(t)
	a := device(t, url)
	old := a.newCode()

	// Each guess comes from a fresh keypair, like an attacker rotating device IDs.
	for i := 0; i < maxCodeGuesses; i++ {
		g := device(t, url)
		g.write(out{"type": "connect", "to": a.id, "code": "000000000"})
		if r := g.read("rejected"); r["reason"] != "denied" {
			t.Fatalf("guess %d: %v", i, r)
		}
	}
	fresh := a.read("code")["code"].(string) // server pushed a replacement to A
	if fresh == old {
		t.Fatal("code did not change")
	}

	// Nobody is locked out: the real visitor can still use the new code, but not the old one.
	b := device(t, url)
	b.write(out{"type": "connect", "to": a.id, "code": old})
	b.read("rejected")
	b.write(out{"type": "connect", "to": a.id, "code": fresh})
	a.read("incoming")
}

func TestUnknownPermRejected(t *testing.T) {
	_, url, _ := testServer(t)
	a, b := device(t, url), device(t, url)
	b.write(out{"type": "connect", "to": a.id, "code": a.newCode()})
	rid := a.read("incoming")["requestId"]
	a.write(out{"type": "consent", "requestId": rid, "accept": true, "perms": []string{"root"}})
	a.read("error")
	// The request is still pending, so A can answer again with valid perms.
	a.write(out{"type": "consent", "requestId": rid, "accept": true, "perms": []string{"view"}})
	if p := fmt.Sprint(b.read("session")["perms"]); p != "[view]" {
		t.Fatalf("got %s", p)
	}
}

// trustB makes a trust b: A saves a secret and accepts one code visit with "trust" ticked.
func trustB(a, b *tclient, secret string) {
	a.write(out{"type": "set_secret", "secret": secret})
	a.read("secret_set")
	b.write(out{"type": "connect", "to": a.id, "code": a.newCode()})
	a.write(out{"type": "consent", "requestId": a.read("incoming")["requestId"], "accept": true, "trust": true})
	sid := b.read("session")["sessionId"]
	a.read("session")
	b.write(out{"type": "end", "sessionId": sid})
	b.read("ended")
	a.read("ended")
}

func TestWrongSecretsRemoveTrust(t *testing.T) {
	_, url, _ := testServer(t)
	a, b := device(t, url), device(t, url)
	trustB(a, b, "correct horse")

	for i := 0; i < maxSecretGuesses; i++ {
		b.write(out{"type": "connect", "to": a.id, "secret": "wrong guess"})
		if r := b.read("rejected"); r["reason"] != "denied" {
			t.Fatalf("guess %d: %v", i, r)
		}
	}
	if u := a.read("untrusted"); u["deviceId"] != b.id || u["reason"] != "wrong secret" {
		t.Fatalf("A not told: %v", u)
	}
	// Trust is gone, so even the right secret no longer works.
	b.write(out{"type": "connect", "to": a.id, "secret": "correct horse"})
	b.read("rejected")
}

func TestRightSecretResetsWrongCount(t *testing.T) {
	_, url, _ := testServer(t)
	a, b := device(t, url), device(t, url)
	trustB(a, b, "correct horse")
	for round := 0; round < 2; round++ {
		for i := 0; i < maxSecretGuesses-1; i++ {
			b.write(out{"type": "connect", "to": a.id, "secret": "typo typo"})
			b.read("rejected")
		}
		b.write(out{"type": "connect", "to": a.id, "secret": "correct horse"})
		a.read("incoming") // still trusted: the typos never reached the limit in a row
		sid := b.read("session")["sessionId"]
		a.read("session")
		b.write(out{"type": "end", "sessionId": sid})
		b.read("ended")
		a.read("ended")
	}
}

func TestUntrustEndsSessionAndReplies(t *testing.T) {
	_, url, _ := testServer(t)
	a, b := device(t, url), device(t, url)
	trustB(a, b, "correct horse")
	b.write(out{"type": "connect", "to": a.id, "secret": "correct horse"})
	a.read("incoming")
	sid := a.read("session")["sessionId"]
	b.read("session")

	a.write(out{"type": "untrust", "deviceId": b.id})
	if e := a.read("ended"); e["sessionId"] != sid {
		t.Fatalf("got %v", e)
	}
	if u := a.read("untrusted"); u["deviceId"] != b.id {
		t.Fatalf("got %v", u)
	}
	b.read("ended")
	b.write(out{"type": "connect", "to": a.id, "secret": "correct horse"})
	b.read("rejected")
}

func TestVisitorLeavingCancelsPrompt(t *testing.T) {
	_, url, _ := testServer(t)
	a, b := device(t, url), device(t, url)
	b.write(out{"type": "connect", "to": a.id, "code": a.newCode()})
	rid := a.read("incoming")["requestId"]
	b.conn.Close(websocket.StatusNormalClosure, "")
	if c := a.read("cancelled"); c["requestId"] != rid {
		t.Fatalf("got %v", c)
	}
}

func TestSessionCarriesTurnCredentials(t *testing.T) {
	h, url, _ := testServer(t)
	h.mu.Lock()
	h.iceURLs, h.turnSecret = []string{"turn:turn.example.com:3478"}, "s3cret"
	h.mu.Unlock()
	a, b := device(t, url), device(t, url)
	b.write(out{"type": "connect", "to": a.id, "code": a.newCode()})
	a.write(out{"type": "consent", "requestId": a.read("incoming")["requestId"], "accept": true})
	a.read("session")
	ice := b.read("session")["iceServers"].([]any)[0].(map[string]any)
	user := ice["username"].(string)
	if !strings.HasSuffix(user, ":"+b.id) {
		t.Fatalf("bad username %q", user)
	}
	// coturn recomputes exactly this from its static-auth-secret.
	mac := hmac.New(sha1.New, []byte("s3cret"))
	mac.Write([]byte(user))
	if ice["credential"] != base64.StdEncoding.EncodeToString(mac.Sum(nil)) {
		t.Fatalf("bad credential %v", ice)
	}
}
