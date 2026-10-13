package main

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
)

const (
	codeTTL        = 10 * time.Minute
	maxCodeGuesses = 5 // wrong guesses from any device before the code is replaced
	minSecret      = 8
)

// knownPerms are the powers A can grant a connecting device. A's own client enforces them.
var knownPerms = map[string]bool{
	"view": true, "voice": true, "control": true, "clipboard": true,
	"files_send": true, "files_receive": true, "terminal": true,
}

// msg is every message a client can send; each type uses a subset of fields.
type msg struct {
	Type      string          `json:"type"`
	Pubkey    string          `json:"pubkey"`
	Sig       string          `json:"sig"`
	To        string          `json:"to"`
	Code      string          `json:"code"`
	Secret    string          `json:"secret"`
	RequestID string          `json:"requestId"`
	Accept    bool            `json:"accept"`
	Trust     bool            `json:"trust"`
	Perms     []string        `json:"perms"`
	SessionID string          `json:"sessionId"`
	DeviceID  string          `json:"deviceId"`
	Data      json.RawMessage `json:"data"`
}

// out is any message the server sends.
type out map[string]any

type client struct {
	id   string
	conn *websocket.Conn
	q    chan out
}

// send never blocks the hub: a client too slow to drain its queue is dropped.
func (c *client) send(m out) {
	select {
	case c.q <- m:
	default:
		c.conn.CloseNow()
	}
}

func (c *client) writeLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case m := <-c.q:
			wctx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err := wsjson.Write(wctx, c.conn, m)
			cancel()
			if err != nil {
				c.conn.CloseNow()
				return
			}
		}
	}
}

type oneTimeCode struct {
	code    string
	expires time.Time
	wrong   int // wrong guesses so far, from any device
}

type request struct{ from, to *client }

type session struct{ a, b *client }

// hub is all live, in-memory state. One mutex guards everything.
// ponytail: global lock, fine for one instance; shard or move to Redis if you scale out.
type hub struct {
	mu       sync.Mutex
	store    *store
	now      func() time.Time // swapped in tests to move time forward
	clients  map[string]*client
	codes    map[string]*oneTimeCode // target device ID -> its current code
	pending  map[string]*request
	sessions map[string]*session
}

func newHub(st *store) *hub {
	return &hub{
		store:    st,
		now:      time.Now,
		clients:  map[string]*client{},
		codes:    map[string]*oneTimeCode{},
		pending:  map[string]*request{},
		sessions: map[string]*session{},
	}
}

func (h *hub) serveWS(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, nil)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	id, err := handshake(ctx, conn)
	if err != nil {
		conn.Close(websocket.StatusPolicyViolation, "auth failed")
		return
	}

	c := &client{id: id, conn: conn, q: make(chan out, 32)}
	go c.writeLoop(ctx)
	h.register(c)
	defer h.unregister(c)

	for {
		var m msg
		if err := wsjson.Read(ctx, conn, &m); err != nil {
			return
		}
		h.handle(c, m)
	}
}

func (h *hub) register(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if old := h.clients[c.id]; old != nil {
		old.conn.CloseNow() // same device reconnected; the newest socket wins
	}
	h.clients[c.id] = c
	c.send(out{"type": "authed", "deviceId": c.id}) // under the lock, so it's always the first message
}

func (h *hub) unregister(c *client) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.clients[c.id] == c {
		delete(h.clients, c.id)
	}
	for id, s := range h.sessions {
		if s.a == c || s.b == c {
			s.a.send(out{"type": "ended", "sessionId": id})
			s.b.send(out{"type": "ended", "sessionId": id})
			delete(h.sessions, id)
		}
	}
	for id, p := range h.pending {
		if p.from == c || p.to == c {
			p.from.send(out{"type": "rejected", "reason": "unavailable"})
			delete(h.pending, id)
		}
	}
}

func (h *hub) handle(c *client, m msg) {
	switch m.Type {
	case "new_code":
		h.mu.Lock()
		h.issueCode(c)
		h.mu.Unlock()
	case "set_secret":
		if len(m.Secret) < minSecret {
			c.send(out{"type": "error", "reason": "secret too short"})
			return
		}
		if err := h.store.setSecret(c.id, m.Secret); err != nil {
			log.Print(err)
			c.send(out{"type": "error", "reason": "internal"})
			return
		}
		c.send(out{"type": "secret_set"})
	case "connect":
		h.connect(c, m)
	case "consent":
		h.consent(c, m)
	case "signal":
		h.signal(c, m)
	case "end":
		h.end(c, m)
	case "untrust":
		if err := h.store.untrust(c.id, m.DeviceID); err != nil {
			log.Print(err)
		}
	default:
		c.send(out{"type": "error", "reason": "unknown type"})
	}
}

// issueCode gives c a fresh one-time code, replacing any older one. Caller holds h.mu.
func (h *hub) issueCode(c *client) {
	n, _ := rand.Int(rand.Reader, big.NewInt(1_000_000_000))
	otc := &oneTimeCode{code: fmt.Sprintf("%09d", n), expires: h.now().Add(codeTTL)}
	h.codes[c.id] = otc
	c.send(out{"type": "code", "code": otc.code, "expiresAt": otc.expires.Unix()})
}

func (h *hub) connect(c *client, m msg) {
	// Argon2 is slow on purpose, so check the secret before taking the lock.
	var perms []string
	secretOK := false
	if m.Secret != "" {
		var trusted bool
		perms, trusted = h.store.trustedPerms(m.To, c.id)
		secretOK = trusted && h.store.checkSecret(m.To, m.Secret)
	}

	h.mu.Lock()
	defer h.mu.Unlock()
	target := h.clients[m.To]
	if target == nil || target == c {
		c.send(out{"type": "rejected", "reason": "unavailable"})
		return
	}

	ok := secretOK
	if m.Secret == "" {
		otc := h.codes[m.To]
		ok = otc != nil && h.now().Before(otc.expires) && subtle.ConstantTimeCompare([]byte(otc.code), []byte(m.Code)) == 1
		if ok {
			delete(h.codes, m.To) // single use
		} else if otc != nil {
			// Count guesses per code, not per device: new keypairs are free,
			// so a per-device limit could be dodged. No one is locked out;
			// the code just changes and A reads the new one to the real visitor.
			if otc.wrong++; otc.wrong >= maxCodeGuesses {
				h.issueCode(target)
			}
		}
	}
	if !ok {
		c.send(out{"type": "rejected", "reason": "denied"}) // same reply for wrong code or secret
		return
	}

	if m.Secret != "" { // trusted device: no prompt, just tell the target who's in
		target.send(out{"type": "incoming", "from": c.id, "needsConsent": false})
		h.startSession(c, target, perms) // the powers A saved for this device last time
		return
	}
	id := randomID()
	h.pending[id] = &request{from: c, to: target}
	target.send(out{"type": "incoming", "requestId": id, "from": c.id, "needsConsent": true})
}

func (h *hub) consent(c *client, m msg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	p := h.pending[m.RequestID]
	if p == nil || p.to != c {
		c.send(out{"type": "error", "reason": "unknown request"})
		return
	}
	for _, perm := range m.Perms {
		if !knownPerms[perm] {
			c.send(out{"type": "error", "reason": "unknown perm " + perm}) // request stays pending; A can retry
			return
		}
	}
	delete(h.pending, m.RequestID)
	if !m.Accept {
		p.from.send(out{"type": "rejected", "reason": "declined"})
		return
	}
	if m.Trust { // save the choice so A isn't asked again for this device
		if err := h.store.trust(c.id, p.from.id, m.Perms); err != nil {
			log.Print(err)
		}
	}
	h.startSession(p.from, c, m.Perms)
}

// startSession pairs two sockets. The initiator creates the WebRTC offer; perms are what
// the target (other) granted it, sent to both so A enforces them and B knows what it got.
// Caller holds h.mu.
func (h *hub) startSession(initiator, other *client, perms []string) {
	if perms == nil {
		perms = []string{} // JSON [] rather than null
	}
	id := randomID()
	h.sessions[id] = &session{initiator, other}
	initiator.send(out{"type": "session", "sessionId": id, "peer": other.id, "initiator": true, "perms": perms})
	other.send(out{"type": "session", "sessionId": id, "peer": initiator.id, "initiator": false, "perms": perms})
}

// signal relays SDP/ICE only between the two members of an active session.
func (h *hub) signal(c *client, m msg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[m.SessionID]
	var peer *client
	switch {
	case s == nil:
	case s.a == c:
		peer = s.b
	case s.b == c:
		peer = s.a
	}
	if peer == nil {
		c.send(out{"type": "error", "reason": "no session"})
		return
	}
	peer.send(out{"type": "signal", "sessionId": m.SessionID, "from": c.id, "data": m.Data})
}

func (h *hub) end(c *client, m msg) {
	h.mu.Lock()
	defer h.mu.Unlock()
	s := h.sessions[m.SessionID]
	if s == nil || (s.a != c && s.b != c) {
		return
	}
	delete(h.sessions, m.SessionID)
	s.a.send(out{"type": "ended", "sessionId": m.SessionID})
	s.b.send(out{"type": "ended", "sessionId": m.SessionID})
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
