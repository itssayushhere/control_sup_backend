// ControlSup signaling server: authenticates devices, brokers pairing,
// and relays WebRTC offer/answer/ICE messages. No media passes through here.
package main

import (
	"log"
	"net/http"
	"os"
	"strings"
)

func main() {
	addr := env("ADDR", ":8080")
	st, err := openStore(env("DB_PATH", "controlsup.db"))
	if err != nil {
		log.Fatal(err)
	}
	h := newHub(st)
	h.iceURLs = strings.Fields(strings.ReplaceAll(os.Getenv("ICE_URLS"), ",", " "))
	h.turnSecret = os.Getenv("TURN_SECRET")
	srv := newServer(h)

	if cert := os.Getenv("TLS_CERT"); cert != "" {
		log.Printf("signaling server listening on %s (wss)", addr)
		log.Fatal(http.ListenAndServeTLS(addr, cert, os.Getenv("TLS_KEY"), srv))
	}
	log.Printf("signaling server listening on %s (plain ws: put a TLS proxy in front, or set TLS_CERT/TLS_KEY)", addr)
	log.Fatal(http.ListenAndServe(addr, srv))
}

// newServer wires the HTTP routes. Tests reuse it with httptest.
func newServer(h *hub) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})
	mux.HandleFunc("GET /ws", h.serveWS)
	return mux
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
