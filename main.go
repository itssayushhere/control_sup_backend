// ControlSup signaling server: authenticates devices, brokers pairing,
// and relays WebRTC offer/answer/ICE messages. No media passes through here.
package main

import (
	"log"
	"net/http"
	"os"
)

func main() {
	addr := env("ADDR", ":8080")
	st, err := openStore(env("DB_PATH", "controlsup.db"))
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("signaling server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, newServer(newHub(st))))
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
