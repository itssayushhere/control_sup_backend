package main

import (
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/json"

	"golang.org/x/crypto/argon2"
	_ "modernc.org/sqlite"
)

// store holds the only persistent data: secret hashes, who trusts whom, and with what powers.
type store struct{ db *sql.DB }

func openStore(path string) (*store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	// ponytail: one connection serializes writes (no SQLITE_BUSY); plenty for signaling volume.
	db.SetMaxOpenConns(1)
	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS secrets (device_id TEXT PRIMARY KEY, salt BLOB NOT NULL, hash BLOB NOT NULL);
		CREATE TABLE IF NOT EXISTS trusted (owner TEXT NOT NULL, peer TEXT NOT NULL, perms TEXT NOT NULL, PRIMARY KEY (owner, peer));`)
	return &store{db}, err
}

func hashSecret(secret string, salt []byte) []byte {
	return argon2.IDKey([]byte(secret), salt, 1, 64*1024, 4, 32)
}

func (s *store) setSecret(id, secret string) error {
	salt := make([]byte, 16)
	rand.Read(salt)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO secrets VALUES (?, ?, ?)`, id, salt, hashSecret(secret, salt))
	return err
}

func (s *store) checkSecret(id, secret string) bool {
	var salt, hash []byte
	if s.db.QueryRow(`SELECT salt, hash FROM secrets WHERE device_id = ?`, id).Scan(&salt, &hash) != nil {
		return false
	}
	return subtle.ConstantTimeCompare(hashSecret(secret, salt), hash) == 1
}

// trust saves (or updates) the powers owner grants peer. perms is stored as a JSON array.
func (s *store) trust(owner, peer string, perms []string) error {
	if perms == nil {
		perms = []string{}
	}
	j, _ := json.Marshal(perms)
	_, err := s.db.Exec(`INSERT OR REPLACE INTO trusted VALUES (?, ?, ?)`, owner, peer, string(j))
	return err
}

func (s *store) untrust(owner, peer string) error {
	_, err := s.db.Exec(`DELETE FROM trusted WHERE owner = ? AND peer = ?`, owner, peer)
	return err
}

// trustedPerms returns the powers owner granted peer, and whether peer is trusted at all.
func (s *store) trustedPerms(owner, peer string) ([]string, bool) {
	var j string
	if s.db.QueryRow(`SELECT perms FROM trusted WHERE owner = ? AND peer = ?`, owner, peer).Scan(&j) != nil {
		return nil, false
	}
	var perms []string
	return perms, json.Unmarshal([]byte(j), &perms) == nil
}
