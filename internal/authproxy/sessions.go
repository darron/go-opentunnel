package authproxy

import (
	"crypto/sha256"
	"errors"
	"sync"
	"time"
)

type Principal struct {
	ID        string    `json:"id"`
	Mechanism string    `json:"mechanism"`
	Expires   time.Time `json:"expires"`
}

var errUnauthorized = errors.New("invalid or expired credential")

type Sessions struct {
	mu      sync.Mutex
	entries map[[32]byte]Principal
	limit   int
	now     func() time.Time
	closed  bool
}

func NewSessions(limit int) *Sessions { return newSessions(limit, time.Now) }
func newSessions(limit int, now func() time.Time) *Sessions {
	if limit <= 0 || limit > 1024 {
		limit = 1024
	}
	return &Sessions{entries: make(map[[32]byte]Principal), limit: limit, now: now}
}
func (s *Sessions) Create(p Principal, ttl time.Duration) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || ttl <= 0 || ttl > 24*time.Hour {
		return "", errors.New("session service closed or invalid lifetime")
	}
	now := s.now()
	for key, p := range s.entries {
		if !now.Before(p.Expires) {
			delete(s.entries, key)
		}
	}
	if len(s.entries) >= s.limit {
		return "", errors.New("session capacity reached")
	}
	p.Expires = now.Add(ttl)
	secret := randomSecret()
	s.entries[sha256.Sum256([]byte(secret))] = p
	return secret, nil
}
func (s *Sessions) Authenticate(secret string) (Principal, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || len(secret) != 43 {
		return Principal{}, errUnauthorized
	}
	key := sha256.Sum256([]byte(secret))
	p, ok := s.entries[key]
	if !ok || !s.now().Before(p.Expires) {
		delete(s.entries, key)
		return Principal{}, errUnauthorized
	}
	return p, nil
}
func (s *Sessions) Revoke(secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.entries, sha256.Sum256([]byte(secret)))
}
func (s *Sessions) Close() { s.mu.Lock(); defer s.mu.Unlock(); s.closed = true; clear(s.entries) }
