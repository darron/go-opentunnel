package authproxy

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
)

type TokenInfo struct {
	ID      string    `json:"id"`
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires"`
}
type tokenRecord struct {
	TokenInfo
	Hash string `json:"hash"`
}
type tokenRegistry struct {
	Version int           `json:"version"`
	Tokens  []tokenRecord `json:"tokens"`
}
type TokenStore struct {
	path string
	now  func() time.Time
}

func (s *TokenStore) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "TokenStore{credentials:[REDACTED]}")
}
func NewTokenStore(path string) *TokenStore { return newTokenStore(path, time.Now) }
func newTokenStore(path string, now func() time.Time) *TokenStore {
	return &TokenStore{path: path, now: now}
}
func (s *TokenStore) load() (tokenRegistry, error) {
	b, e := readPrivate(s.path)
	if e != nil {
		return tokenRegistry{}, e
	}
	var r tokenRegistry
	if e = decodeStrict(b, &r); e != nil || r.Version != 1 || len(r.Tokens) > 256 {
		return tokenRegistry{}, errors.New("invalid token registry")
	}
	ids := make(map[string]bool)
	hashes := make(map[string]bool)
	for _, t := range r.Tokens {
		id, ie := hex.DecodeString(t.ID)
		hash, he := hex.DecodeString(t.Hash)
		if ie != nil || he != nil || len(id) != 12 || len(hash) != 32 || ids[t.ID] || hashes[t.Hash] || t.Created.IsZero() || !t.Created.Before(t.Expires) || t.Expires.Sub(t.Created) > 24*time.Hour {
			return tokenRegistry{}, errors.New("invalid token registry entry")
		}
		ids[t.ID] = true
		hashes[t.Hash] = true
	}
	return r, nil
}
func (s *TokenStore) save(r tokenRegistry) error {
	b, e := json.Marshal(r)
	if e != nil {
		return errors.New("cannot encode token registry")
	}
	return writePrivate(s.path, append(b, '\n'))
}
func (s *TokenStore) Create(ttl time.Duration) (secret, id string, err error) {
	if ttl == 0 {
		ttl = time.Hour
	}
	if ttl < 0 || ttl > 24*time.Hour {
		return "", "", errors.New("token lifetime must be positive and at most 24 hours")
	}
	err = withFileLock(s.path, func() error {
		r, e := s.load()
		if e != nil {
			if _, statErr := os.Lstat(s.path); !os.IsNotExist(statErr) {
				return e
			}
			r = tokenRegistry{Version: 1, Tokens: []tokenRecord{}}
		}
		now := s.now().UTC()
		active := r.Tokens[:0]
		for _, t := range r.Tokens {
			if now.Before(t.Expires) {
				active = append(active, t)
			}
		}
		r.Tokens = active
		if len(r.Tokens) >= 256 {
			return errors.New("token capacity reached")
		}
		secret = "otgo_" + randomSecret()
		id = hex.EncodeToString(randomBytes(12))
		hash := sha256.Sum256([]byte(secret))
		r.Tokens = append(r.Tokens, tokenRecord{TokenInfo: TokenInfo{ID: id, Created: now, Expires: now.Add(ttl)}, Hash: hex.EncodeToString(hash[:])})
		return s.save(r)
	})
	if err != nil {
		return "", "", err
	}
	return secret, id, nil
}
func (s *TokenStore) Authenticate(secret string) (Principal, error) {
	if len(secret) != 48 || !strings.HasPrefix(secret, "otgo_") {
		return Principal{}, errUnauthorized
	}
	r, e := s.load()
	if e != nil {
		return Principal{}, errUnauthorized
	}
	hash := sha256.Sum256([]byte(secret))
	for _, t := range r.Tokens {
		expected, _ := hex.DecodeString(t.Hash)
		if subtle.ConstantTimeCompare(hash[:], expected) == 1 && s.now().Before(t.Expires) {
			return Principal{ID: t.ID, Mechanism: "token", Expires: t.Expires}, nil
		}
	}
	return Principal{}, errUnauthorized
}
func (s *TokenStore) List() ([]TokenInfo, error) {
	r, e := s.load()
	if e != nil {
		return nil, e
	}
	result := make([]TokenInfo, 0, len(r.Tokens))
	for _, t := range r.Tokens {
		result = append(result, t.TokenInfo)
	}
	return result, nil
}
func (s *TokenStore) Revoke(id string) error {
	return withFileLock(s.path, func() error {
		r, e := s.load()
		if e != nil {
			return e
		}
		found := false
		kept := r.Tokens[:0]
		for _, t := range r.Tokens {
			if t.ID == id {
				found = true
			} else {
				kept = append(kept, t)
			}
		}
		if !found {
			return errors.New("unknown token ID")
		}
		r.Tokens = kept
		return s.save(r)
	})
}
