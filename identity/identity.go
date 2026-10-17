// Package identity verifies the GitHub identity assertions sent by otgo to a
// protected backend. Pin the profile's public key locally; never take a key,
// issuer or audience from an incoming request.
package identity

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// VerifyOptions identifies the expected otgo public origin and backend origin.
// Both must be explicit scheme://host[:port] values without a trailing slash.
// For example: https://example.opentunnel.xyz and http://127.0.0.1:8000.
type VerifyOptions struct {
	Issuer   string
	Audience string
}

// GitHubIdentity is verified profile testimony about a GitHub browser session.
// Login was checked at sign-in; ID remains stable if the user renames the account.
// An assertion can be replayed until ExpiresAt. Request bodies are not signed.
type GitHubIdentity struct {
	ID          string
	Login       string
	IssuedAt    time.Time
	ExpiresAt   time.Time
	AssertionID string
}

type claims struct {
	jwt.RegisteredClaims
	Login             string `json:"github_login"`
	Method            string `json:"method"`
	RequestTargetHash string `json:"request_uri_sha256"`
}

var errInvalid = errors.New("invalid otgo identity assertion")

// ParsePublicKey reads a single Ed25519 PKIX PUBLIC KEY PEM block, as exported
// by otgo auth public-key. Public keys need integrity protection, not secrecy.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("expected one Ed25519 PUBLIC KEY PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("invalid identity public key")
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("identity public key must be Ed25519")
	}
	return key, nil
}

// VerifyRequest authenticates X-Otgo-Identity with a locally pinned key. It
// requires matching X-GitHub-User and X-GitHub-ID headers, issuer, audience,
// backend Host and TLS scheme, method and exact escaped path/query, and a valid
// lifetime of at most 30 seconds. Call it before trusting identity headers or processing a body.
// It does not authenticate a request body, enforce one-time use, or continuously
// reauthenticate an established stream. A bad or missing assertion is an error.
func VerifyRequest(r *http.Request, key ed25519.PublicKey, options VerifyOptions) (GitHubIdentity, error) {
	if r == nil || r.URL == nil || r.RequestURI == "" || r.RequestURI != r.URL.RequestURI() || len(key) != ed25519.PublicKeySize || !validOrigin(options.Issuer, true) || !validOrigin(options.Audience, false) {
		return GitHubIdentity{}, errInvalid
	}
	audience, _ := url.Parse(options.Audience)
	if !strings.EqualFold(r.Host, audience.Host) || (audience.Scheme == "https") != (r.TLS != nil) {
		return GitHubIdentity{}, errInvalid
	}
	encoded, ok := oneHeader(r.Header, "X-Otgo-Identity")
	if !ok || len(encoded) > 4096 {
		return GitHubIdentity{}, errInvalid
	}
	for name := range r.Trailer {
		lower := strings.ToLower(name)
		if strings.HasPrefix(lower, "x-otgo-") || strings.HasPrefix(lower, "x-github-") {
			return GitHubIdentity{}, errInvalid
		}
	}
	var c claims
	token, err := jwt.ParseWithClaims(encoded, &c, func(_ *jwt.Token) (any, error) { return key, nil }, jwt.WithValidMethods([]string{"EdDSA"}), jwt.WithIssuer(options.Issuer), jwt.WithAudience(options.Audience), jwt.WithExpirationRequired(), jwt.WithIssuedAt(), jwt.WithStrictDecoding())
	if err != nil || !token.Valid || token.Header["typ"] != "otgo-identity+jwt" || c.IssuedAt == nil || c.ExpiresAt == nil || len(c.Audience) != 1 || c.ID == "" || len(c.ID) > 128 {
		return GitHubIdentity{}, errInvalid
	}
	lifetime := c.ExpiresAt.Sub(c.IssuedAt.Time)
	id, err := strconv.ParseInt(c.Subject, 10, 64)
	if lifetime <= 0 || lifetime > 30*time.Second || err != nil || id <= 0 || strconv.FormatInt(id, 10) != c.Subject || !validLogin(c.Login) || c.Method != r.Method || c.RequestTargetHash != requestTargetHash(r.RequestURI) {
		return GitHubIdentity{}, errInvalid
	}
	login, okLogin := oneHeader(r.Header, "X-GitHub-User")
	subject, okID := oneHeader(r.Header, "X-GitHub-ID")
	if !okLogin || !okID || login != c.Login || subject != c.Subject {
		return GitHubIdentity{}, errInvalid
	}
	return GitHubIdentity{ID: c.Subject, Login: c.Login, IssuedAt: c.IssuedAt.Time, ExpiresAt: c.ExpiresAt.Time, AssertionID: c.ID}, nil
}

func oneHeader(header http.Header, name string) (string, bool) {
	var value string
	found := false
	for k, values := range header {
		if !strings.EqualFold(k, name) {
			continue
		}
		if found || len(values) != 1 || values[0] == "" {
			return "", false
		}
		value = values[0]
		found = true
	}
	return value, found
}
func validOrigin(raw string, httpsOnly bool) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Host != "" && u.User == nil && u.Opaque == "" && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && (u.Scheme == "https" || !httpsOnly && u.Scheme == "http")
}
func validLogin(login string) bool {
	if len(login) == 0 || len(login) > 39 || login[0] == '-' || login[len(login)-1] == '-' {
		return false
	}
	for _, c := range login {
		valid := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
		if !valid {
			return false
		}
	}
	return true
}

func requestTargetHash(target string) string {
	digest := sha256.Sum256([]byte(target))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}
