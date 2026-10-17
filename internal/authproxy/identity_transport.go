package authproxy

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type identityTransport struct {
	next             http.RoundTripper
	key              ed25519.PrivateKey
	issuer, audience string
}

// RoundTrip runs after ReverseProxy has rewritten the URL and removed hop
// headers. Bind the assertion to exactly what the backend will receive.
func (t identityTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	principal, _ := r.Context().Value(principalContextKey{}).(Principal)
	if principal.Mechanism == "github" && len(t.key) != 0 {
		id, err := strconv.ParseInt(principal.ID, 10, 64)
		if err != nil || id <= 0 || strconv.FormatInt(id, 10) != principal.ID || !validGitHubLogin(principal.GitHubLogin) {
			return nil, errors.New("invalid authenticated GitHub identity")
		}
		now := time.Now().Truncate(time.Second)
		expires := now.Add(30 * time.Second)
		if principal.Expires.Before(expires) {
			expires = principal.Expires.Truncate(time.Second)
		}
		if !expires.After(now) {
			return nil, errUnauthorized
		}
		targetHash := sha256.Sum256([]byte(r.URL.RequestURI()))
		assertion := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
			"iss": t.issuer, "aud": t.audience, "sub": principal.ID, "github_login": principal.GitHubLogin,
			"method": r.Method, "request_uri_sha256": base64.RawURLEncoding.EncodeToString(targetHash[:]), "iat": now.Unix(), "exp": expires.Unix(), "jti": rand.Text(),
		})
		assertion.Header["typ"] = "otgo-identity+jwt"
		encoded, err := assertion.SignedString(t.key)
		if err != nil || len(encoded) > 4096 {
			return nil, errors.New("cannot sign bounded identity assertion")
		}
		r.Header.Set("X-Otgo-Identity", encoded)
	}
	return t.next.RoundTrip(r)
}
