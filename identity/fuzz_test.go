package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// The fuzzer can change the wire assertion and request independently. Only the
// original signed routing fields may verify with this pinned public key.
func FuzzVerifyRequest(f *testing.F) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": "https://demo.test", "aud": "http://127.0.0.1:8000", "sub": "123", "github_login": "fixture-user", "method": "POST", "request_uri_sha256": "KxJrhKRERiROulKshQ-flw4Ibbix0Q5ADx0j3VlzTz4", "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": "fuzz-fixture"})
	token.Header["typ"] = "otgo-identity+jwt"
	encoded, err := token.SignedString(private)
	if err != nil {
		f.Fatal(err)
	}
	f.Add("POST", "/mcp%2Fstream?a=1&a=2", "127.0.0.1:8000", encoded)
	f.Add("GET", "/other", "other.test", "e30.e30.fake")
	f.Fuzz(func(t *testing.T, method, uri, host, assertion string) {
		if len(uri) > 8192 || len(method) > 128 || len(host) > 512 {
			return
		}
		u, err := url.ParseRequestURI(uri)
		if err != nil {
			return
		}
		wireAssertion := assertion
		if assertion == encoded {
			// Keep the valid seed live throughout a sustained run; expiry must not
			// turn the request-binding checks into unconditional rejection.
			fresh := time.Now().Truncate(time.Second)
			refreshed := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{"iss": "https://demo.test", "aud": "http://127.0.0.1:8000", "sub": "123", "github_login": "fixture-user", "method": "POST", "request_uri_sha256": requestTargetHash("/mcp%2Fstream?a=1&a=2"), "iat": fresh.Unix(), "exp": fresh.Add(30 * time.Second).Unix(), "jti": "fuzz-fixture"})
			refreshed.Header["typ"] = "otgo-identity+jwt"
			wireAssertion, err = refreshed.SignedString(private)
			if err != nil {
				t.Fatal(err)
			}
		}
		r := &http.Request{Method: method, URL: u, RequestURI: uri, Host: host, Header: http.Header{"X-Otgo-Identity": {wireAssertion}, "X-Github-User": {"fixture-user"}, "X-Github-Id": {"123"}}}
		user, err := VerifyRequest(r, public, VerifyOptions{Issuer: "https://demo.test", Audience: "http://127.0.0.1:8000"})
		if err == nil && (assertion != encoded || method != "POST" || uri != "/mcp%2Fstream?a=1&a=2" || !strings.EqualFold(host, "127.0.0.1:8000") || user.ID != "123" || user.Login != "fixture-user") {
			t.Fatalf("forged identity admitted: %+v", user)
		}
	})
}
