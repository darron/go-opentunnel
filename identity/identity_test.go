package identity

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifyRequest(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	options := VerifyOptions{Issuer: "https://demo.test", Audience: "http://127.0.0.1:8000"}
	claims := func() jwt.MapClaims {
		return jwt.MapClaims{"iss": "https://demo.test", "aud": "http://127.0.0.1:8000", "sub": "123", "github_login": "renamed-user", "method": "POST", "request_uri_sha256": "b8eGQnLmhYhLCqNleRxy349HRmh6qyswkfd3HNKColQ", "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": "unique-assertion"}
	}
	for _, name := range []string{"valid", "valid https", "altered signature", "wrong key", "wrong issuer", "wrong audience", "https audience on http", "http audience on https", "method", "path", "query order", "raw target mismatch", "host", "duplicate assertion", "duplicate user", "wrong user", "wrong id", "identity trailer", "expired", "future", "missing iat", "missing exp", "long lifetime", "zero lifetime", "wrong algorithm", "wrong type", "bad subject", "bad login", "missing request uri", "missing issuer option", "missing audience option"} {
		t.Run(name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), "POST", "/mcp%2Fone?a=1&a=2", nil)
			r.Host = "127.0.0.1:8000"
			c := claims()
			key := public
			opts := options
			method := jwt.SigningMethod(jwt.SigningMethodEdDSA)
			var signingKey any = private
			typ := "otgo-identity+jwt"
			switch name {
			case "wrong key":
				key, _, err = ed25519.GenerateKey(rand.Reader)
				if err != nil {
					t.Fatal(err)
				}
			case "wrong issuer":
				c["iss"] = "https://other.test"
			case "wrong audience":
				c["aud"] = "http://127.0.0.1:8001"
			case "valid https":
				c["aud"] = "https://127.0.0.1:8000"
				opts.Audience = "https://127.0.0.1:8000"
				r.TLS = &tls.ConnectionState{HandshakeComplete: true}
			case "https audience on http":
				c["aud"] = "https://127.0.0.1:8000"
				opts.Audience = "https://127.0.0.1:8000"
			case "http audience on https":
				r.TLS = &tls.ConnectionState{HandshakeComplete: true}
			case "method":
				r.Method = "GET"
			case "path":
				r.URL.Path = "/other"
				r.URL.RawPath = ""
			case "raw target mismatch":
				r.RequestURI += "#fragment"
			case "query order":
				r.URL.RawQuery = "a=2&a=1"
			case "host":
				r.Host = "other.test"
			case "expired":
				c["iat"] = now.Add(-time.Minute).Unix()
				c["exp"] = now.Add(-30 * time.Second).Unix()
			case "future":
				c["iat"] = now.Add(time.Minute).Unix()
				c["exp"] = now.Add(90 * time.Second).Unix()
			case "missing iat":
				delete(c, "iat")
			case "missing exp":
				delete(c, "exp")
			case "long lifetime":
				c["exp"] = now.Add(time.Hour).Unix()
			case "zero lifetime":
				c["exp"] = now.Unix()
			case "wrong algorithm":
				method = jwt.SigningMethodHS256
				signingKey = []byte(public)
			case "wrong type":
				typ = "JWT"
			case "bad subject":
				c["sub"] = "-1"
			case "bad login":
				c["github_login"] = "bad\r\nheader"
			case "missing request uri":
				delete(c, "request_uri_sha256")
			case "missing issuer option":
				opts.Issuer = ""
			case "missing audience option":
				opts.Audience = ""
			}
			token := jwt.NewWithClaims(method, c)
			token.Header["typ"] = typ
			encoded, err := token.SignedString(signingKey)
			if err != nil {
				t.Fatal(err)
			}
			if name == "altered signature" {
				parts := strings.Split(encoded, ".")
				parts[2] = "A" + parts[2][1:]
				if strings.Join(parts, ".") == encoded {
					parts[2] = "B" + parts[2][1:]
				}
				encoded = strings.Join(parts, ".")
			}
			r.Header.Set("X-Otgo-Identity", encoded)
			r.Header.Set("X-GitHub-User", "renamed-user")
			r.Header.Set("X-GitHub-ID", "123")
			switch name {
			case "duplicate assertion":
				r.Header.Add("X-Otgo-Identity", encoded)
			case "duplicate user":
				r.Header["x-github-user"] = []string{"attacker"}
			case "wrong user":
				r.Header.Set("X-GitHub-User", "attacker")
			case "wrong id":
				r.Header.Set("X-GitHub-ID", "456")
			case "identity trailer":
				r.Trailer = http.Header{"X-Github-User": nil}
			}
			got, err := VerifyRequest(r, key, opts)
			if name == "valid" || name == "valid https" {
				if err != nil || got.ID != "123" || got.Login != "renamed-user" || !got.ExpiresAt.Equal(now.Add(30*time.Second)) {
					t.Fatalf("valid: %+v %v", got, err)
				}
			} else if err == nil {
				t.Fatalf("accepted %s: %+v", name, got)
			}
		})
	}
}

func TestParsePublicKey(t *testing.T) {
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	b := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	got, err := ParsePublicKey(b)
	if err != nil || !public.Equal(got) {
		t.Fatalf("key: %v", err)
	}
	for _, bad := range [][]byte{nil, []byte("garbage"), append(append([]byte(nil), b...), b...), append(append([]byte(nil), b...), []byte("garbage")...)} {
		if _, err := ParsePublicKey(bad); err == nil {
			t.Fatal("accepted malformed key")
		}
	}
}

// Exercise Go's real HTTP parser: it reconstructs /a#b as /a%23b, although
// those are distinct wire targets. A signature for the latter must not admit it.
func TestVerifyRequestRejectsRequestTargetAliases(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://demo.test", "aud": "http://backend.test", "sub": "123", "github_login": "fixture-user", "method": "GET", "request_uri_sha256": requestTargetHash("/a%23b"), "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": "parser-fixture",
	})
	token.Header["typ"] = "otgo-identity+jwt"
	encoded, err := token.SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range []string{"/a%23b", "/a#b", "http://backend.test/a%23b"} {
		t.Run(target, func(t *testing.T) {
			wire := "GET " + target + " HTTP/1.1\r\nHost: backend.test\r\nX-GitHub-User: fixture-user\r\nX-GitHub-ID: 123\r\nX-Otgo-Identity: " + encoded + "\r\n\r\n"
			request, err := http.ReadRequest(bufio.NewReader(strings.NewReader(wire)))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = request.Body.Close() }()
			_, err = VerifyRequest(request, public, VerifyOptions{Issuer: "https://demo.test", Audience: "http://backend.test"})
			if (err == nil) != (target == "/a%23b") {
				t.Fatalf("target %q, parsed %q: %v", target, request.URL.RequestURI(), err)
			}
		})
	}
}
