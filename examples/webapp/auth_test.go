package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/golang-jwt/jwt/v5"
)

const testIssuer = "https://example.opentunnel.xyz"
const testAudience = "http://127.0.0.1:8080"

func testIdentityConfig(t *testing.T) (identityConfig, ed25519.PrivateKey) {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "otgo.pub")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), 0600); err != nil {
		t.Fatal(err)
	}
	return identityConfig{PublicKey: path, Issuer: testIssuer, Audience: testAudience}, key
}

// Build fixtures independently of the proxy signer and verifier.
func signedHeaders(t *testing.T, key ed25519.PrivateKey, audience, method, target string, expired bool) http.Header {
	t.Helper()
	now := time.Now().Truncate(time.Second)
	if expired {
		now = now.Add(-time.Minute)
	}
	hash := sha256.Sum256([]byte(target))
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": testIssuer, "aud": audience, "sub": "5176", "github_login": "darron",
		"iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": "example-test",
		"method": method, "request_uri_sha256": base64.RawURLEncoding.EncodeToString(hash[:]),
	})
	token.Header["typ"] = "otgo-identity+jwt"
	encoded, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return http.Header{"X-Otgo-Identity": {encoded}, "X-Github-User": {"darron"}, "X-Github-Id": {"5176"}}
}

func TestIdentityGateProtectsEveryRoute(t *testing.T) {
	cfg, _ := testIdentityConfig(t)
	handler, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodOptions} {
		for _, path := range []string{"/", "/whoami", "/request", "/stream", "/ws", "/mcp", "/unknown"} {
			t.Run(method+path, func(t *testing.T) {
				r := httptest.NewRequestWithContext(t.Context(), method, path, nil)
				r.Host = "127.0.0.1:8080"
				// Headers alone are not authentication.
				r.Header.Set("X-GitHub-User", "darron")
				r.Header.Set("X-GitHub-ID", "5176")
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "darron") {
					t.Fatalf("unverified request reached app: status=%d body=%q", w.Code, w.Body.String())
				}
			})
		}
	}
}

func TestIdentityGateRejectsInvalidAssertions(t *testing.T) {
	cfg, key := testIdentityConfig(t)
	handler, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		edit func(*http.Request)
	}{
		{"expired", func(r *http.Request) { r.Header = signedHeaders(t, key, testAudience, "GET", "/whoami", true) }},
		{"wrong key", func(r *http.Request) { r.Header = signedHeaders(t, other, testAudience, "GET", "/whoami", false) }},
		{"wrong audience", func(r *http.Request) {
			r.Header = signedHeaders(t, key, "http://127.0.0.1:9000", "GET", "/whoami", false)
		}},
		{"changed target", func(r *http.Request) { r.URL.RawQuery = "changed=1"; r.RequestURI = "/whoami?changed=1" }},
		{"changed method", func(r *http.Request) { r.Method = http.MethodPost }},
		{"forged user", func(r *http.Request) { r.Header.Set("X-GitHub-User", "someone-else") }},
		{"duplicate assertion", func(r *http.Request) { r.Header.Add("X-Otgo-Identity", r.Header.Get("X-Otgo-Identity")) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/whoami", nil)
			r.Host = "127.0.0.1:8080"
			r.Header = signedHeaders(t, key, testAudience, "GET", "/whoami", false)
			tc.edit(r)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "darron") || strings.Contains(w.Body.String(), r.Header.Get("X-Otgo-Identity")) {
				t.Fatalf("invalid assertion: status=%d body=%q", w.Code, w.Body.String())
			}
		})
	}
}

func TestIdentityGateServesVerifiedUserAndStreams(t *testing.T) {
	cfg, key := testIdentityConfig(t)
	handler, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/whoami?view=full", "/stream"} {
		r := httptest.NewRequestWithContext(t.Context(), http.MethodGet, path, nil)
		r.Host = "127.0.0.1:8080"
		r.Header = signedHeaders(t, key, testAudience, "GET", path, false)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		if w.Code != http.StatusOK || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status=%d headers=%v", path, w.Code, w.Header())
		}
		if strings.HasPrefix(path, "/whoami") {
			var user struct{ Login, ID string }
			if err := json.Unmarshal(w.Body.Bytes(), &user); err != nil || user.Login != "darron" || user.ID != "5176" {
				t.Fatalf("verified identity: %s, err=%v", w.Body.String(), err)
			}
			if strings.Contains(w.Body.String(), "AssertionID") || strings.Contains(w.Body.String(), r.Header.Get("X-Otgo-Identity")) {
				t.Fatal("whoami leaked assertion material")
			}
		} else if w.Body.String() != "chunk 1\nchunk 2\nchunk 3\n" || !w.Flushed {
			t.Fatalf("stream broken: %q, flushed=%v", w.Body.String(), w.Flushed)
		}
	}
}

func TestIdentityGateHTTPAndWebSocket(t *testing.T) {
	cfg, key := testIdentityConfig(t)
	// Configure the real listener origin before serving, without racing handlers.
	server := httptest.NewUnstartedServer(nil)
	cfg.Audience = "http://" + server.Listener.Addr().String()
	handler, err := newHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	server.Config.Handler = handler
	server.Start()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// Exercise the same middleware over HTTP with the server's real Host/URI.
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/whoami?source=test", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header = signedHeaders(t, key, cfg.Audience, "GET", "/whoami?source=test", false)
	response, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK || string(body) != "{\"login\":\"darron\",\"id\":\"5176\"}\n" {
		t.Fatalf("HTTP identity: status=%d body=%q err=%v", response.StatusCode, body, err)
	}
	wsURL := "ws" + strings.TrimPrefix(server.URL, "http") + "/ws"
	conn, resp, err := websocket.Dial(ctx, wsURL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if conn != nil {
		_ = conn.CloseNow()
	}
	if err == nil || resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unsigned WebSocket admitted: %v, %v", resp, err)
	}
	conn, resp, err = websocket.Dial(ctx, wsURL, &websocket.DialOptions{HTTPHeader: signedHeaders(t, key, cfg.Audience, "GET", "/ws", false)})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	if err := conn.Write(ctx, websocket.MessageText, []byte("authenticated echo")); err != nil {
		t.Fatal(err)
	}
	typ, body, err := conn.Read(ctx)
	if err != nil || typ != websocket.MessageText || string(body) != "authenticated echo" {
		t.Fatalf("echo: %q, %v", body, err)
	}
}

func TestIdentityConfigurationFailsClosed(t *testing.T) {
	cfg, _ := testIdentityConfig(t)
	for _, tc := range []struct {
		name string
		edit func(*identityConfig)
	}{
		{"no key", func(c *identityConfig) { c.PublicKey = "" }},
		{"no issuer", func(c *identityConfig) { c.Issuer = "" }},
		{"no audience", func(c *identityConfig) { c.Audience = "" }},
		{"missing file", func(c *identityConfig) { c.PublicKey += ".missing" }},
		{"issuer must be https", func(c *identityConfig) { c.Issuer = "http://example.opentunnel.xyz" }},
		{"audience path", func(c *identityConfig) { c.Audience += "/" }},
		{"audience credentials", func(c *identityConfig) { c.Audience = "http://user@127.0.0.1:8080" }},
		{"invalid key", func(c *identityConfig) {
			c.PublicKey = filepath.Join(t.TempDir(), "invalid.pub")
			if err := os.WriteFile(c.PublicKey, []byte("invalid"), 0600); err != nil {
				t.Fatal(err)
			}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := cfg
			tc.edit(&bad)
			if handler, err := newHandler(bad); err == nil || handler != nil {
				t.Fatal("invalid configuration did not prevent startup")
			}
		})
	}
}

func TestExplicitEmptyIdentityFlagsFailClosed(t *testing.T) {
	if handler, err := newHandler(identityConfig{requested: true}); err == nil || handler != nil {
		t.Fatal("explicit empty identity flags silently disabled authentication")
	}
}

func TestExampleRemainsUnprotectedWithoutIdentityFlags(t *testing.T) {
	handler, err := newHandler(identityConfig{})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	r, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil || resp.StatusCode != http.StatusOK || string(body) != "go-opentunnel embedded example\n" {
		t.Fatalf("existing example changed: status=%d body=%q err=%v", resp.StatusCode, body, err)
	}
}
