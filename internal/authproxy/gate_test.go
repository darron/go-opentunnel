package authproxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testHandler(t *testing.T, upstream http.Handler) (*Handler, *Sessions, *TokenStore) {
	t.Helper()
	backend := httptest.NewServer(upstream)
	t.Cleanup(backend.Close)
	cfg := fixtureConfig()
	cfg.Upstream = backend.URL
	v, err := NewPasswordVerifier([]byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Password = v
	s := NewSessions(1024)
	tokens := NewTokenStore(filepath.Join(secureTempDir(t), "tokens.json"))
	h, err := NewHandler(Options{Config: cfg, Sessions: s, TokenStore: tokens})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h, s, tokens
}
func publicRequest(method, path string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, "https://demo.test"+path, nil)
	r.Host = "demo.test"
	r.URL.Scheme = ""
	r.URL.Host = ""
	r.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: "demo.test"}
	return r
}
func runRequest(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func browserSession(t *testing.T, s *Sessions) string {
	t.Helper()
	secret, err := s.Create(Principal{ID: "user", Mechanism: "password"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return secret
}
func addSession(r *http.Request, secret string) {
	r.AddCookie(authCookie(SessionCookie, secret, 0))
}

func TestGateNeverCallsUpstreamWithoutAuth(t *testing.T) {
	var calls atomic.Int32
	h, _, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT"} {
		for _, path := range []string{"/", "/health", "/static/app.js", "/mcp", "/.well-known/oauth-protected-resource", "/api/../mcp", "/%6dcp", "//mcp"} {
			r := publicRequest(method, path)
			r.Header.Set("Upgrade", "websocket")
			r.Header.Set("Connection", "upgrade")
			w := runRequest(h, r)
			if w.Code < 400 {
				t.Errorf("ungated %s %s: %d", method, path, w.Code)
			}
		}
	}
	if calls.Load() != 0 {
		t.Fatal("anonymous upstream request")
	}
	if w := runRequest(h, publicRequest("GET", "/__otgo/unknown")); w.Code != 404 {
		t.Fatal("unknown auth endpoint")
	}
}
func TestGateHostSNIAndOrigin(t *testing.T) {
	var calls atomic.Int32
	h, s, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls.Add(1); w.WriteHeader(204) }))
	secret := browserSession(t, s)
	for _, origin := range []string{"", "https://sibling.demo.test", "https://other.test", "https://demo.test:443", "null"} {
		r := publicRequest("POST", "/mcp")
		r.Header.Set("Origin", origin)
		addSession(r, secret)
		if w := runRequest(h, r); w.Code != 403 {
			t.Fatalf("origin %q: %d", origin, w.Code)
		}
	}
	for _, host := range []string{"other.test", "demo.test:443", "demo.test.", "demo.test@evil.test"} {
		r := publicRequest("GET", "/")
		r.Host = host
		addSession(r, secret)
		if w := runRequest(h, r); w.Code != 421 {
			t.Fatalf("host %q: %d", host, w.Code)
		}
	}
	r := publicRequest("GET", "/")
	r.TLS.ServerName = "other.test"
	addSession(r, secret)
	if w := runRequest(h, r); w.Code != 421 {
		t.Fatal("mismatched TLS SNI")
	}
	if calls.Load() != 0 {
		t.Fatal("invalid origin reached backend")
	}
	r = publicRequest("POST", "/")
	addSession(r, secret)
	r.Header.Set("Origin", "https://demo.test")
	if w := runRequest(h, r); w.Code != 204 {
		t.Fatalf("same origin: %d", w.Code)
	}
}
func TestGateCredentialAmbiguity(t *testing.T) {
	h, s, tokens := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	cookie := browserSession(t, s)
	token, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, authorization, xtoken string
		duplicate                   bool
		want                        int
	}{
		{"cookie only", "", "", false, 204},
		{"backend bearer", "Bearer backend-secret", "", false, 204},
		{"bad token cannot fall back", "Bearer otgo_invalid", "", false, 401},
		{"ambiguous sources", "Bearer " + token, token, false, 401},
		{"duplicate cookie", "", "", true, 401},
		{"backend bearer plus machine token", "Bearer backend-secret", token, false, 204},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := publicRequest("GET", "/")
			addSession(r, cookie)
			if tt.duplicate {
				addSession(r, cookie)
			}
			if tt.authorization != "" {
				r.Header.Set("Authorization", tt.authorization)
			}
			if tt.xtoken != "" {
				r.Header.Set("X-Otgo-Token", tt.xtoken)
			}
			if w := runRequest(h, r); w.Code != tt.want {
				t.Fatalf("%d", w.Code)
			}
		})
	}
	for _, key := range []string{"Authorization", "X-Otgo-Token"} {
		r := publicRequest("GET", "/")
		r.Header.Add(key, "Bearer "+token)
		r.Header.Add(key, "Bearer "+token)
		addSession(r, cookie)
		if w := runRequest(h, r); w.Code != 401 {
			t.Fatal("duplicate header")
		}
	}
}
func TestGatePasswordLoginAndLogout(t *testing.T) {
	h, _, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	r := publicRequest("GET", "/__otgo/login")
	w := runRequest(h, r)
	if w.Code != 401 {
		t.Fatalf("login page: %d", w.Code)
	}
	var csrf *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookie {
			csrf = c
		}
	}
	if csrf == nil || !csrf.Secure || !csrf.HttpOnly || csrf.Domain != "" || csrf.Path != "/" || csrf.SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe CSRF cookie")
	}
	login := func(password, csrfValue, origin string) *httptest.ResponseRecorder {
		form := url.Values{"password": {password}, "csrf": {csrfValue}}
		r := publicRequest("POST", "/__otgo/login")
		r.Body = http.NoBody
		r = withForm(r, form.Encode())
		r.AddCookie(csrf)
		r.Header.Set("Origin", origin)
		return runRequest(h, r)
	}
	if w := login("test-password", "wrong", "https://demo.test"); w.Code != 403 {
		t.Fatal("login CSRF accepted")
	}
	for _, origin := range []string{"https://evil.test", "null", ""} {
		if w := login("test-password", csrf.Value, origin); w.Code != 403 {
			t.Fatalf("login accepted untrusted origin %q", origin)
		}
	}
	if w := login("wrong", csrf.Value, "https://demo.test"); w.Code != 401 {
		t.Fatal("wrong password")
	}
	w = login("test-password", csrf.Value, "https://demo.test")
	if w.Code != 303 || w.Header().Get("Location") != "/" {
		t.Fatalf("login did not redirect to root: %d location=%q %s", w.Code, w.Header().Get("Location"), w.Body.String())
	}
	var session *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			session = c
		}
	}
	if session == nil || !session.Secure || !session.HttpOnly || session.Domain != "" || session.Path != "/" || session.SameSite != http.SameSiteLaxMode {
		t.Fatal("unsafe session cookie")
	}
	r = publicRequest("GET", "/")
	r.AddCookie(session)
	if w := runRequest(h, r); w.Code != 204 {
		t.Fatal("logged-in request failed")
	}
	r = withForm(publicRequest("POST", "/__otgo/logout"), url.Values{"csrf": {csrf.Value}}.Encode())
	r.AddCookie(session)
	r.AddCookie(csrf)
	r.Header.Set("Origin", "https://demo.test")
	if w := runRequest(h, r); w.Code != 303 {
		t.Fatal("logout failed")
	}
	r = publicRequest("GET", "/")
	r.AddCookie(session)
	if w := runRequest(h, r); w.Code != 401 {
		t.Fatal("logout did not revoke")
	}
}
func withForm(r *http.Request, body string) *http.Request {
	r.Body = ioNop(body)
	r.ContentLength = int64(len(body))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}
func ioNop(s string) io.ReadCloser { return io.NopCloser(strings.NewReader(s)) }
func TestGateLoginBounds(t *testing.T) {
	s := NewSessions(1024)
	defer s.Close()
	p := NewPasswordBrowserAuthenticator(fixtureConfig(), s)
	now := time.Now()
	p.now = func() time.Time { return now }
	p.last = now
	h := http.NewServeMux()
	p.Register(h)
	page := runRequest(h, publicRequest("GET", "/__otgo/login"))
	var csrf *http.Cookie
	for _, c := range page.Result().Cookies() {
		if c.Name == CSRFCookie {
			csrf = c
		}
	}
	r := withForm(publicRequest("POST", "/__otgo/login"), "password="+strings.Repeat("x", 5000))
	r.AddCookie(csrf)
	r.Header.Set("Origin", "https://demo.test")
	if w := runRequest(h, r); w.Code != 413 {
		t.Fatalf("oversized login: %d", w.Code)
	}
	for range 12 {
		r = withForm(publicRequest("POST", "/__otgo/login"), "password=x&csrf="+csrf.Value)
		r.AddCookie(csrf)
		r.Header.Set("Origin", "https://demo.test")
		w := runRequest(h, r)
		if w.Code == 429 {
			return
		}
	}
	t.Fatal("login attempts not limited")
}

func TestGateLoginLimiterAndConcurrency(t *testing.T) {
	s := NewSessions(1024)
	defer s.Close()
	p := NewPasswordBrowserAuthenticator(fixtureConfig(), s)
	now := time.Now()
	p.now = func() time.Time { return now }
	p.last = now
	for range 10 {
		if !p.admit() {
			t.Fatal("initial burst")
		}
	}
	if p.admit() {
		t.Fatal("unbounded burst")
	}
	now = now.Add(time.Second)
	if !p.admit() || p.admit() {
		t.Fatal("refill rate")
	}
	p.allowance = 10
	p.slots <- struct{}{}
	p.slots <- struct{}{}
	csrf := randomSecret()
	r := withForm(publicRequest("POST", "/__otgo/login"), "password=x&csrf="+csrf)
	r.AddCookie(authCookie(CSRFCookie, csrf, 600))
	r.Header.Set("Origin", "https://demo.test")
	w := httptest.NewRecorder()
	p.login(w, r)
	if w.Code != 429 {
		t.Fatal("unbounded password jobs")
	}
	<-p.slots
	<-p.slots
	for range 10 {
		if !p.admit() {
			t.Fatal("busy hash slots spent password verification budget")
		}
	}
}

// Same-origin form POSTs must retain their Origin while external navigation
// receives no Referer. no-referrer makes HTML form POSTs send Origin: null.
func TestOwnedFormReferrerPolicy(t *testing.T) {
	h, sessions, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	for _, path := range []string{"/__otgo/login", "/__otgo/logout"} {
		r := publicRequest("GET", path)
		if path == "/__otgo/logout" {
			addSession(r, browserSession(t, sessions))
		}
		w := runRequest(h, r)
		if got := w.Header().Get("Referrer-Policy"); got != "same-origin" {
			t.Errorf("%s cannot preserve same-origin forms and hide external referrers: %q", path, got)
		}
	}
}
