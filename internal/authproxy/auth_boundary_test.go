package authproxy

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// A new auth mode must retain the universal gate, including non-browser routes
// and encoded paths. Neither a forged identity nor a protocol upgrade grants access.
func TestBothAuthModesDenyAnonymousBackendAccess(t *testing.T) {
	for _, mode := range []string{"password", "github"} {
		t.Run(mode, func(t *testing.T) {
			var calls atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer backend.Close()
			cfg := fixtureConfig()
			cfg.Upstream, cfg.Mode = backend.URL, mode
			if mode == "github" {
				cfg.GitHub = GitHubConfig{ClientID: "test-client", ClientSecret: "test-secret", Users: []GitHubAccount{{ID: 123, Login: "allowed"}}}
			}
			h, err := NewHandler(Options{Config: cfg, IdentityKey: testIdentityKey(t, cfg)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = h.Close() }()
			for _, method := range []string{"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "CONNECT", "PROPFIND"} {
				for _, path := range []string{"/", "/mcp", "/sse", "/ws", "/health", "/static/app.js", "/.well-known/oauth-protected-resource", "/%6dcp", "//mcp", "/__otgo/../mcp", "/%5f%5fotgo/../mcp"} {
					r := publicRequest(method, path)
					r.Header.Set("Upgrade", "websocket")
					r.Header.Set("Connection", "upgrade")
					r.Header.Set("X-Github-User", "allowed")
					r.Header.Set("X-Forwarded-User", "allowed")
					w := runRequest(h, r)
					if w.Code < 300 {
						t.Errorf("anonymous %s %s admitted: %d", method, path, w.Code)
					}
				}
			}
			if calls.Load() != 0 {
				t.Fatalf("anonymous requests reached backend: %d", calls.Load())
			}
		})
	}
}

func TestMachineTokenRegistryBindsEveryAuthConfigurationField(t *testing.T) {
	shared := filepath.Join(secureTempDir(t), "tokens.json")
	var firstCalls atomic.Int32
	firstBackend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		firstCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(firstBackend.Close)
	first := fixtureConfig()
	first.Upstream = firstBackend.URL
	firstStore := NewTokenStore(shared, first)
	secret, _, err := firstStore.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	firstHandler, err := NewHandler(Options{Config: first, TokenStore: firstStore})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = firstHandler.Close() })

	var otherUpstreamCalls atomic.Int32
	otherUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		otherUpstreamCalls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(otherUpstream.Close)
	tests := []struct {
		name   string
		change func(*Config)
	}{
		{"tunnel ID", func(cfg *Config) { cfg.Binding.TunnelID = "other-id" }},
		{"hostname", func(cfg *Config) { cfg.Binding.Hostname = "other.test" }},
		{"API origin", func(cfg *Config) { cfg.Binding.APIOrigin = "https://other-api.test" }},
		{"upstream", func(cfg *Config) { cfg.Upstream = otherUpstream.URL }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := firstStore.Authenticate(secret); err != nil {
				t.Fatalf("control token did not authenticate against its bound registry: %v", err)
			}
			controlBefore := firstCalls.Load()
			controlRequest := publicRequest(http.MethodGet, "/private")
			controlRequest.Header.Set("Authorization", "Bearer "+secret)
			if got := runRequest(firstHandler, controlRequest).Code; got != http.StatusNoContent || firstCalls.Load() != controlBefore+1 {
				t.Fatalf("control token did not reach its bound backend: status=%d calls=%d", got, firstCalls.Load()-controlBefore)
			}

			candidate := first
			test.change(&candidate)
			candidateStore := NewTokenStore(shared, candidate)
			if _, err := candidateStore.Authenticate(secret); err == nil {
				t.Fatal("token authenticated against a registry bound to another configuration")
			}
			h, err := NewHandler(Options{Config: candidate, TokenStore: candidateStore})
			if err != nil {
				t.Fatalf("changed configuration is not valid: %v", err)
			}
			t.Cleanup(func() { _ = h.Close() })
			beforeFirst := firstCalls.Load()
			beforeOther := otherUpstreamCalls.Load()
			r := publicRequest(http.MethodGet, "/private")
			r.Host = candidate.Binding.Hostname
			r.TLS.ServerName = candidate.Binding.Hostname
			r.Header.Set("Authorization", "Bearer "+secret)
			if got := runRequest(h, r).Code; got != http.StatusUnauthorized {
				t.Fatalf("token returned %d for changed configuration, want 401", got)
			}
			if firstCalls.Load() != beforeFirst || otherUpstreamCalls.Load() != beforeOther {
				t.Fatal("token for another configuration reached a backend")
			}
		})
	}
}

func TestHandlerRejectsTokenStoreForDifferentAuthConfiguration(t *testing.T) {
	first := fixtureConfig()
	second := fixtureConfig()
	second.Upstream = "http://127.0.0.1:8001"
	store := NewTokenStore(filepath.Join(secureTempDir(t), "tokens.json"), first)
	if _, err := NewHandler(Options{Config: second, TokenStore: store}); err == nil || !strings.Contains(err.Error(), "token store does not match") {
		t.Fatalf("handler accepted mismatched token store: %v", err)
	}
}

// Originally public backends may opt into browser/CDN caching. The auth proxy
// must override those policies so protected responses cannot outlive the gate.
func TestBothAuthModesPreventProtectedResponseCaching(t *testing.T) {
	for _, mode := range []string{"password", "github"} {
		t.Run(mode, func(t *testing.T) {
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Cache-Control", "public, max-age=3600")
				w.Header().Set("Expires", "Wed, 21 Oct 2037 07:28:00 GMT")
				w.Header().Set("X-Accel-Expires", "3600")
				w.Header().Set("Pragma", "cache")
				for _, key := range []string{"Surrogate-Control", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Vercel-CDN-Cache-Control", "X-Accel-Expires"} {
					w.Header().Set(key, "public, max-age=3600")
				}
				_, _ = w.Write([]byte("protected-cache-canary"))
			}))
			defer backend.Close()
			cfg := fixtureConfig()
			cfg.Upstream, cfg.Mode = backend.URL, mode
			if mode == "github" {
				cfg.GitHub = GitHubConfig{ClientID: "test-client", ClientSecret: "test-secret", Users: []GitHubAccount{{ID: 123, Login: "allowed"}}}
			}
			h, err := NewHandler(Options{Config: cfg, IdentityKey: testIdentityKey(t, cfg)})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = h.Close() }()
			secret, err := h.sessions.Create(Principal{ID: "123", Mechanism: mode, GitHubLogin: "allowed"}, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			r := publicRequest("GET", "/private")
			addSession(r, secret)
			w := runRequest(h, r)
			if w.Code != http.StatusOK || w.Body.String() != "protected-cache-canary" {
				t.Fatal("authenticated response did not reach backend")
			}
			if w.Header().Get("Cache-Control") != "private, no-store" || w.Header().Get("Pragma") != "no-cache" || w.Header().Get("Expires") != "0" {
				t.Fatalf("protected response cache policy: %v", w.Header())
			}
			for _, key := range []string{"Surrogate-Control", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Vercel-CDN-Cache-Control", "X-Accel-Expires"} {
				if w.Header().Get(key) != "" {
					t.Errorf("backend caching override retained: %s", key)
				}
			}
			h.sessions.Revoke(secret)
			if denied := runRequest(h, r); denied.Code != http.StatusUnauthorized || strings.Contains(denied.Body.String(), "protected-cache-canary") {
				t.Fatal("revoked session received protected content")
			}
		})
	}
}

// Failed OAuth callbacks must never mint an authenticated session or forward
// their code/state to the backend, even when the URL is syntactically plausible.
func TestGitHubCallbackFailuresRemainBehindGate(t *testing.T) {
	for _, failure := range []string{"missing browser", "duplicate browser", "duplicate state", "duplicate code", "denied identity", "provider denial", "exchange failure", "identity failure"} {
		t.Run(failure, func(t *testing.T) {
			g, sessions, _, browser, query := githubFixture(t)
			var calls atomic.Int32
			backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				w.WriteHeader(http.StatusNoContent)
			}))
			defer backend.Close()
			cfg := fixtureConfig()
			cfg.Upstream, cfg.Mode, cfg.GitHub = backend.URL, "github", g.config
			h, err := NewHandler(Options{Config: cfg, IdentityKey: testIdentityKey(t, cfg), Sessions: sessions, BrowserAuthenticator: g})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = h.Close() }()
			q := url.Values{"state": {query.Get("state")}, "code": {"authorization-code-canary"}}
			want := http.StatusForbidden
			switch failure {
			case "duplicate state":
				q.Add("state", query.Get("state"))
			case "duplicate code":
				q.Add("code", "other-code-canary")
			case "denied identity":
				g.allowed = map[int64]bool{456: true}
			case "provider denial":
				q.Set("error", "provider-error-canary")
			case "exchange failure":
				g.provider.endpoints.Token += "/missing"
				want = http.StatusBadGateway
			case "identity failure":
				g.provider.endpoints.API += "/missing"
				want = http.StatusBadGateway
			}
			r := publicRequest("GET", "/__otgo/github/callback?"+q.Encode())
			if failure != "missing browser" {
				r.AddCookie(browser)
			}
			if failure == "duplicate browser" {
				r.AddCookie(browser)
			}
			w := runRequest(h, r)
			if w.Code != want {
				t.Fatalf("callback status: got %d want %d", w.Code, want)
			}
			follow := publicRequest("GET", "/mcp")
			for _, c := range w.Result().Cookies() {
				if c.Name == SessionCookie && c.Value != "" {
					t.Fatal("failed callback created session")
				}
				follow.AddCookie(c)
			}
			if result := runRequest(h, follow); result.Code != http.StatusUnauthorized {
				t.Fatalf("callback failure authenticated backend request: %d", result.Code)
			}
			for _, secret := range []string{"client-secret", "provider-secret", "authorization-code-canary", "other-code-canary", "provider-error-canary", browser.Value} {
				if strings.Contains(w.Body.String(), secret) || strings.Contains(w.Header().Get("Location"), secret) {
					t.Fatal("callback disclosed secret")
				}
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatal("callback error permits credential caching/referrer leakage")
			}
			if calls.Load() != 0 {
				t.Fatal("callback failure forwarded to backend")
			}
		})
	}
}

// Rejected forms must not exhaust the expensive password-verification budget.
func TestRejectedPasswordFormsDoNotBlockValidLogin(t *testing.T) {
	for _, rejection := range []struct {
		name, body string
		status     int
	}{
		{"bad csrf", "password=wrong&csrf=wrong", http.StatusForbidden},
		{"bad encoding", "password=%zz", http.StatusBadRequest},
		{"oversized body", "password=" + strings.Repeat("x", 5000), http.StatusRequestEntityTooLarge},
	} {
		t.Run(rejection.name, func(t *testing.T) {
			cfg := fixtureConfig()
			var err error
			cfg.Password, err = NewPasswordVerifier([]byte("correct-test-password"))
			if err != nil {
				t.Fatal(err)
			}
			sessions := NewSessions(1024)
			defer sessions.Close()
			p := NewPasswordBrowserAuthenticator(cfg, sessions)
			now := time.Now()
			p.now = func() time.Time { return now }
			p.last = now
			csrf := randomSecret()
			for range 20 {
				r := withForm(publicRequest("POST", "/__otgo/login"), rejection.body)
				r.Header.Set("Origin", "https://demo.test")
				r.AddCookie(authCookie(CSRFCookie, csrf, 600))
				if w := runRequest(http.HandlerFunc(p.login), r); w.Code != rejection.status {
					t.Fatalf("rejected form spent password budget: got %d want %d", w.Code, rejection.status)
				}
			}
			r := withForm(publicRequest("POST", "/__otgo/login"), url.Values{"csrf": {csrf}, "password": {"correct-test-password"}}.Encode())
			r.Header.Set("Origin", "https://demo.test")
			r.AddCookie(authCookie(CSRFCookie, csrf, 600))
			if w := runRequest(http.HandlerFunc(p.login), r); w.Code != http.StatusSeeOther {
				t.Fatalf("valid login blocked after rejected forms: %d", w.Code)
			}
		})
	}
}
