package authproxy

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// Exercise the complete gate with attacker-controlled paths and credential
// headers. No browser session or machine credential has been issued.
func FuzzAnonymousBoundary(f *testing.F) {
	var calls atomic.Int64
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	f.Cleanup(backend.Close)
	handlers := make([]*Handler, 0, 2)
	for _, mode := range []string{"password", "github"} {
		cfg := fixtureConfig()
		cfg.Upstream, cfg.Mode = backend.URL, mode
		cfg.GitHub.Users = []GitHubAccount{{ID: 123, Login: "allowed"}}
		h, err := NewHandler(Options{Config: cfg, IdentityKey: testIdentityKey(f, cfg)})
		if err != nil {
			f.Fatal(err)
		}
		handlers = append(handlers, h)
		f.Cleanup(func() { _ = h.Close() })
	}
	for _, path := range []string{"/", "/mcp", "/%6dcp", "//mcp", "/__otgo/../mcp", "/%5f%5fotgo/login", "/__otgo/login", "/__otgo/logout", "/__otgo/github/callback", "/.well-known/oauth-protected-resource"} {
		f.Add("GET", path, "", "", "", "")
		f.Add("POST", path, "Bearer otgo_invalid", "__Host-otgo-session=invalid", "https://demo.test", "websocket")
	}
	f.Fuzz(func(t *testing.T, method, target, authorization, cookie, origin, upgrade string) {
		if len(method)+len(target)+len(authorization)+len(cookie)+len(origin)+len(upgrade) > 4096 {
			return
		}
		for _, h := range handlers {
			r, err := http.NewRequestWithContext(t.Context(), method, target, strings.NewReader("password=invalid&csrf=invalid"))
			if err != nil {
				return
			}
			r.Host = h.config.Binding.Hostname
			r.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: h.config.Binding.Hostname}
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Authorization", authorization)
			r.Header.Set("Cookie", cookie)
			r.Header.Set("Origin", origin)
			r.Header.Set("Upgrade", upgrade)
			r.Header.Set("Connection", "upgrade")
			h.ServeHTTP(httptest.NewRecorder(), r)
			if calls.Load() != 0 {
				t.Fatalf("anonymous request reached the backend in %s mode", h.config.Mode)
			}
		}
	})
}
