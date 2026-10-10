package authproxy

import (
	"crypto/sha256"
	"encoding/base64"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func githubFixture(t *testing.T) (*GitHubBrowserAuthenticator, *Sessions, *http.ServeMux, *http.Cookie, url.Values) {
	t.Helper()
	s := NewSessions(1024)
	t.Cleanup(s.Close)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("client_secret") != "client-secret" || r.Form.Get("code_verifier") == "" || r.Form.Get("redirect_uri") != "https://demo.test/__otgo/github/callback" {
				t.Error("bad token exchange")
			}
			_, _ = io.WriteString(w, `{"access_token":"provider-secret","token_type":"bearer"}`)
		case "/user":
			if r.Header.Get("Authorization") != "Bearer provider-secret" {
				t.Error("missing provider auth")
			}
			_, _ = io.WriteString(w, `{"id":123,"login":"renamed-user"}`)
		case "/users/allowed", "/users/ALLOWED":
			_, _ = io.WriteString(w, `{"id":123,"login":"allowed"}`)
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	cfg := fixtureConfig()
	cfg.Mode = "github"
	cfg.GitHub = GitHubConfig{ClientID: "client-id", ClientSecret: "client-secret", Users: []GitHubAccount{{ID: 123, Login: "allowed"}}}
	g, err := newGitHubBrowser(cfg, s, server.Client(), githubEndpoints{Authorize: server.URL + "/authorize", Token: server.URL + "/token", API: server.URL})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	g.Register(mux)
	w := runRequest(mux, publicRequest("GET", "/__otgo/github"))
	if w.Code != 302 {
		t.Fatalf("begin: %d", w.Code)
	}
	location, err := url.Parse(w.Header().Get("Location"))
	if err != nil {
		t.Fatal(err)
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == GitHubStateCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.Secure || !cookie.HttpOnly || cookie.Domain != "" {
		t.Fatal("missing browser binding")
	}
	return g, s, mux, cookie, location.Query()
}
func githubCallback(mux http.Handler, c *http.Cookie, state string) *httptest.ResponseRecorder {
	r := publicRequest("GET", "/__otgo/github/callback?state="+url.QueryEscape(state)+"&code=authorization-code")
	if c != nil {
		r.AddCookie(c)
	}
	return runRequest(mux, r)
}
func TestGitHubPKCEAndNumericAllowlist(t *testing.T) {
	g, s, mux, cookie, q := githubFixture(t)
	if q.Get("code_challenge_method") != "S256" || q.Get("client_id") != "client-id" {
		t.Fatal("missing PKCE")
	}
	g.mu.Lock()
	pending := g.pending[q.Get("state")]
	g.mu.Unlock()
	sum := sha256.Sum256([]byte(pending.verifier))
	if q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("PKCE not bound to state")
	}
	w := githubCallback(mux, cookie, q.Get("state"))
	if w.Code != 303 {
		t.Fatalf("callback: %d %s", w.Code, w.Body.String())
	}
	var session string
	for _, c := range w.Result().Cookies() {
		if c.Name == SessionCookie {
			session = c.Value
		}
	}
	p, err := s.Authenticate(session)
	if err != nil || p.ID != "123" || p.Mechanism != "github" {
		t.Fatal("numeric allowlist lost on username rename")
	}
	if w := githubCallback(mux, cookie, q.Get("state")); w.Code != 403 {
		t.Fatal("state replay")
	}
	if strings.Contains(w.Body.String(), "provider-secret") {
		t.Fatal("provider token leaked")
	}
}
func TestGitHubStateBindingExpiryAndDenial(t *testing.T) {
	for _, mode := range []string{"missing cookie", "wrong cookie", "expired", "denied user", "provider denial"} {
		t.Run(mode, func(t *testing.T) {
			g, _, mux, cookie, q := githubFixture(t)
			switch mode {
			case "missing cookie":
				cookie = nil
			case "wrong cookie":
				cookie = authCookie(GitHubStateCookie, randomSecret(), 600)
			case "expired":
				g.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
			case "denied user":
				g.allowed = map[int64]bool{456: true}
			case "provider denial":
				r := publicRequest("GET", "/__otgo/github/callback?state="+q.Get("state")+"&error=secret-must-not-print")
				r.AddCookie(cookie)
				w := runRequest(mux, r)
				if w.Code != 403 || strings.Contains(w.Body.String(), "secret-must-not-print") {
					t.Fatal("provider denial leaked")
				}
				return
			}
			if w := githubCallback(mux, cookie, q.Get("state")); w.Code != 403 {
				t.Fatalf("accepted invalid state/account: %d", w.Code)
			}
		})
	}
}
func TestGitHubProviderBoundsAndRedirects(t *testing.T) {
	for _, mode := range []string{"large", "redirect", "error", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "large":
					_, _ = io.WriteString(w, strings.Repeat("x", maxFileBytes+1))
				case "redirect":
					http.Redirect(w, r, "/other", http.StatusFound)
				case "error":
					http.Error(w, "provider-secret", 500)
				case "timeout":
					_, _ = io.Copy(io.Discard, r.Body)
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			client := server.Client()
			client.Timeout = 30 * time.Millisecond
			p := newGitHubProvider(client, githubEndpoints{Token: server.URL, API: server.URL})
			if _, err := p.exchange(t.Context(), "id", "secret", "code", "verifier", "https://demo.test/callback"); err == nil || strings.Contains(err.Error(), "provider-secret") {
				t.Fatal("provider bounds or redaction")
			}
		})
	}
	cfg := fixtureConfig()
	cfg.Mode = "github"
	cfg.GitHub.Users = nil
	if _, err := NewGitHubBrowserAuthenticator(cfg, NewSessions(1024)); err == nil {
		t.Fatal("empty allowlist")
	}
}
func TestGitHubStateCapacityAndUserResolution(t *testing.T) {
	g, _, mux, _, _ := githubFixture(t)
	for range 255 {
		if w := runRequest(mux, publicRequest("GET", "/__otgo/github")); w.Code != 302 {
			t.Fatal("capacity too low")
		}
	}
	if w := runRequest(mux, publicRequest("GET", "/__otgo/github")); w.Code != 503 {
		t.Fatal("unbounded pending state")
	}
	users, err := g.provider.resolveUsers(t.Context(), []string{"allowed", "ALLOWED"})
	if err != nil || len(users) != 1 || users[0].ID != 123 {
		t.Fatal("user resolution")
	}
	for _, name := range []string{"../user", "a/b", "", strings.Repeat("x", 40)} {
		if _, err := g.provider.resolveUsers(t.Context(), []string{name}); err == nil {
			t.Fatal("invalid username")
		}
	}
}

func TestGitHubProviderTimeoutCoversResponseBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_ = http.NewResponseController(w).Flush()
		<-r.Context().Done()
	}))
	defer server.Close()
	client := server.Client()
	client.Timeout = 30 * time.Millisecond
	p := newGitHubProvider(client, githubEndpoints{Token: server.URL})
	if _, err := p.exchange(t.Context(), "id", "secret", "code", "verifier", "https://demo.test/callback"); err == nil {
		t.Fatal("response body unbounded in time")
	}
}
