package authproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"github.com/coder/websocket"
	"github.com/darron/go-opentunnel/identity"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestGitHubIdentityComesFromOAuthNotVisitor(t *testing.T) {
	g, s, mux, cookie, q := githubFixture(t)
	callback := githubCallback(mux, cookie, q.Get("state"))
	if callback.Code != 303 {
		t.Fatalf("callback: %d", callback.Code)
	}
	var session *http.Cookie
	for _, c := range callback.Result().Cookies() {
		if c.Name == SessionCookie {
			session = c
		}
	}
	if session == nil {
		t.Fatal("missing session")
	}
	public, private, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		verified, err := identity.VerifyRequest(r, public, identity.VerifyOptions{Issuer: "https://demo.test", Audience: "http://" + r.Host})
		if err != nil || verified.ID != "123" || verified.Login != "renamed-user" {
			t.Errorf("signed identity: %+v %v", verified, err)
		}
		if got := r.Header.Values("X-GitHub-User"); len(got) != 1 || got[0] != "renamed-user" {
			t.Errorf("user: %q", got)
		}
		if got := r.Header.Values("X-GitHub-ID"); len(got) != 1 || got[0] != "123" {
			t.Errorf("id: %q", got)
		}
		if r.Header.Get("X-GitHub-Other") != "" || r.Header.Get("X-Otgo-Other") != "" {
			t.Error("forged identity header leaked")
		}
		for k := range r.Trailer {
			if strings.HasPrefix(strings.ToLower(k), "x-github-") || strings.HasPrefix(strings.ToLower(k), "x-otgo-") {
				t.Errorf("identity trailer leaked: %s", k)
			}
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	cfg := fixtureConfig()
	cfg.Mode = "github"
	cfg.GitHub = g.config
	cfg.Upstream = backend.URL
	h, err := NewHandler(Options{Config: cfg, Sessions: s, BrowserAuthenticator: g, IdentityKey: private})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	for _, connection := range []string{"", "X-GitHub-User, X-GitHub-ID, X-Otgo-Identity", "long-query"} {
		target := "/mcp?one=two"
		if connection == "long-query" {
			target = "/mcp?" + strings.Repeat("a=1&", 2048)
			connection = ""
		}
		r := publicRequest("POST", target)
		r.AddCookie(session)
		r.Header.Set("Origin", "https://demo.test")
		r.Header["x-github-user"] = []string{"attacker", "another"}
		r.Header.Set("X-GitHub-ID", "999")
		r.Header.Set("X-GitHub-Other", "forged")
		r.Header.Set("X-Otgo-Other", "forged")
		r.Header.Set("Connection", connection)
		r.Body = io.NopCloser(strings.NewReader("streaming body"))
		r.ContentLength = -1
		r.Trailer = http.Header{"X-Github-User": {"attacker"}, "X-Otgo-Identity": {"forged"}}
		if w := runRequest(h, r); w.Code != 204 {
			t.Fatalf("proxy: %d %s", w.Code, w.Body.String())
		}
	}
}

func TestNonGitHubCredentialsNeverAssertGitHubIdentity(t *testing.T) {
	for _, mode := range []string{"password", "github"} {
		t.Run(mode, func(t *testing.T) {
			h, s, tokens := testHandlerForMode(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k := range r.Header {
					if strings.HasPrefix(strings.ToLower(k), "x-github-") || strings.HasPrefix(strings.ToLower(k), "x-otgo-") {
						t.Errorf("identity leaked: %s", k)
					}
				}
				w.WriteHeader(204)
			}), mode)
			secret, _, err := tokens.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			for _, machine := range []bool{false, true} {
				if mode == "github" && !machine {
					continue
				}
				r := publicRequest("GET", "/mcp")
				session := browserSession(t, s)
				if mode == "github" {
					session, err = s.Create(Principal{ID: "123", Mechanism: "github", GitHubLogin: "renamed-user"}, time.Hour)
					if err != nil {
						t.Fatal(err)
					}
				}
				addSession(r, session)
				if machine {
					r.Header.Set("X-Otgo-Token", secret)
				}
				r.Header["x-github-user"] = []string{"attacker"}
				r.Header["x-otgo-identity"] = []string{"forged"}
				if w := runRequest(h, r); w.Code != 204 {
					t.Fatalf("proxy: %d", w.Code)
				}
			}
		})
	}
}

func TestGitHubIdentityStreamingTrailersAndWebSocket(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s := NewSessions(1024)
	verified := make(chan identity.GitHubIdentity, 4)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		principal, e := identity.VerifyRequest(r, public, identity.VerifyOptions{Issuer: "https://demo.test", Audience: "http://" + r.Host})
		if e != nil {
			t.Errorf("backend signature: %v", e)
			http.Error(w, "invalid identity", http.StatusUnauthorized)
			return
		}
		if r.Header.Get("Upgrade") == "websocket" {
			conn, e := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if e != nil {
				t.Error(e)
				return
			}
			defer func() { _ = conn.CloseNow() }()
			verified <- principal
			kind, b, e := conn.Read(r.Context())
			if e != nil {
				return
			}
			_ = conn.Write(r.Context(), kind, b)
			return
		}
		b, e := io.ReadAll(r.Body)
		if e != nil || string(b) != "live upload" {
			t.Errorf("body: %q %v", b, e)
		}
		for k := range r.Trailer {
			if untrustedIdentityHeader(k) {
				t.Errorf("late identity trailer: %s", k)
			}
		}
		verified <- principal
		w.WriteHeader(204)
	}))
	defer backend.Close()
	cfg := fixtureConfig()
	cfg.Mode = "github"
	cfg.GitHub.Users = []GitHubAccount{{ID: 123, Login: "allowed"}}
	cfg.Upstream = backend.URL
	h, err := NewHandler(Options{Config: cfg, Sessions: s, IdentityKey: private})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	session, err := s.Create(Principal{ID: "123", GitHubLogin: "actual-user", Mechanism: "github"}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	surface := proxySurface(t, h)
	reader, writer := io.Pipe()
	r, err := http.NewRequestWithContext(t.Context(), "POST", surface.URL+"/mcp%2Fstream?x=1", reader)
	if err != nil {
		t.Fatal(err)
	}
	r.AddCookie(authCookie(SessionCookie, session, 0))
	r.Header.Set("Origin", "https://demo.test")
	r.Trailer = http.Header{"X-Github-User": nil, "X-Otgo-Identity": nil}
	go func() {
		_, _ = io.WriteString(writer, "live upload")
		r.Trailer.Set("X-GitHub-User", "late-attacker")
		r.Trailer.Set("X-Otgo-Identity", "late-forgery")
		_ = writer.Close()
	}()
	res, err := surface.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != 204 {
		t.Fatalf("upload: %d", res.StatusCode)
	}
	got := <-verified
	if got.ID != "123" || got.Login != "actual-user" {
		t.Fatalf("upload user: %+v", got)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(surface.URL, "http")+"/ws?channel=one", &websocket.DialOptions{HTTPHeader: http.Header{"Cookie": {SessionCookie + "=" + session}, "Origin": {"https://demo.test"}, "X-Github-User": {"attacker"}, "X-Otgo-Identity": {"forged"}}})
	if response != nil && response.Body != nil {
		_ = response.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.CloseNow() }()
	if err := conn.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
		t.Fatal(err)
	}
	_, b, err := conn.Read(ctx)
	if err != nil || string(b) != "hello" {
		t.Fatalf("WebSocket: %q %v", b, err)
	}
	got = <-verified
	if got.ID != "123" || got.Login != "actual-user" {
		t.Fatalf("WebSocket user: %+v", got)
	}
}

func TestSignedIdentitiesStayIsolatedAcrossConcurrentSessions(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, err := identity.VerifyRequest(r, public, identity.VerifyOptions{Issuer: "https://demo.test", Audience: "http://" + r.Host})
		if err != nil || r.URL.Query().Get("expect") != got.ID || got.Login != "user"+got.ID {
			t.Errorf("cross-session identity: %+v %v", got, err)
		}
		w.WriteHeader(204)
	}))
	defer backend.Close()
	cfg := fixtureConfig()
	cfg.Mode = "github"
	cfg.GitHub.Users = []GitHubAccount{{ID: 1, Login: "user1"}, {ID: 2, Login: "user2"}}
	cfg.Upstream = backend.URL
	s := NewSessions(1024)
	h, err := NewHandler(Options{Config: cfg, Sessions: s, IdentityKey: private})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = h.Close() }()
	var wg sync.WaitGroup
	for _, id := range []string{"1", "2"} {
		secret, err := s.Create(Principal{ID: id, GitHubLogin: "user" + id, Mechanism: "github"}, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		for range 15 {
			wg.Go(func() {
				r := publicRequest("GET", "/?expect="+id)
				addSession(r, secret)
				if w := runRequest(h, r); w.Code != 204 {
					t.Errorf("proxy: %d", w.Code)
				}
			})
		}
	}
	wg.Wait()
}
