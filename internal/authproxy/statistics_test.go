package authproxy

import (
	"errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStatisticsAdmissionAndPrivateCollector(t *testing.T) {
	calls := 0
	h, s, tokens := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(204) }))
	secret, _, e := tokens.Create(time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	for _, tc := range []struct {
		outcome, method, path, origin, upgrade string
		token                                  bool
		code                                   int
	}{
		{"public_denied", "GET", "/secret", "", "", false, 421},
		{"auth_denied", "GET", "/secret", "", "", false, 401},
		{"owned", "GET", "/__otgo/metrics", "", "", false, 404},
		{"origin_denied", "POST", "/secret", "https://foreign.test", "", true, 403},
		{"protocol_denied", "GET", "/secret", "", "h2c", true, 400},
		{"admitted", "GET", "/secret", "", "", true, 204},
	} {
		r := publicRequest(tc.method, tc.path)
		if tc.outcome == "public_denied" {
			r.Host = "foreign.test"
		}
		if tc.token {
			r.Header.Set("X-Otgo-Token", secret)
		}
		if tc.origin != "" {
			r.Header.Set("Origin", tc.origin)
		}
		if tc.upgrade != "" {
			r.Header.Set("Upgrade", tc.upgrade)
		}
		if w := runRequest(h, r); w.Code != tc.code {
			t.Fatalf("%s: %d", tc.outcome, w.Code)
		}
	}
	if calls != 1 {
		t.Fatalf("denied/owned reached backend: %d", calls)
	}
	r := publicRequest("GET", "/")
	addSession(r, browserSession(t, s))
	runRequest(h, r)
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(h.Collector())
	if e := testutil.GatherAndCompare(registry, strings.NewReader(`# HELP opentunnel_proxy_backend_responses_total Backend response headers received, including protocol upgrades.
# TYPE opentunnel_proxy_backend_responses_total counter
opentunnel_proxy_backend_responses_total{class="1xx"} 0
opentunnel_proxy_backend_responses_total{class="2xx"} 2
opentunnel_proxy_backend_responses_total{class="3xx"} 0
opentunnel_proxy_backend_responses_total{class="4xx"} 0
opentunnel_proxy_backend_responses_total{class="5xx"} 0
opentunnel_proxy_backend_responses_total{class="other"} 0
`), "opentunnel_proxy_backend_responses_total"); e != nil {
		t.Fatal(e)
	}
	for outcome, want := range map[string]uint64{"public_denied": 1, "auth_denied": 1, "owned": 1, "origin_denied": 1, "protocol_denied": 1, "admitted": 2} {
		if got := h.Stats().Requests[outcome]; got != want {
			t.Fatalf("%s=%d want%d", outcome, got, want)
		}
	}
	families, e := registry.Gather()
	if e != nil {
		t.Fatal(e)
	}
	for _, family := range families {
		for _, metric := range family.Metric {
			for _, label := range metric.Label {
				if strings.Contains(label.GetValue(), "secret") || strings.Contains(label.GetValue(), "test") {
					t.Fatal("metadata label")
				}
			}
		}
	}
}
func TestStatisticsRealPasswordAndGitHubLogin(t *testing.T) {
	h, _, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { t.Error("login reached backend") }))
	for _, password := range []string{"wrong-password", "test-password"} {
		page := runRequest(h, publicRequest("GET", "/__otgo/login"))
		var csrf *http.Cookie
		for _, c := range page.Result().Cookies() {
			if c.Name == CSRFCookie {
				csrf = c
			}
		}
		form := url.Values{"csrf": {csrf.Value}, "password": {password}}
		r := publicRequest("POST", "/__otgo/login")
		r.Body = http.NoBody
		r.Body = io.NopCloser(strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://demo.test")
		r.AddCookie(csrf)
		w := runRequest(h, r)
		if password == "wrong-password" && w.Code != 401 {
			t.Fatal(w.Code)
		}
		if password != "wrong-password" && w.Code != 303 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	if h.Stats().Logins["password"]["success"] != 1 || h.Stats().Logins["password"]["failure"] != 1 {
		t.Fatal(h.Stats())
	}
	g, s, _, cookie, q := githubFixture(t)
	cfg := fixtureConfig()
	cfg.Mode = "github"
	cfg.GitHub = GitHubConfig{ClientID: "client-id", ClientSecret: "client-secret", Users: []GitHubAccount{{ID: 123, Login: "allowed"}}}
	gh, e := NewHandler(Options{Config: cfg, Sessions: s, BrowserAuthenticator: g})
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = gh.Close() }()
	if w := githubCallback(gh, cookie, q.Get("state")); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := githubCallback(gh, cookie, q.Get("state")); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if gh.Stats().Logins["github"]["success"] != 1 || gh.Stats().Logins["github"]["failure"] != 1 {
		t.Fatal(gh.Stats())
	}
}

func TestStatisticsWrongScopeAndBackendFailures(t *testing.T) {
	calls := 0
	h, _, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(503) }))
	cfg := h.config
	cfg.Upstream = "http://127.0.0.1:1"
	wrongStore := NewTokenStore(filepath.Join(secureTempDir(t), "wrong.json"), cfg)
	wrong, _, e := wrongStore.Create(time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	r := publicRequest("GET", "/private-canary")
	r.Header.Set("X-Otgo-Token", wrong)
	if w := runRequest(h, r); w.Code != 401 {
		t.Fatal("wrong scope admitted", w.Code)
	}
	if calls != 0 || h.Stats().Requests["auth_denied"] != 1 {
		t.Fatal("wrong scope reached backend", h.Stats())
	}
	secret, _, e := h.tokens.Create(time.Hour)
	if e != nil {
		t.Fatal(e)
	}
	r = publicRequest("GET", "/private-canary")
	r.Header.Set("X-Otgo-Token", secret)
	if w := runRequest(h, r); w.Code != 503 {
		t.Fatal(w.Code)
	}
	if calls != 1 || h.Stats().BackendResponses["5xx"] != 1 || h.Stats().BackendErrors != 0 {
		t.Fatal(h.Stats())
	}
	h.proxy.Transport = failingTransport{}
	r = publicRequest("GET", "/private-canary")
	r.Header.Set("X-Otgo-Token", secret)
	if w := runRequest(h, r); w.Code != 502 {
		t.Fatal(w.Code)
	}
	stats := h.Stats()
	if stats.BackendErrors != 1 || stats.BackendResponses["5xx"] != 1 {
		t.Fatal("local error confused with backend headers", stats)
	}
	stats.Requests["admitted"] = 999
	stats.Logins["password"]["success"] = 999
	if h.Stats().Requests["admitted"] != 2 || h.Stats().Logins["password"]["success"] != 0 {
		t.Fatal("mutable snapshot shared")
	}
	_ = h.Close()
	r = publicRequest("GET", "/")
	runRequest(h, r)
	if h.Stats().Requests["unavailable"] != 1 {
		t.Fatal("closed request omitted")
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("backend-secret-canary")
}
