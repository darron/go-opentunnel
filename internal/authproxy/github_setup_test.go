package authproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func setupFixture(t *testing.T) (*githubSetup, *bytes.Buffer, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != "POST" || r.URL.Path != "/app-manifests/registration-code/conversions" {
			t.Error("bad conversion")
		}
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"id":1,"client_id":"new-id","client_secret":"new-secret","html_url":"https://github.com/apps/test-app","pem":"discard-private-key","webhook_secret":"discard-webhook-secret"}`)
	}))
	t.Cleanup(provider.Close)
	paths := Paths{AuthConfig: filepath.Join(secureTempDir(t), "auth.json")}
	cfg := fixtureConfig()
	if err := SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	out := &bytes.Buffer{}
	setup, err := newGitHubSetup(cfg, paths, cfg.Binding, []GitHubAccount{{ID: 123, Login: "allowed"}}, newGitHubProvider(provider.Client(), githubEndpoints{API: provider.URL}), "http://127.0.0.1:12345", out)
	if err != nil {
		t.Fatal(err)
	}
	return setup, out, &calls
}
func setupRequest(method, path string) *http.Request {
	r := httptest.NewRequestWithContext(context.Background(), method, "http://127.0.0.1:12345"+path, nil)
	return r
}
func startRegistration(t *testing.T, s *githubSetup) *http.Cookie {
	t.Helper()
	w := runRequest(s, setupRequest("GET", "/start"))
	if w.Code != 200 {
		t.Fatal("start page")
	}
	if w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("registration start page suppresses the local form Origin")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == setupCookie {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("setup cookie")
	}
	r := withForm(setupRequest("POST", "/create"), url.Values{"csrf": {cookie.Value}}.Encode())
	r.AddCookie(cookie)
	r.Header.Set("Origin", s.origin)
	w = runRequest(s, r)
	if w.Code != 200 {
		t.Fatalf("create form: %d", w.Code)
	}
	if w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("external registration page exposes a referrer")
	}
	pattern := regexp.MustCompile(`name="manifest" value="([^"]*)"`)
	match := pattern.FindStringSubmatch(w.Body.String())
	if len(match) != 2 {
		t.Fatal("missing manifest")
	}
	var manifest githubManifest
	if err := json.Unmarshal([]byte(html.UnescapeString(match[1])), &manifest); err != nil {
		t.Fatal(err)
	}
	if len(manifest.CallbackURLs) != 1 || manifest.CallbackURLs[0] != "https://demo.test/__otgo/github/callback" || manifest.RedirectURL != s.origin+"/callback" || manifest.HookAttributes.Active || len(manifest.DefaultPermissions) != 0 || len(manifest.DefaultEvents) != 0 {
		t.Fatal("unsafe manifest")
	}
	return cookie
}
func setupCallback(s *githubSetup, c *http.Cookie, state string) *httptest.ResponseRecorder {
	r := setupRequest("GET", "/callback?state="+url.QueryEscape(state)+"&code=registration-code")
	if c != nil {
		r.AddCookie(c)
	}
	return runRequest(s, r)
}
func TestGitHubSetupManifestApprovalPersistenceAndReplay(t *testing.T) {
	s, out, calls := setupFixture(t)
	if w := setupCallback(s, nil, s.state); w.Code != 403 || calls.Load() != 0 {
		t.Fatal("no owner/browser approval required")
	}
	cookie := startRegistration(t, s)
	if w := setupCallback(s, cookie, "wrong"); w.Code != 403 || calls.Load() != 0 {
		t.Fatal("bad state exchanged")
	}
	if w := setupCallback(s, cookie, s.state); w.Code != 200 {
		t.Fatalf("setup callback: %d %s", w.Code, w.Body.String())
	}
	cfg, err := LoadConfig(s.paths.AuthConfig)
	if err != nil || cfg.Mode != "github" || cfg.GitHub.ClientSecret != "new-secret" || len(cfg.GitHub.Users) != 1 {
		t.Fatal("credentials not persisted")
	}
	raw, err := os.ReadFile(s.paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"discard-private-key", "discard-webhook-secret"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Fatal("unused secrets persisted")
		}
	}
	if strings.Contains(out.String(), "new-secret") {
		t.Fatal("secret output")
	}
	if w := setupCallback(s, cookie, s.state); w.Code != 403 || calls.Load() != 1 {
		t.Fatal("duplicate conversion")
	}
	if err := <-s.completed; err != nil {
		t.Fatal(err)
	}
}
func TestGitHubSetupHostOriginAndPersistenceFailure(t *testing.T) {
	s, out, calls := setupFixture(t)
	r := setupRequest("GET", "/start")
	r.Host = "evil.test"
	if w := runRequest(s, r); w.Code != 421 {
		t.Fatal("bad host")
	}
	r = withForm(setupRequest("POST", "/create"), "csrf=x")
	r.Header.Set("Origin", "https://evil.test")
	if w := runRequest(s, r); w.Code != 403 {
		t.Fatal("bad origin")
	}
	cookie := startRegistration(t, s)
	if err := os.Remove(s.paths.AuthConfig + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(s.paths.AuthConfig+".lock", 0700); err != nil {
		t.Fatal(err)
	}
	if w := setupCallback(s, cookie, s.state); w.Code != 500 {
		t.Fatal("failed persistence accepted")
	}
	if calls.Load() != 1 || !strings.Contains(out.String(), "https://github.com/settings/apps/test-app") || strings.Contains(out.String(), "new-secret") {
		t.Fatal("missing safe cleanup URL")
	}
	if err := <-s.completed; err == nil {
		t.Fatal("partial setup reported success")
	}
}
func TestGitHubSetupCancellationBeforeRegistration(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := RunGitHubSetup(ctx, Paths{}, Binding{}, []string{"allowed"}, io.Discard); err == nil {
		t.Fatal("cancelled wizard started")
	}
}

func TestGitHubSetupExpiryAndSafeCleanupURL(t *testing.T) {
	s, _, _ := setupFixture(t)
	cookie := startRegistration(t, s)
	s.now = func() time.Time { return time.Now().Add(11 * time.Minute) }
	if w := setupCallback(s, cookie, s.state); w.Code != 410 {
		t.Fatal("expired registration accepted")
	}
	for _, raw := range []string{"https://evil.test/apps/secret", "https://github.com/apps/good?secret=bad", "https://user:secret@github.com/apps/good", "https://github.com/apps/../secret"} {
		if got := safeAppManagementURL(raw); got != "https://github.com/settings/apps" {
			t.Fatal("unsafe cleanup URL")
		}
	}
}

type setupOutput struct{ lines chan string }

func (o setupOutput) Write(b []byte) (int, error) { o.lines <- string(b); return len(b), nil }
func TestGitHubSetupRunningCancellationClosesListener(t *testing.T) {
	s, _, _ := setupFixture(t)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"id":123,"login":"allowed"}`) }))
	defer provider.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	output := setupOutput{lines: make(chan string, 8)}
	done := make(chan error, 1)
	go func() {
		done <- runGitHubSetup(ctx, s.paths, s.binding, []string{"allowed"}, output, newGitHubProvider(provider.Client(), githubEndpoints{API: provider.URL}))
	}()
	var address string
	select {
	case line := <-output.lines:
		address = strings.Fields(line)[1]
	case err := <-done:
		t.Fatalf("setup startup: %v", err)
	case <-time.After(time.Second):
		t.Fatal("setup did not listen")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("setup did not stop")
	}
	req, err := http.NewRequestWithContext(t.Context(), "GET", address, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: time.Second}
	if res, err := client.Do(req); err == nil {
		_ = res.Body.Close()
		t.Fatal("setup listener survived cancellation")
	}
	cfg, err := LoadConfig(s.paths.AuthConfig)
	if err != nil || cfg.Mode != "password" {
		t.Fatal("cancellation changed auth setup")
	}
}
