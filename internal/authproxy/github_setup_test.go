package authproxy

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
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
	w := runRequest(s, setupRequest("GET", setupPath+"?token="+s.startToken))
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != setupPath {
		t.Fatal("capability did not redirect to clean setup URL")
	}
	var cookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == s.cookieName {
			cookie = c
		}
	}
	if cookie == nil || !cookie.HttpOnly || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal("setup cookie")
	}
	r := setupRequest("GET", setupPath)
	r.AddCookie(cookie)
	w = runRequest(s, r)
	if w.Code != http.StatusOK || w.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("bound browser cannot render the registration form")
	}
	r = withForm(setupRequest("POST", setupPath+"/create"), url.Values{"csrf": {cookie.Value}}.Encode())
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
	if len(manifest.CallbackURLs) != 1 || manifest.CallbackURLs[0] != "https://demo.test/__otgo/github/callback" || manifest.RedirectURL != s.origin+setupPath+"/callback" || manifest.HookAttributes.Active || len(manifest.DefaultPermissions) != 0 || len(manifest.DefaultEvents) != 0 {
		t.Fatal("unsafe manifest")
	}
	return cookie
}
func setupCallback(s *githubSetup, c *http.Cookie, state string) *httptest.ResponseRecorder {
	r := setupRequest("GET", setupPath+"/callback?state="+url.QueryEscape(state)+"&code=registration-code")
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

func TestGitHubSetupCannotRebindBrowser(t *testing.T) {
	s, _, calls := setupFixture(t)
	cookie := startRegistration(t, s)
	if w := runRequest(s, setupRequest("GET", setupPath)); w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 {
		t.Fatal("another visitor can replace the approved browser")
	}
	if w := setupCallback(s, cookie, s.state); w.Code != http.StatusOK || calls.Load() != 1 {
		t.Fatal("original browser lost its registration")
	}
}
func TestGitHubSetupHostOriginAndPersistenceFailure(t *testing.T) {
	s, out, calls := setupFixture(t)
	r := setupRequest("GET", setupPath)
	r.Host = "evil.test"
	if w := runRequest(s, r); w.Code != 421 {
		t.Fatal("bad host")
	}
	r = withForm(setupRequest("POST", setupPath+"/create"), "csrf=x")
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

func TestGitHubSetupStartCapabilityAndPrefix(t *testing.T) {
	s, _, _ := setupFixture(t)
	token := s.startToken
	for _, path := range []string{setupPath, setupPath + "?token=wrong", setupPath + "?token=" + token + "&token=" + token} {
		w := runRequest(s, setupRequest("GET", path))
		if w.Code != 403 || len(w.Result().Cookies()) != 0 {
			t.Fatal("invalid capability bound a browser")
		}
	}
	for _, path := range []string{"/start", "/create", "/callback"} {
		if w := runRequest(s, setupRequest("GET", path)); w.Code != 404 {
			t.Fatal("setup endpoint escaped /__otgo prefix")
		}
	}
	cookie := startRegistration(t, s)
	if s.startToken != "" {
		t.Fatal("capability was not consumed")
	}
	if w := runRequest(s, setupRequest("GET", setupPath+"?token="+token)); w.Code != 403 || len(w.Result().Cookies()) != 0 {
		t.Fatal("consumed capability rebound a browser")
	}
	r := setupRequest("GET", setupPath)
	r.AddCookie(cookie)
	if w := runRequest(s, r); w.Code != 200 || len(w.Result().Cookies()) != 0 {
		t.Fatal("refresh replaced browser binding")
	}
	other, _, _ := setupFixture(t)
	if s.cookieName == other.cookieName {
		t.Fatal("concurrent loopback setup cookies collide across ports")
	}
	r = setupRequest("GET", setupPath)
	r.AddCookie(cookie)
	if w := runRequest(other, r); w.Code != 403 {
		t.Fatal("another wizard accepted the first wizard's cookie")
	}
}

func TestGitHubSetupCancellationDuringConversionPreservesConfig(t *testing.T) {
	s, _, _ := setupFixture(t)
	saved := s.cfg
	saved.CACertFile = filepath.Join(secureTempDir(t), "saved.pem")
	if err := SaveConfig(s.paths.AuthConfig, saved); err != nil {
		t.Fatal(err)
	}
	override := filepath.Join(secureTempDir(t), "replacement.pem")
	before, err := os.ReadFile(s.paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	converting, release := make(chan struct{}), make(chan struct{})
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			close(converting)
			<-release
			_, _ = io.WriteString(w, `{"client_id":"new-id","client_secret":"new-secret","html_url":"https://github.com/apps/test-app"}`)
			return
		}
		_, _ = io.WriteString(w, `{"id":123,"login":"allowed"}`)
	}))
	defer provider.Close()
	defer close(release)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	output := setupOutput{lines: make(chan string, 8)}
	done := make(chan error, 1)
	go func() {
		done <- runGitHubSetup(ctx, s.paths, s.binding, []string{"allowed"}, output, newGitHubProvider(provider.Client(), githubEndpoints{API: provider.URL}), SetupLaunch{CACertFile: &override})
	}()
	var address string
	select {
	case line := <-output.lines:
		address = strings.Fields(line)[1]
	case <-time.After(3 * time.Second):
		t.Fatal("wizard did not start")
	}
	client, u, state := approveRunningSetup(t, address)
	origin := u.Scheme + "://" + u.Host
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		res, err := setupGet(t.Context(), client, origin+setupPath+"/callback?state="+state+"&code=registration-code") // #nosec G704 -- Ephemeral loopback test server.
		if err == nil {
			_ = res.Body.Close()
		}
	}()
	select {
	case <-converting:
	case <-time.After(3 * time.Second):
		t.Fatal("conversion not reached")
	}
	cancel()
	// Observe shutdown closing its listener before letting the in-flight provider
	// return credentials. This recreates the old graceful-shutdown save race.
	deadline := time.Now().Add(time.Second)
	for {
		conn, dialErr := (&net.Dialer{Timeout: 50 * time.Millisecond}).DialContext(t.Context(), "tcp", u.Host)
		if dialErr != nil {
			break
		}
		_ = conn.Close()
		if time.Now().After(deadline) {
			t.Fatal("canceled listener stayed open")
		}
		time.Sleep(time.Millisecond)
	}
	release <- struct{}{}
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("canceled wizard returned %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("wizard did not join shutdown")
	}
	<-callbackDone
	after, err := os.ReadFile(s.paths.AuthConfig)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("canceled conversion changed auth configuration")
	}
}

func approveRunningSetup(t *testing.T, address string) (*http.Client, *url.URL, string) {
	t.Helper()
	u, err := url.Parse(address)
	if err != nil {
		t.Fatal(err)
	}
	origin := u.Scheme + "://" + u.Host
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	res, err := setupGet(t.Context(), client, address) // #nosec G704 -- Ephemeral loopback test server.
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	cookies := jar.Cookies(res.Request.URL)
	if len(cookies) != 1 {
		t.Fatal("missing browser binding")
	}
	req, err := http.NewRequestWithContext(t.Context(), "POST", origin+setupPath+"/create", strings.NewReader(url.Values{"csrf": {cookies[0].Value}}.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	_ = res.Body.Close()
	if err != nil || res.StatusCode != 200 {
		t.Fatal("manifest failed")
	}
	state := regexp.MustCompile(`state=([^"&]+)`).FindSubmatch(body)
	if len(state) != 2 {
		t.Fatal("missing registration state")
	}
	return client, u, string(state[1])
}

type committingSetupOutput struct {
	setupOutput
	committing, release chan struct{}
	cancel              context.CancelFunc
}

func (o committingSetupOutput) Write(b []byte) (int, error) {
	if strings.HasPrefix(string(b), "GitHub login configured") {
		o.cancel()
		close(o.committing)
		<-o.release
		return len(b), nil
	}
	return o.setupOutput.Write(b)
}
func TestGitHubSetupCancellationAfterCommitJoinsAndReportsSuccess(t *testing.T) {
	s, _, _ := setupFixture(t)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" {
			_, _ = io.WriteString(w, `{"client_id":"new-id","client_secret":"new-secret","html_url":"https://github.com/apps/test-app"}`)
		} else {
			_, _ = io.WriteString(w, `{"id":123,"login":"allowed"}`)
		}
	}))
	defer provider.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	output := committingSetupOutput{setupOutput: setupOutput{lines: make(chan string, 8)}, committing: make(chan struct{}), release: make(chan struct{}), cancel: cancel}
	defer close(output.release)
	done := make(chan error, 1)
	go func() {
		done <- runGitHubSetup(ctx, s.paths, s.binding, []string{"allowed"}, output, newGitHubProvider(provider.Client(), githubEndpoints{API: provider.URL}))
	}()
	var address string
	select {
	case line := <-output.lines:
		address = strings.Fields(line)[1]
	case <-time.After(3 * time.Second):
		t.Fatal("wizard did not start")
	}
	client, u, state := approveRunningSetup(t, address)
	callbackDone := make(chan struct{})
	go func() {
		defer close(callbackDone)
		res, err := setupGet(t.Context(), client, u.Scheme+"://"+u.Host+setupPath+"/callback?state="+state+"&code=registration-code") // #nosec G704 -- Ephemeral loopback test server.
		if err == nil {
			_ = res.Body.Close()
		}
	}()
	select {
	case <-output.committing:
	case <-time.After(3 * time.Second):
		t.Fatal("wizard did not commit")
	}
	// Exceed the graceful HTTP shutdown interval. A command that merely closes
	// the server would release profile locks while the callback still writes.
	select {
	case err := <-done:
		t.Fatalf("wizard returned before joining its committed callback: %v", err)
	case <-time.After(2200 * time.Millisecond):
	}
	output.release <- struct{}{}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("committed wizard reported cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("wizard did not join callback")
	}
	<-callbackDone
	cfg, err := LoadConfig(s.paths.AuthConfig)
	if err != nil || cfg.Mode != "github" {
		t.Fatal("successful commit not persisted")
	}
}

func setupGet(ctx context.Context, client *http.Client, address string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
	if err != nil {
		return nil, err
	}
	return client.Do(req)
}

func TestGitHubSetupReadyCallbackHasLiveListenerAndPrintedFallback(t *testing.T) {
	s, _, _ := setupFixture(t)
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"id":123,"login":"allowed"}`) }))
	defer provider.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	output := setupOutput{lines: make(chan string, 8)}
	invoked := false
	err := runGitHubSetup(ctx, s.paths, s.binding, []string{"allowed"}, output, newGitHubProvider(provider.Client(), githubEndpoints{API: provider.URL}), SetupLaunch{OnReady: func(ctx context.Context, address string) {
		invoked = true
		select {
		case line := <-output.lines:
			if !strings.Contains(line, address) {
				t.Error("fallback did not include setup URL")
			}
		default:
			t.Error("browser callback preceded printed fallback")
		}
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatal(err)
		}
		res, err := setupGet(ctx, &http.Client{Timeout: time.Second, Jar: jar}, address)
		if err != nil {
			t.Errorf("listener unavailable to browser: %v", err)
		} else {
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Errorf("setup status: %d", res.StatusCode)
			}
		}
		cancel()
	}})
	if !invoked || !errors.Is(err, context.Canceled) {
		t.Fatalf("callback=%v, result=%v", invoked, err)
	}
}

func TestGitHubSetupCACertCommitsWithApprovedCredentials(t *testing.T) {
	for _, mode := range []string{"retain", "replace", "clear"} {
		t.Run(mode, func(t *testing.T) {
			existing, out, _ := setupFixture(t)
			cfg := existing.cfg
			cfg.CACertFile = filepath.Join(secureTempDir(t), "saved.pem")
			if err := SaveConfig(existing.paths.AuthConfig, cfg); err != nil {
				t.Fatal(err)
			}
			var launch SetupLaunch
			want := cfg.CACertFile
			switch mode {
			case "replace":
				want = filepath.Join(secureTempDir(t), "replacement.pem")
				launch.CACertFile = &want
			case "clear":
				want = ""
				launch.CACertFile = &want
			}
			setup, err := newGitHubSetup(cfg, existing.paths, existing.binding, existing.accounts, existing.provider, existing.origin, out, launch)
			if err != nil {
				t.Fatal(err)
			}
			before, err := LoadConfig(existing.paths.AuthConfig)
			if err != nil || before.CACertFile != cfg.CACertFile {
				t.Fatal("CA changed before approval")
			}
			cookie := startRegistration(t, setup)
			if response := setupCallback(setup, cookie, setup.state); response.Code != http.StatusOK {
				t.Fatalf("callback: %d", response.Code)
			}
			after, err := LoadConfig(existing.paths.AuthConfig)
			if err != nil || after.CACertFile != want || after.Mode != "github" || after.GitHub.ClientSecret != "new-secret" {
				t.Fatal("CA and credentials not committed together")
			}
		})
	}
}
