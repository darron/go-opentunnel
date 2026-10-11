package authproxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const setupCookie = "otgo-github-setup"
const setupPath = "/__otgo/github/setup"

type githubManifest struct {
	Name           string   `json:"name"`
	URL            string   `json:"url"`
	RedirectURL    string   `json:"redirect_url"`
	CallbackURLs   []string `json:"callback_urls"`
	HookAttributes struct {
		URL    string `json:"url"`
		Active bool   `json:"active"`
	} `json:"hook_attributes"`
	DefaultPermissions map[string]string `json:"default_permissions"`
	DefaultEvents      []string          `json:"default_events"`
	Public             bool              `json:"public"`
}
type githubSetup struct{ *githubSetupState }

type githubSetupState struct {
	cfg                    Config
	paths                  Paths
	binding                Binding
	accounts               []GitHubAccount
	provider               *githubProvider
	origin, state          string
	startToken, cookieName string
	manifest               string
	mu                     sync.Mutex
	browser                [32]byte
	created, used          bool
	closing, commitStarted bool
	commitErr              error
	ctx                    context.Context
	callbacks              sync.WaitGroup
	expires                time.Time
	now                    func() time.Time
	completed              chan error
	out                    io.Writer
}

func newGitHubSetup(cfg Config, paths Paths, binding Binding, accounts []GitHubAccount, provider *githubProvider, origin string, out io.Writer) (*githubSetup, error) {
	if e := ValidateBinding(cfg, binding); e != nil {
		return nil, e
	}
	if e := validateConfig(cfg); e != nil {
		return nil, e
	}
	if len(accounts) == 0 {
		return nil, errors.New("GitHub allowlist cannot be empty")
	}
	u, e := url.Parse(origin)
	if e != nil || u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Path != "" {
		return nil, errors.New("setup requires an exact loopback origin")
	}
	public := "https://" + binding.Hostname
	m := githubManifest{Name: "otgo-" + strings.Split(binding.Hostname, ".")[0] + "-" + hex.EncodeToString(randomBytes(3)), URL: public + "/__otgo/login", RedirectURL: origin + setupPath + "/callback", CallbackURLs: []string{public + "/__otgo/github/callback"}, DefaultPermissions: map[string]string{}, DefaultEvents: []string{}, Public: true}
	m.HookAttributes.URL = public + "/__otgo/github/webhook"
	m.HookAttributes.Active = false
	b, e := json.Marshal(m)
	if e != nil {
		return nil, errors.New("cannot encode GitHub manifest")
	}
	return &githubSetup{&githubSetupState{cfg: cfg, paths: paths, binding: binding, accounts: accounts, provider: provider, origin: origin, state: randomSecret(), startToken: randomSecret(), cookieName: setupCookie + "-" + hex.EncodeToString(randomBytes(8)), manifest: string(b), expires: time.Now().Add(10 * time.Minute), now: time.Now, completed: make(chan error, 1), out: out, ctx: context.Background()}}, nil
}

var setupPage = template.Must(template.New("setup").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Set up otgo GitHub login</title><h1>Set up GitHub login</h1><p>This creates a GitHub App for your tunnel. GitHub will ask you to approve creation. No repository write permissions or webhook deliveries are requested.</p><form method="post" action="/__otgo/github/setup/create"><input type="hidden" name="csrf" value="{{.}}"><button>Continue to GitHub</button></form></html>`))
var manifestPage = template.Must(template.New("manifest").Parse(`<!doctype html><html lang="en"><meta charset="utf-8"><title>Create GitHub App</title><h1>Create your GitHub App</h1><form method="post" action="https://github.com/settings/apps/new?state={{.State}}"><input type="hidden" name="manifest" value="{{.Manifest}}"><button>Create GitHub App on GitHub</button></form></html>`))

func (s *githubSetup) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ownedHeaders(w)
	u, _ := url.Parse(s.origin)
	if r.Host != u.Host {
		http.Error(w, "Misdirected request", http.StatusMisdirectedRequest)
		return
	}
	if !s.now().Before(s.expires) {
		http.Error(w, "Setup expired", http.StatusGone)
		return
	}
	if origins := r.Header.Values("Origin"); len(origins) > 1 || len(origins) == 1 && origins[0] != s.origin {
		http.Error(w, "Invalid request origin", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == "GET" && r.URL.Path == setupPath:
		s.start(w, r)
	case r.Method == "POST" && r.URL.Path == setupPath+"/create":
		if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != s.origin {
			http.Error(w, "Invalid request origin", http.StatusForbidden)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if e := r.ParseForm(); e != nil {
			http.Error(w, "Invalid setup request", http.StatusBadRequest)
			return
		}
		s.mu.Lock()
		valid := !s.used && s.validBrowser(r) && len(r.PostForm["csrf"]) == 1 && subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(s.browserCookie(r))) == 1
		if valid {
			s.created = true
		}
		s.mu.Unlock()
		if !valid {
			http.Error(w, "Invalid setup request", http.StatusForbidden)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; form-action https://github.com; base-uri 'none'; frame-ancestors 'none'")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = manifestPage.Execute(w, struct{ State, Manifest string }{s.state, s.manifest})
	case r.Method == "GET" && r.URL.Path == setupPath+"/callback":
		s.callback(w, r)
	default:
		http.NotFound(w, r)
	}
}

// start binds exactly one browser. The capability is consumed before redirecting
// to a clean URL, so refreshes neither expose it nor replace the browser cookie.
func (s *githubSetup) start(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.used {
		http.Error(w, "Setup already completed", http.StatusGone)
		return
	}
	q := r.URL.Query()
	if s.browser != ([32]byte{}) {
		if !s.validBrowser(r) || len(q["token"]) > 1 {
			http.Error(w, "Invalid setup request", http.StatusForbidden)
			return
		}
		if len(q["token"]) != 0 {
			http.Redirect(w, r, setupPath, http.StatusSeeOther)
			return
		}
		ownedFormHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = setupPage.Execute(w, s.browserCookie(r))
		return
	}
	if len(q["token"]) != 1 || len(q.Get("token")) != 43 || subtle.ConstantTimeCompare([]byte(q.Get("token")), []byte(s.startToken)) != 1 {
		http.Error(w, "Invalid setup request", http.StatusForbidden)
		return
	}
	secret := randomSecret()
	s.browser = sha256.Sum256([]byte(secret))
	s.startToken = ""
	http.SetCookie(w, &http.Cookie{Name: s.cookieName, Value: secret, Path: setupPath, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: 600}) // #nosec G124 -- Temporary HTTP loopback endpoint cannot use a Secure cookie.
	http.Redirect(w, r, setupPath, http.StatusSeeOther)
}
func (s *githubSetup) browserCookie(r *http.Request) string {
	var secret string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == s.cookieName {
			secret = c.Value
			count++
		}
	}
	if count != 1 || len(secret) != 43 {
		return ""
	}
	return secret
}
func (s *githubSetup) validBrowser(r *http.Request) bool {
	secret := s.browserCookie(r)
	if secret == "" {
		return false
	}
	sum := sha256.Sum256([]byte(secret))
	return subtle.ConstantTimeCompare(sum[:], s.browser[:]) == 1
}
func safeAppManagementURL(raw string) string {
	u, e := url.Parse(raw)
	if e == nil && u.Scheme == "https" && u.Host == "github.com" && u.User == nil && u.RawQuery == "" && u.Fragment == "" {
		parts := strings.Split(u.Path, "/")
		if len(parts) == 3 && parts[1] == "apps" && ValidProfile(parts[2]) {
			return "https://github.com/settings/apps/" + parts[2]
		}
	}
	return "https://github.com/settings/apps"
}
func (s *githubSetup) callback(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.mu.Lock()
	valid := !s.closing && s.ctx.Err() == nil && s.created && !s.used && s.validBrowser(r) && len(q["state"]) == 1 && len(q["code"]) == 1 && q.Get("state") == s.state && q.Get("code") != "" && len(q.Get("code")) <= 2048
	if valid {
		s.used = true
		s.callbacks.Add(1)
	}
	s.mu.Unlock()
	if !valid {
		http.Error(w, "Invalid setup callback", http.StatusForbidden)
		return
	}
	defer s.callbacks.Done()
	var converted struct {
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		HTMLURL      string `json:"html_url"`
	}
	e := s.provider.request(r.Context(), "POST", s.provider.endpoints.API+"/app-manifests/"+url.PathEscape(q.Get("code"))+"/conversions", nil, "", &converted)
	if e != nil {
		http.Error(w, "GitHub registration conversion failed", http.StatusBadGateway)
		s.completed <- e
		return
	}
	management := safeAppManagementURL(converted.HTMLURL)
	cfg := s.cfg
	cfg.Mode = "github"
	cfg.Password = PasswordVerifier{}
	cfg.GitHub = GitHubConfig{ClientID: converted.ClientID, ClientSecret: converted.ClientSecret, Users: s.accounts, AppURL: management}
	// Cancellation before this boundary preserves the previous configuration.
	// Once persistence begins, shutdown joins it and reports its actual result.
	s.mu.Lock()
	if e = s.ctx.Err(); e != nil || s.closing {
		s.mu.Unlock()
		_, writeErr := fmt.Fprintf(s.out, "GitHub App was created, but setup stopped before saving. Manage or delete it at %s\n", management)
		if e == nil {
			e = context.Canceled
		}
		http.Error(w, "Setup stopped; see terminal for cleanup URL", http.StatusServiceUnavailable)
		s.completed <- errors.Join(e, writeErr)
		return
	}
	s.commitStarted = true
	if e = SaveConfig(s.paths.AuthConfig, cfg); e != nil {
		s.mu.Unlock()
		_, writeErr := fmt.Fprintf(s.out, "GitHub App was created, but local setup failed. Manage or delete it at %s\n", management)
		http.Error(w, "App created but local setup failed; see terminal for cleanup URL", http.StatusInternalServerError)
		e = errors.Join(errors.New("GitHub App created but credentials could not be saved"), writeErr)
		s.mu.Lock()
		s.commitErr = e
		s.mu.Unlock()
		s.completed <- e
		return
	}
	s.mu.Unlock()
	_, e = fmt.Fprintf(s.out, "GitHub login configured for https://%s\nManage the GitHub App: %s\n", s.binding.Hostname, management)
	s.mu.Lock()
	s.commitErr = e
	s.mu.Unlock()
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, "GitHub login is configured. You can close this tab and start otgo proxy.\n")
	s.completed <- e
}
func RunGitHubSetup(ctx context.Context, paths Paths, binding Binding, approvedUsers []string, out io.Writer) error {
	return runGitHubSetup(ctx, paths, binding, approvedUsers, out, newGitHubProvider(nil, officialGitHub))
}
func runGitHubSetup(ctx context.Context, paths Paths, binding Binding, approvedUsers []string, out io.Writer, provider *githubProvider) (result error) {
	if e := ctx.Err(); e != nil {
		return e
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	cfg, e := LoadConfig(paths.AuthConfig)
	if e != nil {
		return e
	}
	if e = ValidateBinding(cfg, binding); e != nil {
		return e
	}
	accounts, e := provider.resolveUsers(ctx, approvedUsers)
	if e != nil {
		return e
	}
	listener, e := (&net.ListenConfig{}).Listen(ctx, "tcp", "127.0.0.1:0")
	if e != nil {
		return errors.New("cannot listen for GitHub setup")
	}
	defer func() { _ = listener.Close() }()
	origin := "http://" + listener.Addr().String()
	setup, e := newGitHubSetup(cfg, paths, binding, accounts, provider, origin, out)
	if e != nil {
		return e
	}
	setup.ctx = ctx
	server := &http.Server{BaseContext: func(net.Listener) context.Context { return ctx }, Handler: setup, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10}
	startURL := origin + setupPath + "?token=" + setup.startToken
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener) }()
	defer func() {
		setup.mu.Lock()
		setup.closing = true
		setup.mu.Unlock()
		cancel()
		shutdown, stop := context.WithTimeout(context.Background(), 2*time.Second)
		defer stop()
		_ = server.Shutdown(shutdown)
		_ = server.Close()
		setup.callbacks.Wait()
		setup.mu.Lock()
		if setup.commitStarted {
			result = setup.commitErr
		}
		setup.mu.Unlock()
		<-served
	}()
	if _, e = fmt.Fprintf(out, "Open %s to register the GitHub App. Setup expires in ten minutes.\n", startURL); e != nil {
		return e
	}
	select {
	case e := <-setup.completed:
		return e
	case <-ctx.Done():
		return ctx.Err()
	case e := <-served:
		served <- e
		return e
	}
}
