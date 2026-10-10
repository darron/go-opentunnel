package authproxy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const GitHubStateCookie = "__Host-otgo-github-state"

type githubEndpoints struct{ Authorize, Token, API string }

// #nosec G101 -- Public endpoint URLs, not credentials.
var officialGitHub = githubEndpoints{Authorize: "https://github.com/login/oauth/authorize", Token: "https://github.com/login/oauth/access_token", API: "https://api.github.com"}

type githubProvider struct {
	client    *http.Client
	endpoints githubEndpoints
}

func newGitHubProvider(client *http.Client, endpoints githubEndpoints) *githubProvider {
	if client == nil {
		client = &http.Client{}
	}
	c := *client
	c.Jar = nil
	if c.Timeout <= 0 || c.Timeout > 10*time.Second {
		c.Timeout = 10 * time.Second
	}
	c.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return &githubProvider{client: &c, endpoints: endpoints}
}
func (p *githubProvider) request(ctx context.Context, method, address string, body io.Reader, bearer string, result any) error {
	r, e := http.NewRequestWithContext(ctx, method, address, body)
	if e != nil {
		return errors.New("cannot build GitHub request")
	}
	r.Header.Set("Accept", "application/json")
	r.Header.Set("User-Agent", "otgo")
	r.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if bearer != "" {
		r.Header.Set("Authorization", "Bearer "+bearer)
	}
	res, e := p.client.Do(r)
	if e != nil {
		return errors.New("GitHub request failed")
	}
	defer func() { _ = res.Body.Close() }()
	if res.StatusCode != http.StatusOK && res.StatusCode != http.StatusCreated {
		return errors.New("GitHub request rejected")
	}
	b, e := io.ReadAll(io.LimitReader(res.Body, maxFileBytes+1))
	if e != nil || len(b) > maxFileBytes {
		return errors.New("GitHub response is unreadable or too large")
	}
	if e = json.Unmarshal(b, result); e != nil {
		return errors.New("invalid GitHub response")
	}
	return nil
}
func (p *githubProvider) exchange(ctx context.Context, id, secret, code, verifier, redirect string) (string, error) {
	form := url.Values{"client_id": {id}, "client_secret": {secret}, "code": {code}, "code_verifier": {verifier}, "redirect_uri": {redirect}}
	var response struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if e := p.request(ctx, "POST", p.endpoints.Token, strings.NewReader(form.Encode()), "", &response); e != nil {
		return "", e
	}
	if response.AccessToken == "" || len(response.AccessToken) > 8192 || !strings.EqualFold(response.TokenType, "bearer") {
		return "", errors.New("GitHub did not return a valid user token")
	}
	return response.AccessToken, nil
}
func (p *githubProvider) user(ctx context.Context, token string) (GitHubAccount, error) {
	var account GitHubAccount
	if e := p.request(ctx, "GET", p.endpoints.API+"/user", nil, token, &account); e != nil {
		return account, e
	}
	if account.ID <= 0 || account.Login == "" || len(account.Login) > 39 {
		return GitHubAccount{}, errors.New("invalid GitHub identity")
	}
	return account, nil
}
func validGitHubLogin(login string) bool {
	if len(login) == 0 || len(login) > 39 || login[0] == '-' || login[len(login)-1] == '-' {
		return false
	}
	for _, c := range login {
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-'
		if !ok {
			return false
		}
	}
	return true
}
func (p *githubProvider) resolveUsers(ctx context.Context, names []string) ([]GitHubAccount, error) {
	if len(names) == 0 || len(names) > 256 {
		return nil, errors.New("one to 256 approved GitHub users are required")
	}
	for _, name := range names {
		if !validGitHubLogin(name) {
			return nil, errors.New("invalid GitHub username")
		}
	}
	accounts := make([]GitHubAccount, 0, len(names))
	seen := make(map[int64]bool)
	for _, name := range names {
		var a GitHubAccount
		if e := p.request(ctx, "GET", p.endpoints.API+"/users/"+url.PathEscape(name), nil, "", &a); e != nil {
			return nil, e
		}
		if a.ID <= 0 || !strings.EqualFold(a.Login, name) {
			return nil, errors.New("GitHub username resolution mismatch")
		}
		if !seen[a.ID] {
			accounts = append(accounts, a)
			seen[a.ID] = true
		}
	}
	return accounts, nil
}
func ResolveGitHubUsers(ctx context.Context, names []string) ([]GitHubAccount, error) {
	return newGitHubProvider(nil, officialGitHub).resolveUsers(ctx, names)
}

type githubPending struct {
	browser  [32]byte
	verifier string
	expires  time.Time
}
type GitHubBrowserAuthenticator struct{ *githubBrowserState }

type githubBrowserState struct {
	config   GitHubConfig
	sessions *Sessions
	origin   string
	provider *githubProvider
	allowed  map[int64]bool
	mu       sync.Mutex
	pending  map[string]githubPending
	now      func() time.Time
}

func NewGitHubBrowserAuthenticator(cfg Config, sessions *Sessions) (*GitHubBrowserAuthenticator, error) {
	return newGitHubBrowser(cfg, sessions, nil, officialGitHub)
}
func newGitHubBrowser(cfg Config, sessions *Sessions, client *http.Client, endpoints githubEndpoints) (*GitHubBrowserAuthenticator, error) {
	if cfg.Mode != "github" || sessions == nil {
		return nil, errors.New("GitHub configuration and sessions are required")
	}
	if e := validateConfig(cfg); e != nil {
		return nil, e
	}
	allowed := make(map[int64]bool, len(cfg.GitHub.Users))
	for _, a := range cfg.GitHub.Users {
		allowed[a.ID] = true
	}
	return &GitHubBrowserAuthenticator{&githubBrowserState{config: cfg.GitHub, sessions: sessions, origin: "https://" + cfg.Binding.Hostname, provider: newGitHubProvider(client, endpoints), allowed: allowed, pending: make(map[string]githubPending), now: time.Now}}, nil
}
func (g *GitHubBrowserAuthenticator) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /__otgo/login", func(w http.ResponseWriter, r *http.Request) { renderLogin(w, r, true, "") })
	mux.HandleFunc("GET /__otgo/github", g.begin)
	mux.HandleFunc("GET /__otgo/github/callback", g.callback)
}
func (g *GitHubBrowserAuthenticator) begin(w http.ResponseWriter, r *http.Request) {
	ownedHeaders(w)
	if values := r.Header.Values("Origin"); len(values) > 1 || len(values) == 1 && values[0] != g.origin {
		http.Error(w, "Invalid request origin", http.StatusForbidden)
		return
	}
	state, browser, verifier := randomSecret(), randomSecret(), randomSecret()
	g.mu.Lock()
	now := g.now()
	for s, p := range g.pending {
		if !now.Before(p.expires) {
			delete(g.pending, s)
		}
	}
	if len(g.pending) >= 256 {
		g.mu.Unlock()
		http.Error(w, "Login service busy", http.StatusServiceUnavailable)
		return
	}
	g.pending[state] = githubPending{browser: sha256.Sum256([]byte(browser)), verifier: verifier, expires: now.Add(10 * time.Minute)}
	g.mu.Unlock()
	challenge := sha256.Sum256([]byte(verifier))
	q := url.Values{"client_id": {g.config.ClientID}, "redirect_uri": {g.origin + "/__otgo/github/callback"}, "state": {state}, "code_challenge_method": {"S256"}, "code_challenge": {base64.RawURLEncoding.EncodeToString(challenge[:])}}
	http.SetCookie(w, authCookie(GitHubStateCookie, browser, 600))
	http.Redirect(w, r, g.provider.endpoints.Authorize+"?"+q.Encode(), http.StatusFound)
}
func (g *GitHubBrowserAuthenticator) callback(w http.ResponseWriter, r *http.Request) {
	ownedHeaders(w)
	q := r.URL.Query()
	state := q.Get("state")
	if len(q["state"]) != 1 || len(state) != 43 {
		http.Error(w, "Invalid login state", http.StatusForbidden)
		return
	}
	g.mu.Lock()
	pending, ok := g.pending[state]
	delete(g.pending, state)
	g.mu.Unlock()
	var browser string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == GitHubStateCookie {
			browser = c.Value
			count++
		}
	}
	sum := sha256.Sum256([]byte(browser))
	if !ok || !g.now().Before(pending.expires) || count != 1 || len(browser) != 43 || subtle.ConstantTimeCompare(sum[:], pending.browser[:]) != 1 {
		http.Error(w, "Invalid login state", http.StatusForbidden)
		return
	}
	http.SetCookie(w, authCookie(GitHubStateCookie, "", -1))
	if q.Get("error") != "" || len(q["code"]) != 1 || q.Get("code") == "" || len(q.Get("code")) > 2048 {
		http.Error(w, "GitHub login denied", http.StatusForbidden)
		return
	}
	token, e := g.provider.exchange(r.Context(), g.config.ClientID, g.config.ClientSecret, q.Get("code"), pending.verifier, g.origin+"/__otgo/github/callback")
	if e != nil {
		http.Error(w, "GitHub login failed", http.StatusBadGateway)
		return
	}
	account, e := g.provider.user(r.Context(), token)
	if e != nil {
		http.Error(w, "GitHub identity verification failed", http.StatusBadGateway)
		return
	}
	if !g.allowed[account.ID] {
		http.Error(w, "Account is not allowed", http.StatusForbidden)
		return
	}
	secret, e := g.sessions.Create(Principal{ID: strconv.FormatInt(account.ID, 10), Mechanism: "github"}, sessionLifetime)
	if e != nil {
		http.Error(w, "Login service busy", http.StatusServiceUnavailable)
		return
	}
	if old, e := r.Cookie(SessionCookie); e == nil {
		g.sessions.Revoke(old.Value)
	}
	http.SetCookie(w, authCookie(SessionCookie, secret, int(sessionLifetime.Seconds())))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
