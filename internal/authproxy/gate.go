package authproxy

import (
	"crypto/subtle"
	"errors"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

const SessionCookie = "__Host-otgo-session"
const CSRFCookie = "__Host-otgo-csrf"
const sessionLifetime = 8 * time.Hour

type BrowserAuthenticator interface{ Register(*http.ServeMux) }
type credential struct {
	secret    string
	machine   bool
	principal Principal
}

func (h *Handler) authenticate(r *http.Request) (credential, error) {
	auth := r.Header.Values("Authorization")
	xt := r.Header.Values("X-Otgo-Token")
	if len(auth) > 1 || len(xt) > 1 {
		return credential{}, errUnauthorized
	}
	var cookie string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == SessionCookie {
			count++
			cookie = c.Value
		}
	}
	if count > 1 {
		return credential{}, errUnauthorized
	}
	bearer := ""
	if len(auth) == 1 {
		fields := strings.Fields(auth[0])
		if len(fields) >= 2 && strings.EqualFold(fields[0], "Bearer") && strings.HasPrefix(fields[1], "otgo_") {
			if len(fields) != 2 {
				return credential{}, errUnauthorized
			}
			bearer = fields[1]
		}
	}
	if bearer != "" && len(xt) > 0 {
		return credential{}, errUnauthorized
	}
	if len(xt) > 0 {
		bearer = xt[0]
		if bearer == "" {
			return credential{}, errUnauthorized
		}
	}
	if bearer != "" {
		if h.tokens == nil {
			return credential{}, errUnauthorized
		}
		p, e := h.tokens.Authenticate(bearer)
		return credential{secret: bearer, machine: true, principal: p}, e
	}
	p, e := h.sessions.Authenticate(cookie)
	return credential{secret: cookie, principal: p}, e
}
func (h *Handler) validOrigin(r *http.Request, c credential) bool {
	origins := r.Header.Values("Origin")
	if len(origins) > 1 {
		return false
	}
	if len(origins) == 1 && origins[0] != h.origin {
		return false
	}
	if !c.machine {
		for _, key := range []string{"Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
			if len(r.Header.Values(key)) > 1 {
				return false
			}
		}
		// Keep links and bookmarks usable, but do not let another site load
		// authenticated scripts, images, frames or API responses with cookies.
		site := r.Header.Get("Sec-Fetch-Site")
		if site == "same-site" || site == "cross-site" {
			if r.Method != "GET" || r.Header.Get("Sec-Fetch-Mode") != "navigate" || r.Header.Get("Sec-Fetch-Dest") != "document" {
				return false
			}
		}
	}
	unsafe := r.Method != "GET" && r.Method != "HEAD" && r.Method != "OPTIONS"
	ws := r.Header.Get("Upgrade") != ""
	return c.machine || (!unsafe && !ws) || len(origins) == 1
}
func (h *Handler) validPublicRequest(r *http.Request) bool {
	return r.Host == h.config.Binding.Hostname && r.TLS != nil && r.TLS.HandshakeComplete && r.TLS.ServerName == h.config.Binding.Hostname && !r.URL.IsAbs() && r.URL.Host == ""
}
func ownedHeaders(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

// HTML form POSTs under no-referrer send Origin: null. Preserve their real
// same-origin Origin without exposing a Referer to other sites.
func ownedFormHeaders(w http.ResponseWriter) {
	ownedHeaders(w)
	w.Header().Set("Referrer-Policy", "same-origin")
}
func authCookie(name, value string, maxAge int) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, MaxAge: maxAge}
}
func csrfMatches(r *http.Request) bool {
	var val string
	count := 0
	for _, c := range r.Cookies() {
		if c.Name == CSRFCookie {
			count++
			val = c.Value
		}
	}
	given := r.PostForm.Get("csrf")
	return count == 1 && len(val) == 43 && len(given) == 43 && subtle.ConstantTimeCompare([]byte(val), []byte(given)) == 1
}

func renderLogin(w http.ResponseWriter, r *http.Request, github bool, message string) {
	ownedFormHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	csrf := randomSecret()
	http.SetCookie(w, authCookie(CSRFCookie, csrf, 600))
	w.WriteHeader(http.StatusUnauthorized)
	if r.Method != "HEAD" {
		_ = pages.ExecuteTemplate(w, "login", struct {
			CSRF    string
			GitHub  bool
			Message string
		}{csrf, github, message})
	}
}

type PasswordBrowserAuthenticator struct{ *passwordBrowserState }

type passwordBrowserState struct {
	verifier  PasswordVerifier
	sessions  *Sessions
	origin    string
	mu        sync.Mutex
	allowance float64
	last      time.Time
	now       func() time.Time
	slots     chan struct{}
}

func NewPasswordBrowserAuthenticator(cfg Config, s *Sessions) *PasswordBrowserAuthenticator {
	return &PasswordBrowserAuthenticator{&passwordBrowserState{verifier: cfg.Password, sessions: s, origin: "https://" + cfg.Binding.Hostname, allowance: 10, last: time.Now(), now: time.Now, slots: make(chan struct{}, 2)}}
}
func (p *PasswordBrowserAuthenticator) admit() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	p.allowance += now.Sub(p.last).Seconds()
	p.last = now
	if p.allowance > 10 {
		p.allowance = 10
	}
	if p.allowance < 1 {
		return false
	}
	p.allowance--
	return true
}
func (p *PasswordBrowserAuthenticator) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /__otgo/login", func(w http.ResponseWriter, r *http.Request) { renderLogin(w, r, false, "") })
	mux.HandleFunc("POST /__otgo/login", p.login)
}
func (p *PasswordBrowserAuthenticator) login(w http.ResponseWriter, r *http.Request) {
	ownedHeaders(w)
	if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != p.origin {
		http.Error(w, "Invalid request origin", http.StatusForbidden)
		return
	}
	if e := parseOwnedForm(w, r); e != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(e, &tooLarge) {
			http.Error(w, "Login request too large", http.StatusRequestEntityTooLarge)
		} else {
			http.Error(w, "Invalid login request", http.StatusBadRequest)
		}
		return
	}
	if !csrfMatches(r) {
		http.Error(w, "Invalid login request", http.StatusForbidden)
		return
	}
	select {
	case p.slots <- struct{}{}:
		defer func() { <-p.slots }()
	default:
		http.Error(w, "Login service busy", http.StatusTooManyRequests)
		return
	}
	if !p.admit() {
		http.Error(w, "Too many login attempts", http.StatusTooManyRequests)
		return
	}
	if len(r.PostForm["password"]) != 1 || !VerifyPassword(p.verifier, []byte(r.PostForm.Get("password"))) {
		renderLogin(w, r, false, "Invalid password")
		return
	}
	secret, e := p.sessions.Create(Principal{ID: "password", Mechanism: "password"}, sessionLifetime)
	if e != nil {
		http.Error(w, "Login service busy", http.StatusServiceUnavailable)
		return
	}
	if old, e := r.Cookie(SessionCookie); e == nil {
		p.sessions.Revoke(old.Value)
	}
	http.SetCookie(w, authCookie(SessionCookie, secret, int(sessionLifetime.Seconds())))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}
func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	ownedHeaders(w)
	c, e := h.authenticate(r)
	if e != nil || c.machine {
		http.Error(w, "Sign in required", http.StatusUnauthorized)
		return
	}
	if r.Method == "GET" {
		ownedFormHeaders(w)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		csrf := randomSecret()
		http.SetCookie(w, authCookie(CSRFCookie, csrf, 600))
		_ = pages.ExecuteTemplate(w, "logout", csrf)
		return
	}
	if !h.validOrigin(r, c) {
		http.Error(w, "Invalid request origin", http.StatusForbidden)
		return
	}
	if e := parseOwnedForm(w, r); e != nil || !csrfMatches(r) {
		http.Error(w, "Invalid logout request", http.StatusForbidden)
		return
	}
	h.sessions.Revoke(c.secret)
	http.SetCookie(w, authCookie(SessionCookie, "", -1))
	http.SetCookie(w, authCookie(CSRFCookie, "", -1))
	http.Redirect(w, r, "/__otgo/login", http.StatusSeeOther)
}

// Auth forms have a short body deadline; authenticated uploads and streams do
// not. Failed reads retain that deadline through net/http's unread-body drain.
func parseOwnedForm(w http.ResponseWriter, r *http.Request) error {
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(2 * time.Second))
	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/x-www-form-urlencoded" {
		w.Header().Set("Connection", "close")
		return errors.New("auth form requires URL-encoded content")
	}
	if err := r.ParseForm(); err != nil {
		w.Header().Set("Connection", "close")
		return err
	}
	_ = controller.SetReadDeadline(time.Time{})
	return nil
}
