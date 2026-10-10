package authproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

type Options struct {
	Config               Config
	TokenStore           *TokenStore
	Sessions             *Sessions
	BrowserAuthenticator BrowserAuthenticator
}
type Handler struct{ *handlerState }

type handlerState struct {
	config    Config
	origin    string
	tokens    *TokenStore
	sessions  *Sessions
	owned     *http.ServeMux
	proxy     *httputil.ReverseProxy
	transport *http.Transport
	mu        sync.Mutex
	closed    bool
	active    map[*requestLease]credential
	stop      chan struct{}
	watched   chan struct{}
	wg        sync.WaitGroup
}
type connContextKey struct{}

// WithClientConnection lets the HTTP server abort a blocked client write or a
// hijacked socket when its credential expires. The value must come from ConnContext.
func WithClientConnection(ctx context.Context, c net.Conn) context.Context {
	return context.WithValue(ctx, connContextKey{}, c)
}

type requestLease struct {
	cancel   context.CancelFunc
	client   net.Conn
	mu       sync.Mutex
	hijacked net.Conn
	aborted  bool
	finished bool
}

func (l *requestLease) terminate() {
	l.mu.Lock()
	if l.finished || l.aborted {
		l.mu.Unlock()
		return
	}
	l.aborted = true
	client, hijacked := l.client, l.hijacked
	l.mu.Unlock()
	l.cancel()
	abortConnection(client)
	abortConnection(hijacked)
}

// Revocation must abort the transport, without waiting for a TLS close_notify
// write to a peer that may have stopped reading.
func abortConnection(c net.Conn) {
	if c == nil {
		return
	}
	if wrapped, ok := c.(interface{ NetConn() net.Conn }); ok {
		c = wrapped.NetConn()
	}
	_ = c.Close()
}

type leaseWriter struct {
	http.ResponseWriter
	lease *requestLease
}

func (w *leaseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w *leaseWriter) Flush()                      { _ = http.NewResponseController(w.ResponseWriter).Flush() }
func (w *leaseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	c, r, e := http.NewResponseController(w.ResponseWriter).Hijack()
	if e != nil {
		return nil, nil, e
	}
	w.lease.mu.Lock()
	w.lease.hijacked = c
	aborted := w.lease.aborted
	w.lease.mu.Unlock()
	if aborted {
		abortConnection(c)
		return nil, nil, net.ErrClosed
	}
	return c, r, nil
}
func NewHandler(o Options) (*Handler, error) {
	if e := validateConfig(o.Config); e != nil {
		return nil, e
	}
	if o.Sessions == nil {
		o.Sessions = NewSessions(1024)
	}
	h := &Handler{&handlerState{config: o.Config, origin: "https://" + o.Config.Binding.Hostname, tokens: o.TokenStore, sessions: o.Sessions, owned: http.NewServeMux(), active: make(map[*requestLease]credential), stop: make(chan struct{}), watched: make(chan struct{})}}
	browser := o.BrowserAuthenticator
	if browser == nil {
		if o.Config.Mode == "github" {
			var e error
			browser, e = NewGitHubBrowserAuthenticator(o.Config, h.sessions)
			if e != nil {
				return nil, e
			}
		} else {
			browser = NewPasswordBrowserAuthenticator(o.Config, h.sessions)
		}
	}

	browser.Register(h.owned)
	h.owned.HandleFunc("GET /__otgo/logout", h.logout)
	h.owned.HandleFunc("POST /__otgo/logout", h.logout)
	upstream, e := upstreamURL(o.Config.Upstream)
	if e != nil {
		return nil, e
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok {
		return nil, errors.New("default HTTP transport was replaced")
	}
	h.transport = base.Clone()
	h.transport.Proxy = nil
	h.transport.ResponseHeaderTimeout = 15 * time.Second
	h.transport.MaxConnsPerHost = 256
	h.proxy = &httputil.ReverseProxy{Transport: h.transport, FlushInterval: -1, ErrorLog: log.New(io.Discard, "", 0), ErrorHandler: func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Upstream unavailable", http.StatusBadGateway)
	}, Rewrite: func(p *httputil.ProxyRequest) {
		p.SetURL(upstream)
		p.Out.Host = upstream.Host
		stripRequestCredentials(p.Out)
		if p.In.Header.Get("Origin") == h.origin {
			p.Out.Header.Set("Origin", upstream.Scheme+"://"+upstream.Host)
		}
		if ref, e := url.Parse(p.In.Header.Get("Referer")); e == nil && ref.Scheme+"://"+ref.Host == h.origin {
			ref.Scheme = upstream.Scheme
			ref.Host = upstream.Host
			p.Out.Header.Set("Referer", ref.String())
		}
	}, ModifyResponse: func(res *http.Response) error {
		cookies := res.Header.Values("Set-Cookie")
		res.Header.Del("Set-Cookie")
		for _, c := range cookies {
			name, _, _ := strings.Cut(c, "=")
			if !strings.HasPrefix(strings.TrimSpace(name), "__Host-otgo-") {
				res.Header.Add("Set-Cookie", c)
			}
		}
		location := res.Header.Get("Location")
		if u, e := url.Parse(location); e == nil && u.Host == upstream.Host && (u.Scheme == upstream.Scheme || u.Scheme == "") {
			u.Scheme = "https"
			u.Host = h.config.Binding.Hostname
			res.Header.Set("Location", u.String())
		}
		return nil
	}}
	go h.watch()
	return h, nil
}
func stripRequestCredentials(r *http.Request) {
	for key := range r.Header {
		k := strings.ToLower(key)
		if k == "forwarded" || k == "x-real-ip" || k == "remote-user" || k == "x-remote-user" || k == "cf-connecting-ip" || k == "true-client-ip" || k == "x-client-ip" || strings.HasPrefix(k, "x-forwarded-") || strings.HasPrefix(k, "x-auth-") || strings.HasPrefix(k, "x-authenticated-") || strings.HasPrefix(k, "x-otgo-") || strings.HasPrefix(k, "x-user") || strings.HasPrefix(k, "x-github-") || strings.HasPrefix(k, "x-goog-authenticated-") || strings.HasPrefix(k, "cf-access-") {
			r.Header.Del(key)
		}
	}
	fields := strings.Fields(r.Header.Get("Authorization"))
	if len(fields) == 2 && strings.EqualFold(fields[0], "Bearer") && strings.HasPrefix(fields[1], "otgo_") {
		r.Header.Del("Authorization")
	}
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if !strings.HasPrefix(c.Name, "__Host-otgo-") {
			r.AddCookie(c)
		}
	}
}
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Even a denied request can make net/http drain an unfinished body. Bound
	// untrusted body reads, then remove the limit only for authenticated forwarding.
	controller := http.NewResponseController(w)
	_ = controller.SetReadDeadline(time.Now().Add(2 * time.Second))
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	client, _ := ctx.Value(connContextKey{}).(net.Conn)
	lease := &requestLease{cancel: cancel, client: client}
	h.mu.Lock()
	if h.closed || len(h.active) >= 256 {
		h.mu.Unlock()
		http.Error(w, "Proxy unavailable", http.StatusServiceUnavailable)
		return
	}
	h.active[lease] = credential{}
	h.wg.Add(1)
	h.mu.Unlock()
	defer func() {
		lease.mu.Lock()
		lease.finished = true
		lease.mu.Unlock()
		h.mu.Lock()
		delete(h.active, lease)
		h.mu.Unlock()
		h.wg.Done()
	}()
	r = r.WithContext(ctx)
	if !h.validPublicRequest(r) {
		http.Error(w, "Misdirected request", http.StatusMisdirectedRequest)
		return
	}
	if strings.HasPrefix(r.URL.Path, "/__otgo/") || r.URL.Path == "/__otgo" {
		ownedHeaders(w)
		h.owned.ServeHTTP(w, r)
		return
	}
	c, e := h.authenticate(r)
	if e != nil {
		if r.Method == "GET" && strings.Contains(r.Header.Get("Accept"), "text/html") {
			renderLogin(w, r, h.config.Mode == "github", "")
		} else {
			ownedHeaders(w)
			http.Error(w, "Sign in required", http.StatusUnauthorized)
		}
		return
	}
	if !h.validOrigin(r, c) {
		http.Error(w, "Invalid request origin", http.StatusForbidden)
		return
	}
	if r.Method == "CONNECT" || r.Header.Get("Upgrade") != "" && !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		http.Error(w, "Unsupported protocol", http.StatusBadRequest)
		return
	}
	h.mu.Lock()
	h.active[lease] = c
	h.mu.Unlock()
	_ = controller.SetReadDeadline(time.Time{})
	h.proxy.ServeHTTP(&leaseWriter{ResponseWriter: w, lease: lease}, r)
}
func (h *Handler) watch() {
	defer close(h.watched)
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-h.stop:
			return
		case <-ticker.C:
			h.mu.Lock()
			snapshot := make(map[*requestLease]credential, len(h.active))
			for l, c := range h.active {
				snapshot[l] = c
			}
			h.mu.Unlock()
			for l, c := range snapshot {
				if c.secret == "" {
					continue
				}
				var e error
				if c.machine {
					_, e = h.tokens.Authenticate(c.secret)
				} else {
					_, e = h.sessions.Authenticate(c.secret)
				}
				if e != nil {
					l.terminate()
				}
			}
		}
	}
}
func (h *Handler) Close() error {
	h.mu.Lock()
	if !h.closed {
		h.closed = true
		close(h.stop)
	}
	leases := make([]*requestLease, 0, len(h.active))
	for l := range h.active {
		leases = append(leases, l)
	}
	h.mu.Unlock()
	for _, l := range leases {
		l.terminate()
	}
	h.sessions.Close()
	h.transport.CloseIdleConnections()
	<-h.watched
	h.wg.Wait()
	return nil
}
