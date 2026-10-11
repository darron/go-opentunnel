package authproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestRevocationAbortsTLSWithoutCloseNotify(t *testing.T) {
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	defer fixture.Close()
	serverWire, clientWire := net.Pipe()
	defer func() { _ = serverWire.Close(); _ = clientWire.Close() }()
	server := tls.Server(serverWire, fixture.TLS.Clone())
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	client := tls.Client(clientWire, &tls.Config{RootCAs: roots, ServerName: "example.com", MinVersion: tls.VersionTLS12})
	ctx, stop := context.WithTimeout(context.Background(), 3*time.Second)
	defer stop()
	ready := make(chan error, 1)
	go func() { ready <- server.HandshakeContext(ctx) }()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-ready; err != nil {
		t.Fatal(err)
	}
	lease := &requestLease{cancel: func() {}, client: server, hijacked: server}
	done := make(chan struct{})
	go func() { lease.terminate(); close(done) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		_ = clientWire.Close()
		<-done
		t.Fatal("forced revocation waited for a peer to read TLS close_notify")
	}
}

func TestCompletedLeaseCannotAbortReusedConnection(t *testing.T) {
	server, peer := net.Pipe()
	defer func() { _ = server.Close(); _ = peer.Close() }()
	canceled := false
	lease := &requestLease{cancel: func() { canceled = true }, client: server, finished: true}
	lease.terminate()
	if canceled {
		t.Fatal("a stale watcher snapshot canceled a completed request")
	}
	_ = peer.SetWriteDeadline(time.Now().Add(time.Second))
	done := make(chan error, 1)
	go func() { _, err := peer.Write([]byte("x")); done <- err }()
	buf := make([]byte, 1)
	if _, err := server.Read(buf); err != nil {
		t.Fatalf("completed lease closed the reused connection: %v", err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeFormattingRedactsActiveSecrets(t *testing.T) {
	h, s, tokens := testHandler(t, http.NotFoundHandler())
	secret, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	l := &requestLease{cancel: func() {}}
	h.mu.Lock()
	h.active[l] = credential{secret: secret, machine: true}
	h.mu.Unlock()
	t.Cleanup(func() { h.mu.Lock(); delete(h.active, l); h.mu.Unlock() })
	p := NewPasswordBrowserAuthenticator(h.config, s)
	cfg := h.config
	cfg.Mode = "github"
	cfg.GitHub = GitHubConfig{ClientID: "client", ClientSecret: "sensitive-github-client-secret", Users: []GitHubAccount{{ID: 1, Login: "owner"}}}
	g, err := NewGitHubBrowserAuthenticator(cfg, s)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{h, p, g, reflect.ValueOf(h).Elem().Interface(), reflect.ValueOf(p).Elem().Interface(), reflect.ValueOf(g).Elem().Interface()} {
		for _, verb := range []string{"%v", "%+v", "%#v"} {
			out := fmt.Sprintf(verb, value)
			for _, forbidden := range []string{secret, h.config.Password.Salt, h.config.Password.Digest, cfg.GitHub.ClientSecret} {
				if strings.Contains(out, forbidden) {
					t.Fatalf("runtime formatting exposed a secret with %s", verb)
				}
			}
		}
	}
}

func TestSlowLoginBodyDoesNotOccupyHashSlots(t *testing.T) {
	for _, contentType := range []string{"application/x-www-form-urlencoded", "application/json", "multipart/form-data"} {
		t.Run(contentType, func(t *testing.T) { slowLoginBody(t, contentType) })
	}
}

func slowLoginBody(t *testing.T, contentType string) {
	cfg := fixtureConfig()
	verifier, err := NewPasswordVerifier([]byte("test-password"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Password = verifier
	sessions := NewSessions(1024)
	p := NewPasswordBrowserAuthenticator(cfg, sessions)
	mux := http.NewServeMux()
	p.Register(mux)
	started := make(chan struct{}, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && r.ContentLength == 99 {
			started <- struct{}{}
		}
		mux.ServeHTTP(w, r)
	}))
	defer server.Close()
	peers := make([]net.Conn, 0, 2)
	defer func() {
		for _, c := range peers {
			_ = c.Close()
		}
	}()
	for range 2 {
		c, e := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", strings.TrimPrefix(server.URL, "http://"))
		if e != nil {
			t.Fatal(e)
		}
		peers = append(peers, c)
		_, e = io.WriteString(c, "POST /__otgo/login HTTP/1.1\r\nHost: demo.test\r\nOrigin: https://demo.test\r\nContent-Type: "+contentType+"\r\nContent-Length: 99\r\n\r\npassword=")
		if e != nil {
			t.Fatal(e)
		}
		<-started
	}
	// The handlers have entered body parsing; neither peer supplies the remaining bytes.
	time.Sleep(50 * time.Millisecond)
	form := url.Values{"password": {"test-password"}, "csrf": {strings.Repeat("c", 43)}}
	r, err := http.NewRequestWithContext(context.Background(), "POST", server.URL+"/__otgo/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", "https://demo.test")
	r.AddCookie(authCookie(CSRFCookie, strings.Repeat("c", 43), 600))
	client := &http.Client{Timeout: 4 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}
	res, err := client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	if res.StatusCode != http.StatusSeeOther {
		t.Fatalf("slow unauthenticated bodies disabled login: %d", res.StatusCode)
	}
	for _, c := range peers {
		_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
		res, err := http.ReadResponse(bufio.NewReader(c), nil)
		if err != nil {
			t.Fatalf("slow login was not bounded: %v", err)
		}
		_ = res.Body.Close()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("slow login: %d", res.StatusCode)
		}
	}
}

func TestDeniedRequestBodiesHaveReadDeadline(t *testing.T) {
	h, _, _ := testHandler(t, http.NotFoundHandler())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: "demo.test"}
		h.ServeHTTP(w, r)
	}))
	defer server.Close()
	for _, tc := range []struct {
		path, origin string
		status       int
	}{
		{"/mcp", "", 401}, {"/__otgo/login", "https://evil.test", 403}, {"/__otgo/unknown", "", 404},
	} {
		t.Run(tc.path+tc.origin, func(t *testing.T) {
			c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", strings.TrimPrefix(server.URL, "http://"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_, err = fmt.Fprintf(c, "POST %s HTTP/1.1\r\nHost: demo.test\r\nOrigin: %s\r\nContent-Type: application/json\r\nContent-Length: 99\r\n\r\n{", tc.path, tc.origin)
			if err != nil {
				t.Fatal(err)
			}
			_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
			res, err := http.ReadResponse(bufio.NewReader(c), nil)
			if err != nil {
				t.Fatalf("denied request held the connection indefinitely: %v", err)
			}
			_ = res.Body.Close()
			if res.StatusCode != tc.status {
				t.Fatalf("status: %d", res.StatusCode)
			}
		})
	}
}

func TestAuthenticatedUploadClearsUntrustedDeadline(t *testing.T) {
	h, _, tokens := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.Copy(w, r.Body) }))
	secret, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: "demo.test"}
		h.ServeHTTP(w, r)
	}))
	defer server.Close()
	c, err := (&net.Dialer{Timeout: time.Second}).DialContext(context.Background(), "tcp", strings.TrimPrefix(server.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, err = fmt.Fprintf(c, "POST /upload HTTP/1.1\r\nHost: demo.test\r\nAuthorization: Bearer %s\r\nContent-Length: 1\r\n\r\n", secret)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2100 * time.Millisecond)
	if _, err = io.WriteString(c, "x"); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(4 * time.Second))
	res, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(res.Body)
	if err != nil || res.StatusCode != 200 || string(body) != "x" {
		t.Fatal("authenticated upload inherited the untrusted body deadline")
	}
}

// A handler must finish revocation's transport abort before net/http can reuse
// its client connection for the next request.
type pausedCloseConn struct {
	net.Conn
	entered chan struct{}
	release chan struct{}
}

func (c *pausedCloseConn) Close() error {
	close(c.entered)
	<-c.release
	return c.Conn.Close()
}
func TestLeaseCompletionWaitsForTransportAbort(t *testing.T) {
	server, client := net.Pipe()
	defer func() { _ = client.Close() }()
	conn := &pausedCloseConn{Conn: server, entered: make(chan struct{}), release: make(chan struct{})}
	releaseClosed := false
	defer func() {
		if !releaseClosed {
			close(conn.release)
		}
	}()
	lease := &requestLease{cancel: func() {}, client: conn}
	aborted := make(chan struct{})
	go func() { lease.terminate(); close(aborted) }()
	select {
	case <-conn.entered:
	case <-time.After(time.Second):
		t.Fatal("revocation did not close its transport")
	}
	finished := make(chan struct{})
	go func() { lease.finish(); close(finished) }()
	select {
	case <-finished:
		t.Fatal("handler completed while an old revocation close could still reach a reused connection")
	case <-time.After(100 * time.Millisecond):
	}
	// Finish the abort before waiting for completion, without leaving goroutines
	// behind even when the pre-fix assertion above fails.
	close(conn.release)
	releaseClosed = true
	select {
	case <-aborted:
	case <-time.After(time.Second):
		t.Fatal("abort did not finish")
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("handler did not finish after abort")
	}
}
