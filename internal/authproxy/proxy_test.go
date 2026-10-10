package authproxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestProxyRemovesGateCredentials(t *testing.T) {
	var seen *http.Request
	var body string
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Clone(r.Context())
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.Header().Add("Set-Cookie", SessionCookie+"=forged; Path=/; Secure")
		w.Header().Add("Set-Cookie", CSRFCookie+" =forged; Path=/; Secure")
		w.Header().Add("Set-Cookie", "backend=ok; Path=/")
		w.Header().Set("Location", "http://"+r.Host+"/next?q=1")
		w.WriteHeader(302)
	})
	h, s, tokens := testHandler(t, backend)
	secret, _, err := tokens.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	r := publicRequest("POST", "/path%2Fsegment?q=1")
	r.Body = io.NopCloser(strings.NewReader("upload"))
	r.ContentLength = 6
	addSession(r, browserSession(t, s))
	r.AddCookie(authCookie(CSRFCookie, "private", 0))
	r.AddCookie(authCookie("backend", "session", 0))
	r.Header.Set("Authorization", "Bearer backend-auth")
	r.Header.Set("X-Otgo-Token", secret)
	r.Header.Set("Origin", "https://demo.test")
	for _, key := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "X-Authenticated-User", "Remote-User"} {
		r.Header.Set(key, "spoofed")
	}
	w := runRequest(h, r)
	if w.Code != 302 || body != "upload" || seen.URL.EscapedPath() != "/path%2Fsegment" || seen.URL.RawQuery != "q=1" {
		t.Fatalf("round trip: %d %q", w.Code, body)
	}
	if seen.Header.Get("Authorization") != "Bearer backend-auth" || seen.Header.Get("Cookie") != "backend=session" {
		t.Fatal("backend credentials changed or gate cookies leaked")
	}
	if seen.Header.Get("X-Otgo-Token") != "" || strings.Contains(seen.Header.Get("Cookie"), "private") {
		t.Fatal("gate secret leaked")
	}
	for _, key := range []string{"Forwarded", "X-Forwarded-For", "X-Forwarded-Host", "X-Real-IP", "X-Authenticated-User", "Remote-User"} {
		if seen.Header.Get(key) != "" {
			t.Errorf("spoofed %s", key)
		}
	}
	if seen.Header.Get("Origin") != "http://"+seen.Host {
		t.Fatalf("origin not adapted: %s", seen.Header.Get("Origin"))
	}
	if w.Header().Get("Location") != "https://demo.test/next?q=1" {
		t.Fatal("backend redirect not translated")
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "backend" {
		t.Fatal("backend set reserved cookie")
	}
	r = publicRequest("GET", "/")
	r.Header.Set("Authorization", "Bearer "+secret)
	runRequest(h, r)
	if seen.Header.Get("Authorization") != "" {
		t.Fatal("gate bearer leaked")
	}
}
func TestProxyRejectsUnsupportedProtocolsAndForeignOrigin(t *testing.T) {
	calls := 0
	h, s, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++; w.WriteHeader(204) }))
	cookie := browserSession(t, s)
	for _, upgrade := range []string{"h2c", "other"} {
		r := publicRequest("GET", "/")
		addSession(r, cookie)
		r.Header.Set("Origin", "https://demo.test")
		r.Header.Set("Connection", "upgrade")
		r.Header.Set("Upgrade", upgrade)
		if w := runRequest(h, r); w.Code != 400 {
			t.Fatal("unsupported upgrade")
		}
	}
	r := publicRequest("CONNECT", "/")
	addSession(r, cookie)
	r.Header.Set("Origin", "https://demo.test")
	if w := runRequest(h, r); w.Code != 400 {
		t.Fatal("CONNECT accepted")
	}
	r = publicRequest("POST", "/")
	addSession(r, cookie)
	r.Header.Set("Origin", "https://sibling.test")
	if w := runRequest(h, r); w.Code != 403 {
		t.Fatal("foreign origin")
	}
	if calls != 0 {
		t.Fatal("invalid request reached backend")
	}
}
func TestProxyExternalRedirectIsPreserved(t *testing.T) {
	h, s, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://other.test/path")
		w.WriteHeader(302)
	}))
	r := publicRequest("GET", "/")
	addSession(r, browserSession(t, s))
	w := runRequest(h, r)
	if w.Code != 302 || w.Header().Get("Location") != "https://other.test/path" {
		t.Fatal("external redirect changed")
	}
}
func proxySurface(t *testing.T, h *Handler) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = h.config.Binding.Hostname
		r.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: r.Host}
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}
func TestProxyStreamRevocation(t *testing.T) {
	for _, mode := range []string{"token revoke", "registry corrupt", "session logout", "expiry", "handler close"} {
		t.Run(mode, func(t *testing.T) {
			h, s, tokens := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/event-stream")
				_, _ = io.WriteString(w, "data: hello\n\n")
				_ = http.NewResponseController(w).Flush()
				<-r.Context().Done()
			}))
			surface := proxySurface(t, h)
			req, err := http.NewRequestWithContext(t.Context(), "GET", surface.URL+"/mcp", nil)
			if err != nil {
				t.Fatal(err)
			}
			secret, id, err := tokens.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "session logout" {
				secret = browserSession(t, s)
				addSession(req, secret)
			} else {
				req.Header.Set("Authorization", "Bearer "+secret)
			}
			if mode == "expiry" {
				secret, _, err = tokens.Create(500 * time.Millisecond)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("Authorization", "Bearer "+secret)
			}
			res, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = res.Body.Close() }()
			reader := bufio.NewReader(res.Body)
			line, err := reader.ReadString('\n')
			if err != nil || line != "data: hello\n" {
				t.Fatal("SSE did not flush")
			}
			started := time.Now()
			switch mode {
			case "token revoke":
				err = tokens.Revoke(id)
			case "registry corrupt":
				err = os.WriteFile(tokens.path, []byte("broken"), 0600)
			case "session logout":
				s.Revoke(secret)
			case "handler close":
				err = h.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			ended := make(chan error, 1)
			go func() { _, e := io.Copy(io.Discard, reader); ended <- e }()
			select {
			case <-ended:
				if time.Since(started) > time.Second {
					t.Fatal("slow stream revocation")
				}
			case <-time.After(2 * time.Second):
				t.Fatal("stream survived revocation")
			}
		})
	}
}
func TestProxyWebSocketRevocationAndClose(t *testing.T) {
	for _, mode := range []string{"revoke", "close"} {
		t.Run(mode, func(t *testing.T) {
			h, _, tokens := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				c, e := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
				if e != nil {
					return
				}
				defer func() { _ = c.CloseNow() }()
				for {
					typ, b, e := c.Read(r.Context())
					if e != nil {
						return
					}
					if e = c.Write(r.Context(), typ, b); e != nil {
						return
					}
				}
			}))
			surface := proxySurface(t, h)
			secret, id, err := tokens.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			c, res, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(surface.URL, "http")+"/mcp", &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + secret}}})
			if err != nil {
				if res != nil {
					_ = res.Body.Close()
				}
				t.Fatal(err)
			}
			defer func() { _ = c.CloseNow() }()
			if err = c.Write(ctx, websocket.MessageText, []byte("hello")); err != nil {
				t.Fatal(err)
			}
			_, b, err := c.Read(ctx)
			if err != nil || string(b) != "hello" {
				t.Fatal("WebSocket round trip")
			}
			start := time.Now()
			if mode == "close" {
				err = h.Close()
			} else {
				err = tokens.Revoke(id)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err = c.Read(ctx); err == nil || time.Since(start) > time.Second {
				t.Fatal("WebSocket survived credential shutdown")
			}
		})
	}
}
func TestProxyStreamAdmissionLimit(t *testing.T) {
	h, _, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) }))
	_ = h.Close()
	if w := runRequest(h, publicRequest("GET", "/")); w.Code != 503 {
		t.Fatal("closed handler admitted request")
	}
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
}
