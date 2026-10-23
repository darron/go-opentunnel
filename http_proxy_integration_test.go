package opentunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func clearProxyEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"HTTP_PROXY", "http_proxy", "HTTPS_PROXY", "https_proxy", "ALL_PROXY", "all_proxy", "NO_PROXY", "no_proxy", "REQUEST_METHOD"} {
		t.Setenv(key, "")
	}
}

// The destination name deliberately does not resolve. Only this proxy (or an
// explicit NO_PROXY dial override) can map it to the real TLS relay fixture.
func connectProxy(t *testing.T, destination string, handle func(http.ResponseWriter, *http.Request) bool, tlsConfig *tls.Config) *httptest.Server {
	t.Helper()
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if handle != nil && !handle(w, r) {
			return
		}
		remote, err := (&net.Dialer{Timeout: time.Second}).DialContext(r.Context(), "tcp", destination)
		if err != nil {
			http.Error(w, "destination unavailable", http.StatusBadGateway)
			return
		}
		incoming, buffer, err := proxyHijacker(t, w).Hijack()
		if err != nil {
			_ = remote.Close()
			return
		}
		defer func() { _ = incoming.Close(); _ = remote.Close() }()
		_ = incoming.SetDeadline(time.Now().Add(15 * time.Second))
		_ = remote.SetDeadline(time.Now().Add(15 * time.Second))
		if _, err = io.WriteString(incoming, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		done := make(chan struct{})
		go func() { _, _ = io.Copy(remote, buffer); _ = remote.Close(); close(done) }()
		_, _ = io.Copy(incoming, remote)
		_ = incoming.Close()
		<-done
	}))
	if tlsConfig != nil {
		server.TLS = tlsConfig.Clone()
		server.StartTLS()
	} else {
		server.Start()
	}
	t.Cleanup(server.Close)
	return server
}

func TestEnvironmentProxyTunnel(t *testing.T) {
	for _, mode := range []string{"HTTPS_PROXY", "ALL_PROXY", "all_proxy", "https proxy", "NO_PROXY", "socks5", "socks5h", "transient reconnect"} {
		t.Run(mode, func(t *testing.T) {
			clearProxyEnvironment(t)
			var mu sync.Mutex
			paths := map[string]int{}
			var leaked atomic.Bool
			f, caFile := newTLSRelay(t, func(next http.Handler) http.Handler {
				return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					paths[r.URL.Path]++
					mu.Unlock()
					if r.Header.Get("Proxy-Authorization") != "" {
						leaked.Store(true)
					}
					next.ServeHTTP(w, r)
				})
			})
			destination, err := url.Parse(f.api.server.URL)
			if err != nil {
				t.Fatal(err)
			}
			target := net.JoinHostPort("egress-relay.invalid", destination.Port())
			var connects atomic.Int64
			var failNext atomic.Bool
			var failures atomic.Int64
			var proxyTLS *tls.Config
			if mode == "https proxy" {
				proxyTLS = f.api.server.TLS
			}
			proxy := connectProxy(t, destination.Host, func(w http.ResponseWriter, r *http.Request) bool {
				if r.Method != "CONNECT" || r.Host != target || r.Header.Get("Proxy-Authorization") != "Basic dXNlcjpwYXNz" {
					http.Error(w, "invalid proxy request", http.StatusProxyAuthRequired)
					return false
				}
				if failNext.CompareAndSwap(true, false) {
					failures.Add(1)
					w.WriteHeader(http.StatusServiceUnavailable)
					return false
				}
				connects.Add(1)
				return true
			}, proxyTLS)
			p, err := url.Parse(proxy.URL)
			if err != nil {
				t.Fatal(err)
			}
			p.User = url.UserPassword("user", "pass")
			if mode == "socks5" || mode == "socks5h" {
				p, err = url.Parse(mode + "://" + socksProxy(t, destination.Host, target, &connects))
				if err != nil {
					t.Fatal(err)
				}
			}
			key := mode
			if mode == "https proxy" || mode == "NO_PROXY" || strings.HasPrefix(mode, "socks5") || mode == "transient reconnect" {
				key = "ALL_PROXY"
			}
			t.Setenv(key, p.String())
			t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")
			if mode == "HTTPS_PROXY" {
				t.Setenv("ALL_PROXY", "ftp://unused.invalid")
			}
			if mode == "NO_PROXY" {
				t.Setenv("NO_PROXY", "egress-relay.invalid")
			}
			client, err := NewHTTPClientWithCACert(caFile)
			if err != nil {
				t.Fatal(err)
			}
			transport := proxyTestTransport(t, client)
			// Verify the real relay certificate rather than the deliberately unmapped DNS alias.
			transport.TLSClientConfig.ServerName = "localhost"
			var direct atomic.Int64
			if mode == "NO_PROXY" {
				transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
					if address != target {
						t.Errorf("unexpected direct dial %q", address)
					}
					direct.Add(1)
					return (&net.Dialer{}).DialContext(ctx, network, destination.Host)
				}
			}
			c, err := NewClient(ClientOptions{API: "https://" + target, HTTPClient: client, Storage: NewMemoryStorage(), Transport: TransportOptions{CertificatePollInterval: time.Millisecond, BackoffMin: time.Millisecond, BackoffMax: 2 * time.Millisecond}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close(); client.CloseIdleConnections() }()
			connection := connectTest(t, c, Routes{"@": echoTarget(t)})
			defer func() { _ = connection.Close() }()
			session := f.next(t)
			for round := 0; round < 2; round++ {
				public := session.public(t, uint32(round+1), "demo.test")
				payload := "proxy transport roundtrip"
				if _, err := io.WriteString(public, payload); err != nil {
					t.Fatal(err)
				}
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(public, got); err != nil || string(got) != payload {
					t.Fatalf("payload=%q error=%v", got, err)
				}
				_ = public.Close()
				if round == 0 {
					if mode == "transient reconnect" {
						failNext.Store(true)
					}
					session.close()
					session = f.next(t)
				}
			}
			if mode == "transient reconnect" && (failures.Load() != 1 || connection.Stats().BridgeFailures < 1) {
				t.Fatalf("transient failures=%d stats=%+v", failures.Load(), connection.Stats())
			}
			mu.Lock()
			defer mu.Unlock()
			if paths["/api/tunnel"] != 1 || paths["/api/tunnel/demo/certificate"] == 0 || paths["/api/tunnel/demo/connect"] < 2 || leaked.Load() {
				t.Fatalf("paths=%v leaked=%v", paths, leaked.Load())
			}
			if mode == "NO_PROXY" {
				if connects.Load() != 0 || direct.Load() < 3 {
					t.Fatalf("proxy=%d direct=%d", connects.Load(), direct.Load())
				}
			} else if connects.Load() < 3 {
				t.Fatalf("CONNECT count=%d; API and both bridges must use proxy", connects.Load())
			}
		})
	}
}

func TestProxyRejectionDiagnostics(t *testing.T) {
	for _, status := range []int{403, 407} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			clearProxyEnvironment(t)
			var attempts atomic.Int64
			proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				attempts.Add(1)
				c, _, err := proxyHijacker(t, w).Hijack()
				if err != nil {
					return
				}
				defer func() { _ = c.Close() }()
				_, _ = fmt.Fprintf(c, "HTTP/1.1 %d credential-canary\r\nContent-Length: 17\r\nConnection: close\r\n\r\ncredential-canary", status)
			}))
			defer proxy.Close()
			t.Setenv("ALL_PROXY", proxy.URL)
			c, err := NewClient(ClientOptions{Storage: NewMemoryStorage()})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_, err = c.API().Get(t.Context(), "demo", "tunnel-token-canary")
			if err == nil || !strings.Contains(err.Error(), http.StatusText(status)) || strings.Contains(err.Error(), "canary") || attempts.Load() != 1 {
				t.Fatalf("error=%v attempts=%d", err, attempts.Load())
			}
		})
	}
}

func TestProxyTunnelTLSVerification(t *testing.T) {
	for _, mode := range []string{"untrusted CA", "wrong hostname"} {
		t.Run(mode, func(t *testing.T) {
			clearProxyEnvironment(t)
			f, caFile := newTLSRelay(t)
			destination, _ := url.Parse(f.api.server.URL)
			proxy := connectProxy(t, destination.Host, nil, nil)
			t.Setenv("ALL_PROXY", proxy.URL)
			client, err := NewHTTPClientWithCACert(caFile)
			if err != nil {
				t.Fatal(err)
			}
			defer client.CloseIdleConnections()
			tr := proxyTestTransport(t, client)
			if mode == "untrusted CA" {
				tr.TLSClientConfig.RootCAs = x509.NewCertPool()
				tr.TLSClientConfig.ServerName = "localhost"
			}
			api, err := NewAPI("https://egress-relay.invalid:"+destination.Port(), client, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = api.Get(t.Context(), "demo", "canary")
			var verification *tls.CertificateVerificationError
			if !errors.As(err, &verification) {
				t.Fatalf("TLS verification not enforced: %v", err)
			}
		})
	}
}

func TestProxyMalformedResponseRedacted(t *testing.T) {
	clearProxyEnvironment(t)
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		c, _, err := proxyHijacker(t, w).Hijack()
		if err != nil {
			return
		}
		defer func() { _ = c.Close() }()
		_, _ = io.WriteString(c, "credential-canary\r\n\r\n")
	}))
	defer proxy.Close()
	p, _ := url.Parse(proxy.URL)
	p.User = url.UserPassword("user", "proxy-password-canary")
	t.Setenv("ALL_PROXY", p.String())
	c, err := NewClient(ClientOptions{Storage: NewMemoryStorage(), RequestTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, err = c.API().Get(t.Context(), "demo", "token-canary")
	if err == nil || !strings.Contains(err.Error(), "outbound proxy") || strings.Contains(err.Error(), "canary") {
		t.Fatalf("error=%v", err)
	}

}

func TestProxyBridgeRejectionIsTerminal(t *testing.T) {
	for _, status := range []int{403, 407} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			clearProxyEnvironment(t)
			f, caFile := newTLSRelay(t)
			destination, _ := url.Parse(f.api.server.URL)
			var reject atomic.Bool
			var rejections atomic.Int64
			proxy := connectProxy(t, destination.Host, func(w http.ResponseWriter, _ *http.Request) bool {
				if reject.Load() {
					rejections.Add(1)
					w.WriteHeader(status)
					return false
				}
				return true
			}, nil)
			t.Setenv("ALL_PROXY", proxy.URL)
			httpClient, err := NewHTTPClientWithCACert(caFile)
			if err != nil {
				t.Fatal(err)
			}
			defer httpClient.CloseIdleConnections()
			proxyTestTransport(t, httpClient).TLSClientConfig.ServerName = "localhost"
			c, err := NewClient(ClientOptions{API: "https://egress-relay.invalid:" + destination.Port(), HTTPClient: httpClient, Storage: NewMemoryStorage(), Transport: TransportOptions{CertificatePollInterval: time.Millisecond}})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			if _, err = c.Ensure(t.Context(), "default"); err != nil {
				t.Fatal(err)
			}
			reject.Store(true) // The pooled API connection still works; the new bridge CONNECT is denied.
			ctx, cancel := context.WithTimeout(t.Context(), time.Second)
			defer cancel()
			_, err = c.Connect(ctx, ConnectOptions{Routes: Routes{"@": echoTarget(t)}})
			var p *proxyError
			if !errors.As(err, &p) || !p.permanent || !strings.Contains(err.Error(), http.StatusText(status)) || rejections.Load() != 1 {
				t.Fatalf("error=%v rejects=%d", err, rejections.Load())
			}
		})
	}
}

func TestExplicitProxyTransportOverride(t *testing.T) {
	clearProxyEnvironment(t)
	t.Setenv("ALL_PROXY", "ftp://invalid-canary")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNotFound) }))
	defer server.Close()
	var calls atomic.Int64
	base := proxyTestTransport(t, &http.Client{Transport: http.DefaultTransport}).Clone()
	base.Proxy = func(*http.Request) (*url.URL, error) { calls.Add(1); return nil, nil } //nolint:nilnil // net/http uses nil, nil to select a direct connection.
	defer base.CloseIdleConnections()
	supplied := &http.Client{Transport: base}
	c, err := NewClient(ClientOptions{API: server.URL, HTTPClient: supplied, Storage: NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.API().Get(t.Context(), "demo", "token")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusNotFound {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || supplied.Transport != base || c.ownedHTTPClient != nil {
		t.Fatal("caller-owned transport changed, closed or proxy callback repeated")
	}
}

func TestProxyConnectionFailureRetainsDeadline(t *testing.T) {
	clearProxyEnvironment(t)
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	_ = listener.Close()
	t.Setenv("ALL_PROXY", "http://user:credential-canary@"+address)
	c, err := NewClient(ClientOptions{Storage: NewMemoryStorage(), RequestTimeout: 50 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	for _, method := range []string{"get", "create", "remove"} {
		t.Run(method, func(t *testing.T) {
			switch method {
			case "get":
				_, err = c.API().Get(t.Context(), "demo", "token-canary")
			case "create":
				_, err = c.API().Create(t.Context())
			case "remove":
				err = c.API().Remove(t.Context(), "demo", "token-canary")
			}
			if err == nil || !strings.Contains(err.Error(), "outbound proxy") || strings.Contains(err.Error(), "canary") || !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func socksProxy(t *testing.T, destination, target string, connections *atomic.Int64) string {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	workers.Add(1)
	go func() {
		defer workers.Done()
		for {
			socket, err := listener.Accept()
			if err != nil {
				return
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer func() { _ = socket.Close() }()
				_ = socket.SetDeadline(time.Now().Add(15 * time.Second))
				greeting := make([]byte, 3)
				if _, err := io.ReadFull(socket, greeting); err != nil {
					return
				}
				if string(greeting) != string([]byte{5, 1, 0}) {
					t.Errorf("SOCKS greeting=%v", greeting)
					return
				}
				if _, err := socket.Write([]byte{5, 0}); err != nil {
					return
				}
				request := make([]byte, 5)
				if _, err := io.ReadFull(socket, request); err != nil {
					return
				}
				if request[0] != 5 || request[1] != 1 || request[3] != 3 {
					t.Errorf("SOCKS request=%v", request)
					return
				}
				address := make([]byte, int(request[4])+2)
				if _, err := io.ReadFull(socket, address); err != nil {
					return
				}
				host := string(address[:len(address)-2])
				port := int(address[len(address)-2])<<8 | int(address[len(address)-1])
				if net.JoinHostPort(host, fmt.Sprint(port)) != target {
					t.Errorf("SOCKS target=%s:%d", host, port)
					return
				}
				remote, err := (&net.Dialer{Timeout: time.Second}).DialContext(t.Context(), "tcp", destination)
				if err != nil {
					t.Error(err)
					return
				}
				defer func() { _ = remote.Close() }()
				_ = remote.SetDeadline(time.Now().Add(15 * time.Second))
				if _, err := socket.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0}); err != nil {
					return
				}
				connections.Add(1)
				done := make(chan struct{})
				go func() { _, _ = io.Copy(remote, socket); _ = remote.Close(); close(done) }()
				_, _ = io.Copy(socket, remote)
				_ = socket.Close()
				<-done
			}()
		}
	}()
	t.Cleanup(func() { _ = listener.Close(); workers.Wait() })
	return listener.Addr().String()
}

func proxyTestTransport(t *testing.T, client *http.Client) *http.Transport {
	t.Helper()
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("expected *http.Transport, got %T", client.Transport)
	}
	return transport
}
func proxyHijacker(t *testing.T, w http.ResponseWriter) http.Hijacker {
	t.Helper()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		t.Errorf("expected http.Hijacker, got %T", w)
	}
	return hijacker
}

func TestProxyCreateAmbiguousFailureNotReplayed(t *testing.T) {
	clearProxyEnvironment(t)
	var attempts atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		attempts.Add(1)
		socket, _, err := proxyHijacker(t, w).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = socket.Close()
	}))
	defer server.Close()
	destination, _ := url.Parse(server.URL)
	proxy := connectProxy(t, destination.Host, nil, nil)
	t.Setenv("ALL_PROXY", proxy.URL)
	// The normal trusted-root transport still owns all actual proxy networking.
	client, _ := defaultProxyClient(nil)
	proxyTestTransport(t, client).TLSClientConfig = proxyTestTransport(t, server.Client()).TLSClientConfig.Clone()
	defer client.CloseIdleConnections()
	api, err := NewAPI("https://egress-relay.invalid:"+destination.Port(), client, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	proxyTestTransport(t, client).TLSClientConfig.ServerName = "example.com"
	_, err = api.Create(t.Context())
	if err == nil || attempts.Load() != 1 || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("error=%v origin requests=%d", err, attempts.Load())
	}
}

func TestProxySOCKSFailuresRedacted(t *testing.T) {
	for _, mode := range []string{"malformed", "authentication", "refusal"} {
		t.Run(mode, func(t *testing.T) {
			clearProxyEnvironment(t)
			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			var workers sync.WaitGroup
			workers.Add(1)
			go func() {
				defer workers.Done()
				for {
					socket, err := listener.Accept()
					if err != nil {
						return
					}
					workers.Add(1)
					go func() {
						defer workers.Done()
						defer func() { _ = socket.Close() }()
						_ = socket.SetDeadline(time.Now().Add(2 * time.Second))
						greeting := make([]byte, 2)
						if _, err := io.ReadFull(socket, greeting); err != nil {
							return
						}
						methods := make([]byte, int(greeting[1]))
						if _, err := io.ReadFull(socket, methods); err != nil {
							return
						}
						if mode == "malformed" {
							_, _ = socket.Write([]byte{99, 0})
							return
						}
						if mode == "authentication" {
							if _, err := socket.Write([]byte{5, 2}); err != nil {
								return
							}
							auth := make([]byte, 2)
							if _, err := io.ReadFull(socket, auth); err != nil {
								return
							}
							user := make([]byte, int(auth[1])+1)
							if _, err := io.ReadFull(socket, user); err != nil {
								return
							}
							password := make([]byte, int(user[len(user)-1]))
							if _, err := io.ReadFull(socket, password); err != nil {
								return
							}
							_, _ = socket.Write([]byte{1, 1})
							return
						}
						if _, err := socket.Write([]byte{5, 0}); err != nil {
							return
						}
						request := make([]byte, 5)
						if _, err := io.ReadFull(socket, request); err != nil {
							return
						}
						address := make([]byte, int(request[4])+2)
						if _, err := io.ReadFull(socket, address); err != nil {
							return
						}
						_, _ = socket.Write([]byte{5, 2, 0, 1, 127, 0, 0, 1, 0, 0})
					}()
				}
			}()
			defer func() { _ = listener.Close(); workers.Wait() }()
			t.Setenv("ALL_PROXY", "socks5://user:credential-canary@"+listener.Addr().String())
			c, err := NewClient(ClientOptions{Storage: NewMemoryStorage(), RequestTimeout: 100 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = c.Close() }()
			_, err = c.API().Create(t.Context())
			if err == nil || !strings.Contains(err.Error(), "outbound proxy") || strings.Contains(err.Error(), "canary") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProxyUppercaseLocalhostStaysDirect(t *testing.T) {
	clearProxyEnvironment(t)
	var proxyCalls, originCalls atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyCalls.Add(1)
		w.WriteHeader(http.StatusProxyAuthRequired)
	}))
	defer proxy.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { originCalls.Add(1); w.WriteHeader(http.StatusNotFound) }))
	defer server.Close()
	t.Setenv("HTTP_PROXY", proxy.URL)
	c, err := NewClient(ClientOptions{API: strings.Replace(server.URL, "127.0.0.1", "LOCALHOST", 1), Storage: NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_, err = c.API().Get(t.Context(), "demo", "local-token-canary")
	var remote *APIError
	if !errors.As(err, &remote) || remote.StatusCode != http.StatusNotFound || originCalls.Load() != 1 || proxyCalls.Load() != 0 {
		t.Fatalf("error=%v origin=%d proxy=%d", err, originCalls.Load(), proxyCalls.Load())
	}
}
