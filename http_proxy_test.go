package opentunnel

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestEnvironmentProxy(t *testing.T) {
	tests := []struct {
		name, target  string
		env           map[string]string
		want, failure string
	}{
		{name: "all https", target: "https://relay.example/api", env: map[string]string{"ALL_PROXY": "http://proxy.example:3128"}, want: "http://proxy.example:3128"},
		{name: "all http", target: "http://relay.example/api", env: map[string]string{"all_proxy": "socks5h://proxy.example:1080"}, want: "socks5h://proxy.example:1080"},
		{name: "specific wins", target: "https://relay.example", env: map[string]string{"HTTPS_PROXY": "http://secure.example:1", "ALL_PROXY": "http://fallback.example:2"}, want: "http://secure.example:1"},
		{name: "uppercase wins", target: "https://relay.example", env: map[string]string{"ALL_PROXY": "http://upper.example", "all_proxy": "http://lower.example"}, want: "http://upper.example"},
		{name: "lowercase specific", target: "https://relay.example", env: map[string]string{"https_proxy": "http://lower.example", "ALL_PROXY": "http://fallback.example"}, want: "http://lower.example"},
		{name: "no cross scheme", target: "https://relay.example", env: map[string]string{"HTTP_PROXY": "http://http.example"}},
		{name: "bare host", target: "https://relay.example", env: map[string]string{"ALL_PROXY": "proxy.example:3128"}, want: "http://proxy.example:3128"},
		{name: "loopback", target: "https://127.0.0.1", env: map[string]string{"ALL_PROXY": "http://proxy.example"}},
		{name: "CGI loopback", target: "http://LOCALHOST", env: map[string]string{"HTTP_PROXY": "http://proxy.example", "REQUEST_METHOD": "GET"}},
		{name: "localhost suffix", target: "https://localhost.example", env: map[string]string{"ALL_PROXY": "http://proxy.example"}, want: "http://proxy.example"},
		{name: "uppercase localhost", target: "http://LOCALHOST", env: map[string]string{"ALL_PROXY": "http://proxy.example"}},
		{name: "localhost", target: "http://localhost", env: map[string]string{"ALL_PROXY": "http://proxy.example"}},
		{name: "ipv6 loopback", target: "https://[::1]", env: map[string]string{"ALL_PROXY": "http://proxy.example"}},
		{name: "domain bypass", target: "https://sub.relay.example", env: map[string]string{"ALL_PROXY": "http://proxy.example", "NO_PROXY": "relay.example"}},
		{name: "domain boundary", target: "https://notrelay.example", env: map[string]string{"ALL_PROXY": "http://proxy.example", "NO_PROXY": "relay.example"}, want: "http://proxy.example"},
		{name: "cidr", target: "https://10.2.3.4", env: map[string]string{"ALL_PROXY": "http://proxy.example", "no_proxy": "10.0.0.0/8"}},
		{name: "ipv6 cidr", target: "https://[2001:db8::2]", env: map[string]string{"ALL_PROXY": "http://proxy.example", "NO_PROXY": "2001:db8::/32"}},
		{name: "port bypass", target: "https://relay.example", env: map[string]string{"ALL_PROXY": "http://proxy.example", "NO_PROXY": "relay.example:443"}},
		{name: "other port", target: "https://relay.example:8443", env: map[string]string{"ALL_PROXY": "http://proxy.example", "NO_PROXY": "relay.example:443"}, want: "http://proxy.example"},
		{name: "star", target: "https://relay.example", env: map[string]string{"ALL_PROXY": "http://proxy.example", "NO_PROXY": "*"}},
		{name: "unicode", target: "https://bücher.example", env: map[string]string{"ALL_PROXY": "http://proxy.example", "NO_PROXY": "xn--bcher-kva.example"}},
		{name: "invalid scheme", target: "https://relay.example", env: map[string]string{"ALL_PROXY": "ftp://user:secret@proxy.example"}, failure: "ALL_PROXY"}, // #nosec G101 -- Fake credentials prove diagnostics redact secrets.
		{name: "invalid specific no fallback", target: "https://relay.example", env: map[string]string{"HTTPS_PROXY": "http://secret%zz", "ALL_PROXY": "http://proxy.example"}, failure: "HTTPS_PROXY"},
		{name: "invalid port", target: "https://relay.example", env: map[string]string{"ALL_PROXY": "http://user:secret@proxy.example:99999"}, failure: "ALL_PROXY"}, // #nosec G101 -- Fake credentials prove diagnostics redact secrets.
		{name: "missing host", target: "https://relay.example", env: map[string]string{"ALL_PROXY": "http://"}, failure: "ALL_PROXY"},
		{name: "CGI", target: "http://relay.example", env: map[string]string{"HTTP_PROXY": "http://user:secret@proxy.example", "REQUEST_METHOD": "GET"}, failure: "CGI"}, // #nosec G101 -- Fake credentials prove diagnostics redact secrets.
		{name: "CGI fallback", target: "http://relay.example", env: map[string]string{"ALL_PROXY": "http://proxy.example", "REQUEST_METHOD": "GET"}, want: "http://proxy.example"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			choose := environmentProxy(func(key string) string { return tt.env[key] })
			req, err := http.NewRequestWithContext(context.Background(), "GET", tt.target, nil)
			if err != nil {
				t.Fatal(err)
			}
			p, err := choose(req)
			if tt.failure != "" {
				if err == nil || !strings.Contains(err.Error(), tt.failure) || !errors.Is(err, ErrInvalid) {
					t.Fatalf("proxy=%v err=%v", p, err)
				}
				if strings.Contains(err.Error(), "secret") {
					t.Fatal("proxy credentials leaked")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got := ""
			if p != nil {
				got = p.String()
			}
			if got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestEnvironmentProxySnapshot(t *testing.T) {
	env := map[string]string{"ALL_PROXY": "http://first.example"}
	choose := environmentProxy(func(key string) string { return env[key] })
	env["ALL_PROXY"] = "http://second.example"
	env["NO_PROXY"] = "*"
	req, _ := http.NewRequestWithContext(context.Background(), "GET", "https://relay.example", nil)
	p, err := choose(req)
	if err != nil || p == nil || p.Host != "first.example" {
		t.Fatalf("proxy=%v err=%v", p, err)
	}
}

func TestProxyDiagnostics(t *testing.T) {
	for _, status := range []int{403, 407, 502} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			tr := proxyTestTransport(t, &http.Client{Transport: http.DefaultTransport}).Clone()
			configureProxyDiagnostics(tr)
			err := tr.OnProxyConnectResponse(context.Background(), &url.URL{User: url.UserPassword("user", "secret")}, nil, &http.Response{StatusCode: status, Status: "secret untrusted response"})
			if err == nil || !strings.Contains(err.Error(), http.StatusText(status)) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("error=%v", err)
			}
			var p *proxyError
			if !errors.As(err, &p) {
				t.Fatalf("not a proxy error: %v", err)
			}
			if p.permanent != (status == 403 || status == 407) {
				t.Fatalf("permanent=%v for %d", p.permanent, status)
			}
		})
	}
}
