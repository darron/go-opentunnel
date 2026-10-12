package main

import (
	"bytes"
	"context"
	"github.com/darron/go-opentunnel/internal/authproxy"
	"github.com/prometheus/client_golang/prometheus"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMetricsBindRejectsUnsafeAddresses(t *testing.T) {
	for _, address := range []string{"0.0.0.0:0", ":0", "[::]:0", "192.0.2.1:0", "example.test:0", "127.0.0.1", "localhost:bad", "localhost:-1"} {
		if m, err := bindMetrics(t.Context(), address); err == nil {
			_ = m.Close()
			t.Fatalf("accepted %q", address)
		}
	}
}
func TestMetricsPrivateHTTPAndJoinedCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	m, err := bindMetrics(ctx, "localhost:0")
	if err != nil {
		t.Fatal(err)
	}
	second, err := bindMetrics(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = second.Close() }()
	if m.URL() == second.URL() {
		t.Fatal("shared listener")
	}
	if m.server.ReadTimeout <= 0 || m.server.ReadHeaderTimeout <= 0 || m.server.WriteTimeout <= 0 || m.server.IdleTimeout <= 0 || m.server.MaxHeaderBytes <= 0 {
		t.Fatal("unbounded metrics server")
	}
	client := &http.Client{Timeout: 3 * time.Second}
	for _, tc := range []struct {
		method, path, host, origin string
		code                       int
	}{
		{"GET", "/metrics", "", "", 200}, {"HEAD", "/metrics", "", "", 405}, {"POST", "/metrics", "", "", 405}, {"GET", "/", "", "", 404}, {"GET", "/metrics", "attacker.test", "", 403}, {"GET", "/metrics", "localhost:1", "", 403}, {"GET", "/metrics", "", "https://attacker.test", 403}, {"GET", "/metrics", "", m.URL(), 200},
	} {
		req, e := http.NewRequestWithContext(t.Context(), tc.method, m.URL()+tc.path, nil)
		if e != nil {
			t.Fatal(e)
		}
		if tc.host != "" {
			req.Host = tc.host
		}
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		res, e := client.Do(req)
		if e != nil {
			t.Fatal(e)
		}
		b, e := io.ReadAll(res.Body)
		_ = res.Body.Close()
		if e != nil {
			t.Fatal(e)
		}
		if res.StatusCode != tc.code {
			t.Fatalf("%+v: %d", tc, res.StatusCode)
		}
		if tc.code == 200 && (!strings.Contains(string(b), "go_goroutines") || strings.Contains(string(b), "process_")) {
			t.Fatal("wrong private runtime collectors")
		}
	}
	address := m.listener.Addr().String()
	cancel()
	if err = m.Close(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		next, e := bindMetrics(t.Context(), address)
		if e != nil {
			t.Fatal("listener not reusable", e)
		}
		if e = next.Close(); e != nil {
			t.Fatal(e)
		}
	}
	occupied, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = occupied.Close() }()
	if next, e := bindMetrics(t.Context(), occupied.Addr().String()); e == nil {
		_ = next.Close()
		t.Fatal("occupied address accepted")
	}
}

func TestMetricsUnexpectedServeErrorCancelsCommand(t *testing.T) {
	m, e := bindMetrics(t.Context(), "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	if e = m.listener.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case <-m.ctx.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("serve failure did not cancel command")
	}
	if e = m.Close(); e == nil {
		t.Fatal("unexpected Serve error suppressed")
	}
}
func TestRuntimeFlagsFailBeforeStorageAndRemote(t *testing.T) {
	for _, command := range []string{"connect", "listen", "proxy"} {
		for _, flag := range [][]string{{"--half-close-timeout", "-1s"}, {"--metrics-listen", "example.test:0"}, {"--metrics-listen", "0.0.0.0:0"}} {
			root := filepath.Join(t.TempDir(), "must-not-exist")
			var out, errout bytes.Buffer
			args := append([]string{command, "--data-dir", root, "--api", "http://127.0.0.1:1"}, flag...)
			if e := run(t.Context(), args, strings.NewReader(""), &out, &errout); e == nil {
				t.Fatal("invalid runtime flag accepted")
			}
			if _, e := os.Stat(root); !os.IsNotExist(e) {
				t.Fatalf("state touched before validation: %v", e)
			}
			if out.Len() != 0 {
				t.Fatal("validation damaged stdout")
			}
		}
	}
	for _, command := range []string{"create", "auth", "get", "profiles"} {
		var out, errout bytes.Buffer
		args := []string{command, "--metrics-listen", "127.0.0.1:0"}
		if command == "auth" {
			args = []string{"auth", "init", "--metrics-listen", "127.0.0.1:0"}
		}
		if e := run(t.Context(), args, strings.NewReader(""), &out, &errout); e == nil || !strings.Contains(e.Error(), "flag provided but not defined") {
			t.Fatalf("runtime flag leaked to %s: %v", command, e)
		}
	}
}
func TestMetricsCLIErrorClosesListenerAndPreservesJSON(t *testing.T) {
	held, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	address := held.Addr().String()
	_ = held.Close()
	var out, errout bytes.Buffer
	e = run(t.Context(), []string{"listen", "--json", "--metrics-listen", address, "--data-dir", filepath.Join(t.TempDir(), "state"), "--api", "http://127.0.0.1:1"}, strings.NewReader(""), &out, &errout)
	if e == nil {
		t.Fatal("remote failure expected")
	}
	if out.Len() != 0 {
		t.Fatalf("non-JSON metrics output on stdout: %s", out.String())
	}
	if !strings.Contains(errout.String(), "metrics: http://"+address+"/metrics") {
		t.Fatal(errout.String())
	}
	next, e := bindMetrics(t.Context(), address)
	if e != nil {
		t.Fatal("CLI failure leaked metrics port", e)
	}
	_ = next.Close()
}

func TestProxySavedMetricsOverrideAndPrivateScrape(t *testing.T) {
	for _, mode := range []string{"saved", "override", "disabled", "occupied", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			flags, paths := authFixture(t)
			held, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if e != nil {
				t.Fatal(e)
			}
			saved := held.Addr().String()
			if mode != "occupied" {
				_ = held.Close()
			} else {
				defer func() { _ = held.Close() }()
			}
			entered := make(chan struct{}, 1)
			api := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) { entered <- struct{}{}; <-r.Context().Done() }))
			defer api.Close()
			cfg, e := authproxy.LoadConfig(paths.AuthConfig)
			if e != nil {
				t.Fatal(e)
			}
			cfg.Binding.APIOrigin = api.URL
			cfg.MetricsListen = saved
			if e = authproxy.SaveConfig(paths.AuthConfig, cfg); e != nil {
				t.Fatal(e)
			}
			if mode == "invalid" {
				raw, e := os.ReadFile(paths.AuthConfig)
				if e != nil {
					t.Fatal(e)
				}
				// #nosec G703 -- auth path is an isolated test fixture.
				if e = os.WriteFile(paths.AuthConfig, []byte(strings.ReplaceAll(string(raw), saved, "0.0.0.0:0")), 0600); e != nil {
					t.Fatal(e)
				}
			}
			before, e := os.ReadFile(paths.AuthConfig)
			if e != nil {
				t.Fatal(e)
			}
			address := saved
			args := append([]string{"proxy", "--json", "--api", api.URL}, flags...)
			if mode == "override" {
				other, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
				if e != nil {
					t.Fatal(e)
				}
				address = other.Addr().String()
				_ = other.Close()
				args = append(args, "--metrics-listen", address)
			}
			if mode == "disabled" {
				args = append(args, "--metrics-listen=")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var out, errout bytes.Buffer
			done := make(chan error, 1)
			go func() { done <- run(ctx, args, strings.NewReader(""), &out, &errout) }()
			if mode == "occupied" || mode == "invalid" {
				select {
				case e := <-done:
					if e == nil || !strings.Contains(e.Error(), "metrics-listen") && !strings.Contains(e.Error(), "cannot bind metrics") {
						t.Fatal(e)
					}
				case <-time.After(3 * time.Second):
					t.Fatal("occupied config did not fail promptly")
				}
				select {
				case <-entered:
					t.Fatal("occupied address reached remote")
				default:
				}
			} else {
				select {
				case <-entered:
				case e := <-done:
					t.Fatal("failed before fixture", e)
				case <-time.After(3 * time.Second):
					t.Fatal("no remote fixture request")
				}
				if mode != "disabled" {
					req, e := http.NewRequestWithContext(t.Context(), "GET", "http://"+address+"/metrics", nil)
					if e != nil {
						t.Fatal(e)
					}
					res, e := (&http.Client{Timeout: 3 * time.Second}).Do(req)
					if e != nil {
						t.Fatal(e)
					}
					b, e := io.ReadAll(res.Body)
					_ = res.Body.Close()
					if e != nil {
						t.Fatal(e)
					}
					for _, family := range []string{"go_goroutines", "opentunnel_client_api_requests_total", "opentunnel_proxy_requests_total", "opentunnel_proxy_logins_total"} {
						if !strings.Contains(string(b), family) {
							t.Fatal("missing private family", family)
						}
					}
				} else {
					next, e := (&net.ListenConfig{}).Listen(t.Context(), "tcp", saved)
					if e != nil {
						t.Fatal("explicit empty did not disable", e)
					}
					_ = next.Close()
				}
				cancel()
				select {
				case <-done:
				case <-time.After(3 * time.Second):
					t.Fatal("CLI cancellation did not join")
				}
			}
			after, e := os.ReadFile(paths.AuthConfig)
			if e != nil || string(before) != string(after) {
				t.Fatal("run override rewrote saved config")
			}
			if out.Len() != 0 {
				t.Fatal("metrics damaged JSON output", out.String())
			}
			if mode == "disabled" && strings.Contains(errout.String(), "metrics:") {
				t.Fatal("disabled address announced")
			}
		})
	}
}

type blockingMetricsCollector struct{ entered, release chan struct{} }

func (c blockingMetricsCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- prometheus.NewDesc("fixture_blocking", "Fixture scrape gate.", nil, nil)
}
func (c blockingMetricsCollector) Collect(ch chan<- prometheus.Metric) {
	c.entered <- struct{}{}
	<-c.release
	ch <- prometheus.MustNewConstMetric(prometheus.NewDesc("fixture_blocking", "Fixture scrape gate.", nil, nil), prometheus.GaugeValue, 1)
}
func TestMetricsScrapeConcurrencyBound(t *testing.T) {
	m, e := bindMetrics(t.Context(), "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer func() { _ = m.Close() }()
	gate := blockingMetricsCollector{entered: make(chan struct{}, 2), release: make(chan struct{})}
	m.registry.MustRegister(gate)
	client := &http.Client{Timeout: 3 * time.Second}
	done := make(chan error, 2)
	for range 2 {
		go func() {
			req, e := http.NewRequestWithContext(t.Context(), "GET", m.URL()+"/metrics", nil)
			if e == nil {
				var res *http.Response
				res, e = client.Do(req)
				if res != nil {
					_, _ = io.Copy(io.Discard, res.Body)
					_ = res.Body.Close()
				}
			}
			done <- e
		}()
	}
	defer close(gate.release)
	for range 2 {
		select {
		case <-gate.entered:
		case <-time.After(2 * time.Second):
			t.Fatal("scrape not admitted")
		}
	}
	req, e := http.NewRequestWithContext(t.Context(), "GET", m.URL()+"/metrics", nil)
	if e != nil {
		t.Fatal(e)
	}
	res, e := client.Do(req)
	if e != nil {
		t.Fatal(e)
	}
	_, _ = io.Copy(io.Discard, res.Body)
	_ = res.Body.Close()
	if res.StatusCode != 503 {
		t.Fatalf("unbounded concurrent scrapes: %d", res.StatusCode)
	}
	// Unblock and join the fixture requests before returning.
	gate.release <- struct{}{}
	gate.release <- struct{}{}
	for range 2 {
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	}
}
