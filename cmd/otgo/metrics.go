package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"github.com/darron/go-opentunnel/internal/authproxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type runtimeFlags struct {
	metricsListen    string
	halfCloseTimeout time.Duration
}

func (f *runtimeFlags) bind(fs *flag.FlagSet) {
	fs.StringVar(&f.metricsListen, "metrics-listen", "", "loopback metrics host:port (empty disables metrics)")
	fs.DurationVar(&f.halfCloseTimeout, "half-close-timeout", 0, "half-close inactivity timeout (0 uses the library default)")
}
func (f runtimeFlags) validate() error {
	if f.halfCloseTimeout < 0 {
		return errors.New("half-close-timeout must not be negative")
	}
	_, err := authproxy.MetricsListenAddress(f.metricsListen)
	return err
}

type metricsServer struct {
	listener        net.Listener
	server          *http.Server
	registry        *prometheus.Registry
	ctx             context.Context
	cancel          context.CancelFunc
	served, watched chan struct{}
	serveErr        error
	closeOnce       sync.Once
}

func loopbackAddress(address string) (string, error) { return authproxy.MetricsListenAddress(address) }
func bindMetrics(ctx context.Context, address string) (*metricsServer, error) {
	if address == "" {
		return nil, nil //nolint:nilnil // A nil listener explicitly represents disabled metrics.
	}
	address, err := loopbackAddress(address)
	if err != nil {
		return nil, err
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("cannot bind metrics listener: %w", err)
	}
	ctx, cancel := context.WithCancel(ctx)
	m := &metricsServer{listener: listener, registry: prometheus.NewRegistry(), ctx: ctx, cancel: cancel, served: make(chan struct{}), watched: make(chan struct{})}
	m.registry.MustRegister(collectors.NewGoCollector())
	scrape := promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{MaxRequestsInFlight: 2, Timeout: 5 * time.Second})
	m.server = &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !m.validAuthority(r.Host) || !m.validOrigin(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		if r.URL.Path != "/metrics" || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", "GET")
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		scrape.ServeHTTP(w, r)
	}), ReadHeaderTimeout: 2 * time.Second, ReadTimeout: 5 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 15 * time.Second, MaxHeaderBytes: 8 << 10}
	go func() {
		defer close(m.served)
		e := m.server.Serve(listener)
		if !errors.Is(e, http.ErrServerClosed) {
			m.serveErr = e
		}
		cancel()
	}()
	go func() { defer close(m.watched); <-ctx.Done(); _ = m.server.Close() }()
	return m, nil
}
func (m *metricsServer) validAuthority(authority string) bool {
	host, port, err := net.SplitHostPort(authority)
	if err != nil {
		return false
	}
	_, actualPort, err := net.SplitHostPort(m.listener.Addr().String())
	if err != nil || port != actualPort {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip, err := netip.ParseAddr(host)
	return err == nil && ip.IsLoopback() && ip.Zone() == ""
}
func (m *metricsServer) validOrigin(r *http.Request) bool {
	values := r.Header.Values("Origin")
	if len(values) == 0 {
		return true
	}
	if len(values) != 1 {
		return false
	}
	u, err := url.Parse(values[0])
	return err == nil && u.Scheme == "http" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" && m.validAuthority(u.Host)
}
func (m *metricsServer) URL() string { return "http://" + m.listener.Addr().String() }
func (m *metricsServer) Close() error {
	if m == nil {
		return nil
	}
	m.closeOnce.Do(func() { m.cancel(); _ = m.server.Close(); <-m.served; <-m.watched })
	return m.serveErr
}
func (m *metricsServer) announce(errout io.Writer) error {
	if m == nil {
		return nil
	}
	_, err := fmt.Fprintln(errout, "metrics:", m.URL()+"/metrics")
	return err
}
