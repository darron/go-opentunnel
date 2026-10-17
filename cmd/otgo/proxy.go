package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"io"
	"net/http"
	"time"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/internal/authproxy"
	"github.com/darron/go-opentunnel/metrics"
)

// boundStorage turns disappearance during Listen/refresh into a hard failure.
// Client.Listen normally provisions missing profiles; this proxy must never do so.
type boundStorage struct {
	opentunnel.Storage
	binding authproxy.Binding
}

func (s *boundStorage) check(id *opentunnel.Identity) error {
	if id == nil {
		return errors.New("profile has no stored tunnel; run explicit auth setup")
	}
	if id.ID != s.binding.TunnelID || id.Hostname != s.binding.Hostname {
		return errors.New("stored tunnel does not match auth binding")
	}
	return nil
}
func (s *boundStorage) Load(ctx context.Context, p string) (*opentunnel.Identity, error) {
	id, e := s.Storage.Load(ctx, p)
	if e != nil {
		return nil, e
	}
	if e = s.check(id); e != nil {
		return nil, e
	}
	return id, nil
}
func (s *boundStorage) Save(ctx context.Context, p string, id opentunnel.Identity) error {
	if e := s.check(&id); e != nil {
		return e
	}
	if _, e := s.Load(ctx, p); e != nil {
		return e
	}
	return s.Storage.Save(ctx, p, id)
}
func (s *boundStorage) SavePending(ctx context.Context, p string, id opentunnel.PendingIdentity) error {
	if id.ID != s.binding.TunnelID || id.Hostname != s.binding.Hostname {
		return errors.New("pending identity does not match auth binding")
	}
	if _, e := s.Load(ctx, p); e != nil {
		return e
	}
	return s.Storage.SavePending(ctx, p, id)
}

func runProxy(ctx context.Context, args []string, out, errout io.Writer) (result error) {
	fs := newFlagSet("proxy", errout)
	var a authFlags
	a.bind(fs)
	var runtime runtimeFlags
	runtime.bind(fs)
	var qrMode string
	fs.StringVar(&qrMode, "qr", "auto", "terminal URL QR code: auto, always or never (suppressed with --json)")
	var timeout time.Duration
	fs.DurationVar(&timeout, "timeout", 0, "overall proxy lifetime (0 runs until cancelled)")
	if e := parseAuthFlags(fs, args, &a); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if qrMode != "auto" && qrMode != "always" && qrMode != "never" {
		return errors.New("qr must be auto, always or never")
	}
	if timeout < 0 {
		return errors.New("timeout must not be negative")
	}
	if e := runtime.validate(); e != nil {
		return e
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
	}
	paths, e := a.paths()
	if e != nil {
		return e
	}
	cfg, e := authproxy.LoadConfig(paths.AuthConfig)
	if e != nil {
		return e
	}
	metricsExplicit := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "metrics-listen" {
			metricsExplicit = true
		}
	})
	if !metricsExplicit {
		runtime.metricsListen = cfg.MetricsListen
	}
	admin, e := bindMetrics(ctx, runtime.metricsListen)
	if e != nil {
		return e
	}
	defer func() {
		if e := admin.Close(); e != nil {
			result = e
		}
	}()
	if admin != nil {
		ctx = admin.ctx
	}
	storage := &boundStorage{Storage: opentunnel.NewFileStorage(paths.TunnelRoot), binding: cfg.Binding}
	id, e := storage.Load(ctx, a.profile)
	if e != nil {
		return e
	}
	b, e := a.binding(*id)
	if e != nil {
		return e
	}
	if e = authproxy.ValidateBinding(cfg, b); e != nil {
		return e
	}
	return authproxy.WithProfileLock(a.profileLock(paths), func() error {
		// Recheck after acquiring the lock, before any network operation.
		current, e := authproxy.LoadConfig(paths.AuthConfig)
		if e != nil {
			return e
		}
		if e = authproxy.ValidateBinding(current, b); e != nil {
			return e
		}
		cfg = current
		var identityKey ed25519.PrivateKey
		if cfg.Mode == "github" {
			identityKey, e = authproxy.EnsureIdentityKey(paths, cfg)
			if e != nil {
				return e
			}
		}
		caCertFile, e := a.effectiveCACert(cfg.CACertFile)
		if e != nil {
			return e
		}
		client, e := opentunnel.NewClient(opentunnel.ClientOptions{API: a.api, Storage: storage, RequestTimeout: a.requestTimeout, Transport: opentunnel.TransportOptions{HalfCloseTimeout: runtime.halfCloseTimeout}, CACertFile: caCertFile})
		if e != nil {
			return e
		}
		defer func() { _ = client.Close() }()
		h, e := authproxy.NewHandler(authproxy.Options{Config: cfg, TokenStore: authproxy.NewTokenStore(paths.TokenFile, cfg), IdentityKey: identityKey})
		if e != nil {
			return e
		}
		defer func() { _ = h.Close() }()
		if admin != nil {
			admin.registry.MustRegister(metrics.NewCollector(client), h.Collector())
			if e := admin.announce(errout); e != nil {
				return e
			}
		}
		listener, e := client.Listen(ctx, opentunnel.ListenOptions{Profile: a.profile, Routes: []string{"@"}, Lifetime: ctx})
		if e != nil {
			return e
		}
		defer func() { _ = listener.Close() }()
		actual, e := a.binding(listener.Identity())
		if e != nil {
			return e
		}
		if e = authproxy.ValidateBinding(cfg, actual); e != nil {
			return e
		}
		server := newProxyServer(h)
		served := make(chan error, 1)
		go func() { served <- server.Serve(listener); close(served) }()
		defer func() { _ = listener.Close(); _ = server.Close(); _ = h.Close(); <-served }()
		write := &lockedWriter{w: out}
		e = writeProxyAnnouncement(write, a.json, a.profile, cfg, qrMode, qrTerminal(out))
		if e != nil {
			return e
		}
		for {
			select {
			case e := <-served:
				if errors.Is(e, http.ErrServerClosed) {
					return nil
				}
				return e
			case <-ctx.Done():
				return ctx.Err()
			case <-listener.Done():
				return listener.Err()
			case event, ok := <-listener.Events():
				if !ok {
					return listener.Err()
				}
				if e := printEvent(write, a.json, event); e != nil {
					return e
				}
			}
		}
	})
}

func newProxyServer(h http.Handler) *http.Server {
	return &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 32 << 10, ConnContext: authproxy.WithClientConnection}
}
