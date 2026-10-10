package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/internal/authproxy"
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

func runProxy(ctx context.Context, args []string, out, errout io.Writer) error {
	fs := newFlagSet("proxy", errout)
	var a authFlags
	a.bind(fs)
	var timeout time.Duration
	fs.DurationVar(&timeout, "timeout", 0, "overall proxy lifetime (0 runs until cancelled)")
	if e := parseAuthFlags(fs, args, &a); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return nil
		}
		return e
	}
	if timeout < 0 {
		return errors.New("timeout must not be negative")
	}
	paths, e := a.paths()
	if e != nil {
		return e
	}
	cfg, e := authproxy.LoadConfig(paths.AuthConfig)
	if e != nil {
		return e
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
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, timeout)
		defer cancel()
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
		client, e := opentunnel.NewClient(opentunnel.ClientOptions{API: a.api, Storage: storage, RequestTimeout: a.requestTimeout})
		if e != nil {
			return e
		}
		defer func() { _ = client.Close() }()
		h, e := authproxy.NewHandler(authproxy.Options{Config: cfg, TokenStore: authproxy.NewTokenStore(paths.TokenFile)})
		if e != nil {
			return e
		}
		defer func() { _ = h.Close() }()
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
		server := &http.Server{Handler: h, ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 32 << 10, ConnContext: authproxy.WithClientConnection}
		served := make(chan error, 1)
		go func() { served <- server.Serve(listener); close(served) }()
		defer func() { _ = listener.Close(); _ = server.Close(); _ = h.Close(); <-served }()
		write := &lockedWriter{w: out}
		if a.json {
			e = json.NewEncoder(write).Encode(struct{ Type, Profile, Hostname, Upstream, Mode string }{"proxy", a.profile, cfg.Binding.Hostname, cfg.Upstream, cfg.Mode})
		} else {
			_, e = fmt.Fprintf(write, "protected https://%s -> %s (profile=%s, auth=%s)\n", terminalText(cfg.Binding.Hostname), terminalText(cfg.Upstream), a.profile, cfg.Mode)
		}
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
