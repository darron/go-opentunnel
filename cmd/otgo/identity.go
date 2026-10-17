package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/internal/authproxy"
)

func runAuthPublicKey(ctx context.Context, a authFlags, paths authproxy.Paths, out io.Writer) error {
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		return err
	}
	stored, err := opentunnel.NewFileStorage(paths.TunnelRoot).Load(ctx, a.profile)
	if err != nil {
		return err
	}
	if stored == nil {
		return errors.New("profile has no stored tunnel; run auth setup")
	}
	binding, err := a.binding(*stored)
	if err != nil {
		return err
	}
	if err := authproxy.ValidateBinding(cfg, binding); err != nil {
		return err
	}
	key, err := authproxy.EnsureIdentityKey(paths, cfg)
	if err != nil {
		return err
	}
	public, err := authproxy.IdentityPublicKeyPEM(key)
	if err != nil {
		return err
	}
	if !a.json {
		_, err = out.Write(public)
		return err
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return err
	}
	return json.NewEncoder(out).Encode(struct{ PublicKey, KeyID, Issuer, Audience string }{string(public), authproxy.IdentityKeyID(key), "https://" + cfg.Binding.Hostname, upstream.Scheme + "://" + upstream.Host})
}
