package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/identity"
	"github.com/darron/go-opentunnel/internal/authproxy"
	"github.com/golang-jwt/jwt/v5"
)

type identityVerifyFlags struct {
	assertionStdin, requireCurrent bool
	method, target, login, id      string
}

func (v *identityVerifyFlags) bind(fs *flag.FlagSet) {
	fs.BoolVar(&v.assertionStdin, "assertion-stdin", false, "read one X-Otgo-Identity assertion from stdin (required)")
	fs.BoolVar(&v.requireCurrent, "require-current", false, "fail if an otherwise verified assertion has expired")
	fs.StringVar(&v.method, "method", "GET", "backend request method")
	fs.StringVar(&v.target, "request-uri", "", "exact escaped backend path and query, e.g. /api?q=1 (required)")
	fs.StringVar(&v.login, "github-user", "", "also check captured X-GitHub-User (requires --github-id)")
	fs.StringVar(&v.id, "github-id", "", "also check captured X-GitHub-ID (requires --github-user)")
}

func runAuthVerify(ctx context.Context, a authFlags, paths authproxy.Paths, v identityVerifyFlags, in io.Reader, out io.Writer) error {
	if !v.assertionStdin {
		return errors.New("verify requires --assertion-stdin")
	}
	if v.target == "" {
		return errors.New("verify requires --request-uri with the exact backend path and query")
	}
	if v.method == "" {
		return errors.New("method must not be empty")
	}
	if (v.login == "") != (v.id == "") {
		return errors.New("--github-user and --github-id must be supplied together")
	}
	target, err := url.ParseRequestURI(v.target)
	if err != nil || target.IsAbs() || target.Host != "" || !strings.HasPrefix(v.target, "/") || target.RequestURI() != v.target {
		return errors.New("request-uri must be an exact escaped path and query, not an absolute URL or fragment")
	}
	// Bound input before parsing. A trailing newline is convenient for pipes;
	// assertions themselves must fit the backend verifier's 4096-byte limit.
	data, err := io.ReadAll(io.LimitReader(in, 4098))
	if err != nil {
		return errors.New("cannot read identity assertion from stdin")
	}
	encoded := strings.TrimSpace(string(data))
	if len(data) > 4097 || len(encoded) == 0 || len(encoded) > 4096 || strings.ContainsAny(encoded, " \t\r\n") {
		return errors.New("stdin must contain one identity assertion of at most 4096 bytes")
	}
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
	key, err := authproxy.LoadIdentityPublicKey(paths, cfg)
	if err != nil {
		return err
	}
	upstream, err := url.Parse(cfg.Upstream)
	if err != nil {
		return errors.New("invalid configured backend")
	}
	issuer := "https://" + cfg.Binding.Hostname
	audience := upstream.Scheme + "://" + upstream.Host
	r, err := http.NewRequestWithContext(ctx, v.method, audience+v.target, nil)
	if err != nil {
		return errors.New("invalid request method or target")
	}
	r.URL = target
	r.RequestURI = v.target
	// This is an offline assertion check: model the configured backend transport,
	// not a connection observed by the CLI. Backend enforcement uses VerifyRequest.
	if upstream.Scheme == "https" {
		r.TLS = &tls.ConnectionState{}
	}
	r.Header.Set("X-Otgo-Identity", encoded)
	checked := v.login != ""
	if !checked {
		// Unverified claims only supply candidate companion headers. No claim is
		// trusted or printed unless the shared signature and binding checks pass.
		claims := jwt.MapClaims{}
		if _, _, err := jwt.NewParser().ParseUnverified(encoded, claims); err != nil {
			return errors.New("malformed identity assertion")
		}
		v.login, _ = claims["github_login"].(string)
		v.id, _ = claims["sub"].(string)
	}
	r.Header.Set("X-GitHub-User", v.login)
	r.Header.Set("X-GitHub-ID", v.id)
	inspection, err := identity.InspectRequest(r, key, identity.VerifyOptions{Issuer: issuer, Audience: audience})
	if err != nil {
		return errors.New("identity verification failed: check signature, validity window, profile, method, path/query and GitHub headers")
	}
	if v.requireCurrent && !inspection.ValidNow {
		return errors.New("identity assertion has expired (--require-current)")
	}
	user := inspection.Identity
	if a.json {
		return json.NewEncoder(out).Encode(struct {
			Verified             bool
			ValidNow             bool
			Identity             identity.GitHubIdentity
			Issuer, Audience     string
			GitHubHeadersChecked bool
		}{true, inspection.ValidNow, user, issuer, audience, checked})
	}
	status := "currently valid"
	if !inspection.ValidNow {
		status = "EXPIRED; not valid for backend access"
	}
	_, err = fmt.Fprintf(out, "Verified GitHub user: %s (ID %s)\nIssuer: %s\nAudience: %s\nValidity: %s\nIssued at: %s\nExpires at (exclusive): %s\n", user.Login, user.ID, issuer, audience, status, user.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"), user.ExpiresAt.UTC().Format("2006-01-02T15:04:05Z"))
	if err != nil {
		return err
	}
	if checked {
		_, err = io.WriteString(out, "Captured GitHub username/ID headers match.\n")
	} else {
		_, err = io.WriteString(out, "Companion GitHub headers were not supplied; only signed identity was checked.\n")
	}
	if err != nil {
		return err
	}
	_, err = io.WriteString(out, "Offline check; backend connection, body and one-time use are not verified.\n")
	return err
}
