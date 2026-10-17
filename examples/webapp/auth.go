package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"

	"github.com/darron/go-opentunnel/identity"
)

type identityConfig struct {
	PublicKey string
	Issuer    string
	Audience  string
	requested bool
}

func (c identityConfig) enabled() bool {
	return c.requested || c.PublicKey != "" || c.Issuer != "" || c.Audience != ""
}

type verifiedUserKey struct{}

func newHandler(auth identityConfig) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { _, _ = fmt.Fprintln(w, "go-opentunnel embedded example") })
	mux.HandleFunc("/request", requestMetadata)
	mux.HandleFunc("/stream", stream)
	mux.HandleFunc("/ws", echo)
	if !auth.enabled() {
		return mux, nil
	}
	if auth.PublicKey == "" || !validIdentityOrigin(auth.Issuer, true) || !validIdentityOrigin(auth.Audience, false) {
		return nil, errors.New("identity verification requires --identity-public-key, an HTTPS --identity-issuer and an HTTP(S) --identity-audience; origins must have no path, query or fragment")
	}
	// Trust only a key deployed locally, never a key supplied with a request.
	pemBytes, err := os.ReadFile(auth.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("read identity public key: %w", err)
	}
	key, err := identity.ParsePublicKey(pemBytes)
	if err != nil {
		return nil, err
	}
	options := identity.VerifyOptions{Issuer: auth.Issuer, Audience: auth.Audience}
	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) {
		// Middleware supplies this value only after cryptographic verification.
		user, ok := r.Context().Value(verifiedUserKey{}).(identity.GitHubIdentity)
		if !ok {
			http.Error(w, "GitHub sign-in required", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(struct {
			Login string `json:"login"`
			ID    string `json:"id"`
		}{Login: user.Login, ID: user.ID})
	})
	// Wrap the whole mux, before routing/redirects or any request-field rewriting.
	// The original ResponseWriter preserves streaming and WebSocket upgrades.
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		user, err := identity.VerifyRequest(r, key, options)
		if err != nil {
			// Do not echo or log the assertion, which is a short-lived credential.
			http.Error(w, "GitHub sign-in required", http.StatusUnauthorized)
			return
		}
		ctx := context.WithValue(r.Context(), verifiedUserKey{}, user)
		mux.ServeHTTP(w, r.WithContext(ctx))
	}), nil
}

func validIdentityOrigin(raw string, httpsOnly bool) bool {
	u, err := url.Parse(raw)
	return err == nil && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.Path == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		(u.Scheme == "https" || !httpsOnly && u.Scheme == "http")
}
