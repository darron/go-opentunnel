package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/darron/go-opentunnel"
)

func listen(ctx context.Context, client *opentunnel.Client, profile string, names []string, policy opentunnel.RouteConflictPolicy, asJSON bool, out io.Writer) error {
	listener, err := client.Listen(ctx, opentunnel.ListenOptions{Profile: profile, Routes: names, Lifetime: ctx, OnRouteConflict: policy})
	if err != nil {
		return err
	}
	defer func() { _ = listener.Close() }()
	server := &http.Server{Handler: http.HandlerFunc(listenerDiagnostic), ReadHeaderTimeout: 5 * time.Second}
	served := make(chan error, 1)
	go func() { served <- server.Serve(listener); close(served) }()
	// Close the listener before joining Serve. Server.Close also handles ordinary
	// HTTP connections; listener.Close covers hijacked application sockets.
	defer func() {
		_ = listener.Close()
		_ = server.Close()
		<-served //nolint:errcheck // Shutdown join; the normal path handles Serve's result.
	}()
	if asJSON {
		err = json.NewEncoder(out).Encode(struct {
			Type     string              `json:"type"`
			Identity opentunnel.Identity `json:"identity"`
			Routes   []string            `json:"routes"`
		}{Type: "listening", Identity: listener.Identity(), Routes: names})
	} else {
		_, err = fmt.Fprintf(out, "listening https://%s\n", terminalText(listener.Identity().Hostname))
	}
	if err != nil {
		return err
	}
	for {
		select {
		case err := <-served:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-listener.Done():
			return listener.Err()
		case event, ok := <-listener.Events():
			if !ok {
				return listener.Err()
			}
			if err := printEvent(out, asJSON, event); err != nil {
				return err
			}
		}
	}
}

func listenerDiagnostic(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	state := struct {
		TLS    bool   `json:"tls"`
		SNI    string `json:"sni"`
		Peer   string `json:"peer"`
		Origin string `json:"origin"`
	}{Peer: r.RemoteAddr}
	if r.TLS != nil {
		state.TLS = r.TLS.HandshakeComplete
		state.SNI = r.TLS.ServerName
		state.Origin = "https://" + r.TLS.ServerName
	}
	_ = json.NewEncoder(w).Encode(state)
}

// nameFlags collects SNI names; Client.Listen validates their grammar and uniqueness.
type nameFlags []string

func (n *nameFlags) String() string         { return strings.Join(*n, ",") }
func (n *nameFlags) Set(value string) error { *n = append(*n, value); return nil }
