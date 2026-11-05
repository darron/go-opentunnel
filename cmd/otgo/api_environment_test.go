package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/internal/authproxy"
)

func TestCLIAPIEnvironmentSelection(t *testing.T) {
	for _, tc := range []struct {
		name, environment string
		args              []string
		want              string
	}{
		{"default", "", nil, "https://opentunnel.xyz"},
		{"environment", "https://relay.example.test/control", nil, "https://relay.example.test"},
		{"explicit wins", "invalid", []string{"--api=https://explicit.example.test"}, "https://explicit.example.test"},
		{"empty flag uses environment", "https://relay.example.test", []string{"--api="}, "https://relay.example.test"},
		{"empty flag uses default", "", []string{"--api="}, "https://opentunnel.xyz"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OPENTUNNEL_API", tc.environment)
			var a authFlags
			fs := newFlagSet("test", &bytes.Buffer{})
			a.bind(fs)
			t.Setenv("OPENTUNNEL_API", "invalid-before-parse")
			if err := parseAuthFlags(fs, tc.args, &a); err != nil {
				t.Fatal(err)
			}
			t.Setenv("OPENTUNNEL_API", "invalid-after-parse")
			got, err := a.apiOrigin()
			if err != nil || got != tc.want {
				t.Fatalf("auth API origin = %q, %v; want %q", got, err, tc.want)
			}
			paths, err := authproxy.ResolvePaths("test", t.TempDir(), "", "")
			if err != nil {
				t.Fatal(err)
			}
			client, err := a.clientAt(paths)
			if err != nil {
				t.Fatalf("client reread environment after flag parsing: %v", err)
			}
			_ = client.Close()
		})
	}
}

func TestCLIRejectsInvalidAPIEnvironment(t *testing.T) {
	for _, command := range [][]string{{"ensure"}, {"auth", "init", "--upstream=http://127.0.0.1:8000"}} {
		t.Run(strings.Join(command, " "), func(t *testing.T) {
			t.Setenv("OPENTUNNEL_API", "https://user:secret-canary@relay.example.test")
			var out, errout bytes.Buffer
			args := append([]string{}, command...)
			args = append(args, "--data-dir", t.TempDir())
			err := run(t.Context(), args, strings.NewReader(""), &out, &errout)
			if err == nil || strings.Contains(err.Error()+out.String()+errout.String(), "secret-canary") {
				t.Fatalf("invalid API environment accepted or disclosed: %v", err)
			}
		})
	}
}

func TestCLIAPIEnvironmentRequestAndLaunchCommands(t *testing.T) {
	var hits atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path != "/control/api/tunnel/id" || r.Header.Get("Authorization") != "Bearer fixture-token" {
			t.Errorf("unexpected API request: %s", r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer api.Close()
	t.Setenv("OPENTUNNEL_API", api.URL+"/control")
	var a authFlags
	fs := newFlagSet("test", &bytes.Buffer{})
	a.bind(fs)
	if err := parseAuthFlags(fs, []string{"--data-dir", t.TempDir()}, &a); err != nil {
		t.Fatal(err)
	}
	origin, err := a.apiOrigin()
	if err != nil || origin != api.URL {
		t.Fatalf("environment API not selected: %s %v", origin, err)
	}
	t.Setenv("OPENTUNNEL_API", "invalid-after-parse")
	client, err := a.clientWithTransport(opentunnel.TransportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	var apiError *opentunnel.APIError
	if _, err := client.API().Get(t.Context(), "id", "fixture-token"); !errors.As(err, &apiError) || apiError.StatusCode != http.StatusNotFound || hits.Load() != 1 {
		t.Fatalf("environment request failed: %v hits=%d", err, hits.Load())
	}
	if command := a.launchCommand(); !strings.Contains(command, "--api "+api.URL+"/control") {
		t.Fatalf("launch command lost API base path: %s", command)
	}
	if err := opentunnel.NewFileStorage(a.dataDir).SavePending(t.Context(), a.profile, opentunnel.PendingIdentity{ID: "pending", Hostname: "pending.test", Token: "token", PrivateKey: "key", CSR: "csr"}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	_ = pendingProvisionError(client, a.commonFlags, context.DeadlineExceeded, &stderr)
	if !strings.Contains(stderr.String(), "--api "+api.URL+"/control") {
		t.Fatalf("resume command lost API base path: %s", stderr.String())
	}
}

func TestCLIDefaultAPIInCopiedCommands(t *testing.T) {
	t.Setenv("OPENTUNNEL_API", "")
	var a authFlags
	fs := newFlagSet("test", &bytes.Buffer{})
	a.bind(fs)
	if err := parseAuthFlags(fs, []string{"--data-dir", t.TempDir()}, &a); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OPENTUNNEL_API", "https://different-server.example.test")
	if command := a.launchCommand(); !strings.Contains(command, "--api https://opentunnel.xyz") {
		t.Errorf("copied launch command can select a different API: %s", command)
	}
	client, err := a.clientWithTransport(opentunnel.TransportOptions{})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	if err := opentunnel.NewFileStorage(a.dataDir).SavePending(t.Context(), a.profile, opentunnel.PendingIdentity{ID: "pending", Hostname: "pending.test", Token: "token", PrivateKey: "key", CSR: "csr"}); err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	_ = pendingProvisionError(client, a.commonFlags, context.DeadlineExceeded, &stderr)
	if !strings.Contains(stderr.String(), "--api https://opentunnel.xyz") {
		t.Errorf("copied resume command can select a different API: %s", stderr.String())
	}
}

func TestCLIAPIEnvironmentProtectedProfileBinding(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	flags, paths := authFixture(t)
	previous := http.DefaultTransport
	base, ok := previous.(*http.Transport)
	if !ok {
		t.Fatal("test requires the standard HTTP transport")
	}
	trap := base.Clone()
	var attempts atomic.Int32
	trap.DialContext = func(context.Context, string, string) (net.Conn, error) {
		attempts.Add(1)
		return nil, opentunnel.ErrInvalid
	}
	http.DefaultTransport = trap
	defer func() { http.DefaultTransport = previous; trap.CloseIdleConnections() }()
	var hits atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer api.Close()
	t.Setenv("OPENTUNNEL_API", api.URL+"/control")
	var out, errout bytes.Buffer
	err := run(t.Context(), append([]string{"proxy"}, flags...), strings.NewReader(""), &out, &errout)
	if err == nil || !strings.Contains(err.Error(), "does not match") || hits.Load() != 0 || attempts.Load() != 0 {
		t.Fatalf("mismatched origin reached API: err=%v hits=%d attempts=%d", err, hits.Load(), attempts.Load())
	}
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Binding.APIOrigin = api.URL
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runProfiles(t.Context(), append(flags, "--json"), &out, &errout); err != nil {
		t.Fatal(err)
	}
	var rows []profileSummary
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Status != "ready" || !strings.Contains(rows[0].Command, "--api "+api.URL+"/control") || hits.Load() != 0 {
		t.Fatalf("environment binding/launch inventory incorrect: %s, hits=%d", out.String(), hits.Load())
	}
}
