package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/darron/go-opentunnel/internal/authproxy"

	"github.com/darron/go-opentunnel"
)

func TestCACertFlagPrecedence(t *testing.T) {
	for _, tc := range []struct {
		name, env, saved string
		args             []string
		want             string
	}{
		{"saved", "", "/saved/ca.pem", nil, "/saved/ca.pem"},
		{"environment", "/env/ca.pem", "/saved/ca.pem", nil, "/env/ca.pem"},
		{"flag", "/env/ca.pem", "/saved/ca.pem", []string{"--ca-cert", "local.pem"}, "local.pem"},
		{"whitespace is a path", "/env/ca.pem", "/saved/ca.pem", []string{"--ca-cert= "}, " "},
		{"disabled", "/env/ca.pem", "/saved/ca.pem", []string{"--ca-cert="}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OPENTUNNEL_CA_CERT", tc.env)
			var a authFlags
			fs := newFlagSet("test", &bytes.Buffer{})
			a.bind(fs)
			if err := parseAuthFlags(fs, tc.args, &a); err != nil {
				t.Fatal(err)
			}
			got, err := a.effectiveCACert(tc.saved)
			if err != nil {
				t.Fatal(err)
			}
			want := tc.want
			if want != "" {
				want, _ = filepath.Abs(want)
			}
			if got != want {
				t.Fatalf("got %q, want %q", got, want)
			}
		})
	}
}

func TestCACertSavedProfilesLaunchCommand(t *testing.T) {
	t.Setenv("OPENTUNNEL_CA_CERT", "")
	args, paths := authFixture(t)
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CACertFile = filepath.Join(t.TempDir(), "public 'ca.pem")
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if err := runProfiles(context.Background(), args, &out, &errout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "--ca-cert") || !strings.Contains(out.String(), "ca.pem") {
		t.Fatalf("missing CA launch option: %s", out.String())
	}
}

func TestCACertCLIHTTPSAndFailClosed(t *testing.T) {
	t.Setenv("OPENTUNNEL_CA_CERT", "")
	args, _ := authFixture(t)
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.Header.Get("Authorization") != "Bearer do-not-print" {
			t.Error("stored identity missing")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"id","hostname":"test.opentunnel.test","state":"offline"}`))
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	// inspect has no auth-config/token-file flags.
	args = args[:4]
	args = append([]string{"inspect"}, append(args, "--api", server.URL, "--json")...)
	var out, errout bytes.Buffer
	if err := run(t.Context(), args, strings.NewReader(""), &out, &errout); err == nil || hits.Load() != 0 {
		t.Fatalf("untrusted API reached: %v", err)
	}
	for _, mode := range []string{"flag", "environment"} {
		t.Run(mode, func(t *testing.T) {
			selected := append([]string(nil), args...)
			if mode == "flag" {
				selected = append(selected, "--ca-cert", path)
			} else {
				t.Setenv("OPENTUNNEL_CA_CERT", path)
			}
			out.Reset()
			if err := run(t.Context(), selected, strings.NewReader(""), &out, &errout); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "test.opentunnel.test") || strings.Contains(out.String(), "do-not-print") {
				t.Fatalf("unexpected metadata: %s", out.String())
			}
		})
	}
	before := hits.Load()
	for _, invalid := range []string{filepath.Join(t.TempDir(), "missing.pem"), t.TempDir()} {
		selected := append(append([]string(nil), args...), "--ca-cert", invalid)
		if err := run(t.Context(), selected, strings.NewReader(""), &out, &errout); !errors.Is(err, opentunnel.ErrInvalid) || hits.Load() != before {
			t.Fatalf("invalid CA did not fail before request: %v", err)
		}
	}
}

func TestCACertProxyLoadsSavedSetting(t *testing.T) {
	t.Setenv("OPENTUNNEL_CA_CERT", "")
	args, paths := authFixture(t)
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CACertFile = filepath.Join(t.TempDir(), "missing.pem")
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if err := runProxy(t.Context(), args, &out, &errout); !errors.Is(err, opentunnel.ErrInvalid) || !strings.Contains(err.Error(), "ca-cert") {
		t.Fatalf("saved CA not used: %v", err)
	}
}

func TestCACertGitHubFailedSetupPreservesConfigAndTrust(t *testing.T) {
	t.Setenv("OPENTUNNEL_CA_CERT", "")
	var hits atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"id":123,"login":"allowed"}`))
	}))
	defer server.Close()
	original := http.DefaultTransport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, ServerName: server.Certificate().DNSNames[0]},
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if address != "api.github.com:443" {
				return nil, errors.New("unexpected test request")
			}
			return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		},
	}
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = original; transport.CloseIdleConnections() }()
	for _, mode := range []string{"saved", "environment", "disable"} {
		t.Run(mode, func(t *testing.T) {
			args, paths := authFixture(t)
			cfg, err := authproxy.LoadConfig(paths.AuthConfig)
			if err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(t.TempDir(), "saved.pem")
			data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
			cfg.CACertFile = path
			if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadFile(paths.AuthConfig)
			if err != nil {
				t.Fatal(err)
			}
			selected := append([]string{"auth", "github", "--allow-user", "allowed", "--no-browser"}, args...)
			switch mode {
			case "environment":
				override := filepath.Join(t.TempDir(), "override.pem")
				if err := os.WriteFile(override, data, 0600); err != nil {
					t.Fatal(err)
				}
				t.Setenv("OPENTUNNEL_CA_CERT", override)
			case "disable":
				selected = append(selected, "--ca-cert=")
			}
			var out, errout bytes.Buffer
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			err = run(ctx, selected, strings.NewReader(""), &out, &errout)
			if err == nil || err.Error() != "GitHub request failed" {
				t.Fatalf("expected isolated GitHub trust failure: %v", err)
			}
			after, err := os.ReadFile(paths.AuthConfig)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("failed setup changed saved configuration")
			}
			if hits.Load() != 0 || transport.TLSClientConfig.RootCAs != nil {
				t.Fatal("service CA leaked into GitHub trust")
			}
		})
	}
}

func TestCACertPendingResumeHint(t *testing.T) {
	store := opentunnel.NewMemoryStorage()
	if err := store.SavePending(t.Context(), "unit", opentunnel.PendingIdentity{ID: "pending", Hostname: "pending.test", Token: "resume-canary", PrivateKey: "private-canary", CSR: "csr"}); err != nil {
		t.Fatal(err)
	}
	client, err := opentunnel.NewClient(opentunnel.ClientOptions{Storage: store})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	for _, path := range []string{"relative dir/public 'ca.pem", ""} {
		common := commonFlags{profile: "unit", caCertFile: path, caCertExplicit: true}
		var stderr bytes.Buffer
		if err := pendingProvisionError(client, common, context.DeadlineExceeded, &stderr); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
		absolute := path
		if absolute != "" {
			absolute, err = filepath.Abs(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		want := shellCommand([]string{"otgo", "resume", "--profile", "unit", "--ca-cert", absolute})
		if !strings.Contains(stderr.String(), want) || strings.Contains(stderr.String(), "canary") {
			t.Fatalf("resume hint damaged: %s", stderr.String())
		}
	}
}
