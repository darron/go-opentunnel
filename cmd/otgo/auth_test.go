package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/internal/authproxy"
)

func authFixture(t *testing.T) ([]string, authproxy.Paths) {
	t.Helper()
	root := t.TempDir()
	paths, err := authproxy.ResolvePaths("inbox", filepath.Join(root, "tunnels"), filepath.Join(root, "config", "auth.json"), filepath.Join(root, "data", "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	v, err := authproxy.NewPasswordVerifier([]byte("fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := authproxy.Config{Binding: authproxy.Binding{TunnelID: "id", Hostname: "test.opentunnel.test", APIOrigin: opentunnel.DefaultAPI}, Upstream: "http://127.0.0.1:57732", Mode: "password", Password: v}
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	id := opentunnel.Identity{ID: "id", Hostname: cfg.Binding.Hostname, Token: "do-not-print", PrivateKey: "do-not-print-key", Certificate: "cert", Chain: "chain", CertificateExpiry: time.Now().Add(time.Hour)}
	if err := opentunnel.NewFileStorage(paths.TunnelRoot).Save(t.Context(), "inbox", id); err != nil {
		t.Fatal(err)
	}
	return []string{"--profile", "inbox", "--data-dir", paths.TunnelRoot, "--auth-config", paths.AuthConfig, "--token-file", paths.TokenFile}, paths
}
func TestAuthPathsAndMissingProxy(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	var out, errout bytes.Buffer
	if err := run(t.Context(), []string{"auth", "paths", "--profile", "inbox", "--json"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), filepath.Join(home, ".config", "otgo", "inbox", "auth.json")) {
		t.Fatal("XDG paths")
	}
	if _, err := os.Stat(filepath.Join(home, ".config")); !os.IsNotExist(err) {
		t.Fatal("paths created files")
	}
	if err := run(t.Context(), []string{"proxy", "--profile", "missing"}, strings.NewReader(""), &out, &errout); err == nil {
		t.Fatal("missing setup accepted")
	}
}

func TestAuthHelpListsTokenReset(t *testing.T) {
	var out bytes.Buffer
	if err := run(t.Context(), []string{"auth", "--help"}, strings.NewReader(""), &out, io.Discard); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "token reset") {
		t.Fatal("auth help omitted token reset")
	}
}

func TestAuthTokenCommandsAndReset(t *testing.T) {
	flags, paths := authFixture(t)
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	args := append([]string{"auth", "token", "create", "--json"}, flags...)
	if err := run(t.Context(), args, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	var result struct{ Token, ID string }
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(result.Token, "otgo_") || result.ID == "" {
		t.Fatal("missing one-time credential")
	}
	out.Reset()
	if err := run(t.Context(), append([]string{"auth", "token", "list", "--json"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), result.Token) || strings.Contains(out.String(), "hash") {
		t.Fatal("list leaked credential")
	}
	out.Reset()
	if err := run(t.Context(), append([]string{"auth", "token", "revoke", "--id", result.ID}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if _, err := authproxy.NewTokenStore(paths.TokenFile, cfg).Authenticate(result.Token); err == nil {
		t.Fatal("CLI revocation failed")
	}
	out.Reset()
	if err := run(t.Context(), append([]string{"auth", "token", "create", "--json"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	var replacement struct{ Token string }
	if err := json.Unmarshal(out.Bytes(), &replacement); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(t.Context(), append([]string{"auth", "token", "reset"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.TokenFile); !os.IsNotExist(err) {
		t.Fatal("token registry survived token reset")
	}
	if _, err := authproxy.LoadConfig(paths.AuthConfig); err != nil {
		t.Fatal("token reset removed auth config")
	}
	if _, err := authproxy.NewTokenStore(paths.TokenFile, cfg).Authenticate(replacement.Token); err == nil {
		t.Fatal("token reset left machine token usable")
	}
	unknown := filepath.Join(filepath.Dir(paths.AuthConfig), "unrelated.txt")
	if err := os.WriteFile(unknown, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := run(t.Context(), append([]string{"auth", "reset"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(paths.AuthConfig); !os.IsNotExist(err) {
		t.Fatal("config survived reset")
	}
	if _, err := os.Stat(unknown); err != nil {
		t.Fatal("reset removed unrelated file")
	}
	if id, err := opentunnel.NewFileStorage(paths.TunnelRoot).Load(t.Context(), "inbox"); err != nil || id == nil {
		t.Fatal("reset removed tunnel")
	}
}
func TestAuthInitRejectsBeforeProvisioning(t *testing.T) {
	flags, _ := authFixture(t)
	for _, args := range [][]string{
		{"auth", "init", "--upstream", "http://remote.test"},
		{"auth", "init", "--upstream", "http://127.0.0.1:8000"},
		{"auth", "token", "create", "--ttl", "25h"},
		{"proxy", "--timeout", "-1s"},
		{"auth", "init", "--upstream", "http://127.0.0.1:8000", "--password-stdin", "--generate-password"},
	} {
		var out, errout bytes.Buffer
		if err := run(t.Context(), append(args, flags...), strings.NewReader("secret"), &out, &errout); err == nil {
			t.Fatalf("accepted %v", args)
		}
		if strings.Contains(out.String(), "secret") || strings.Contains(errout.String(), "secret") {
			t.Fatal("password leaked")
		}
	}
}
func TestProxyBindingAndMissingIdentityRefuseWithoutNetwork(t *testing.T) {
	flags, paths := authFixture(t)
	store := opentunnel.NewFileStorage(paths.TunnelRoot)
	if err := store.Remove(context.Background(), "inbox"); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	err := run(t.Context(), append([]string{"proxy"}, flags...), strings.NewReader(""), &out, &errout)
	if err == nil || !strings.Contains(err.Error(), "stored tunnel") {
		t.Fatalf("missing identity: %v", err)
	}
	if pending, err := store.LoadPending(t.Context(), "inbox"); err != nil || pending != nil {
		t.Fatal("proxy silently provisioned identity")
	}
}

func TestAuthRejectsNegativeDuration(t *testing.T) {
	var out, errout bytes.Buffer
	if err := run(t.Context(), []string{"auth", "paths", "--request-timeout=-1s"}, strings.NewReader(""), &out, &errout); err == nil {
		t.Fatal("negative timeout accepted")
	}
}
func TestAuthPasswordInputSingleLineAndCancellation(t *testing.T) {
	if password, err := readPasswordInput(t.Context(), strings.NewReader("has spaces \nignored")); err != nil || password != "has spaces " {
		t.Fatal("password line changed")
	}
	reader, writer := io.Pipe()
	defer func() { _ = writer.Close() }()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := readPasswordInput(ctx, reader); !errors.Is(err, context.Canceled) {
		t.Fatalf("password input cancellation: %v", err)
	}
}
func TestProxyProfileLockAndIndependentProfiles(t *testing.T) {
	flags, paths := authFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	done := make(chan error, 1)
	lock := filepath.Join(paths.TunnelRoot, "inbox", "otgo-proxy")
	go func() {
		done <- authproxy.WithProfileLock(lock, func() error { close(entered); <-release; return nil })
	}()
	<-entered
	var out, errout bytes.Buffer
	if err := run(t.Context(), append([]string{"proxy"}, flags...), strings.NewReader(""), &out, &errout); err == nil || !strings.Contains(err.Error(), "might already be running") || !strings.Contains(err.Error(), lock+".lock") {
		t.Fatalf("duplicate proxy: %v", err)
	}
	if err := authproxy.WithProfileLock(filepath.Join(paths.TunnelRoot, "dashboard", "otgo-proxy"), func() error { return nil }); err != nil {
		t.Fatal("another profile blocked")
	}
	// Token issuance remains available while its proxy holds the profile lock.
	if err := run(t.Context(), append([]string{"auth", "token", "create"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal("running proxy blocked token issuance")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestAuthGitHubManualValidation(t *testing.T) {
	flags, _ := authFixture(t)
	for _, args := range [][]string{{"auth", "github", "--client-id", "id", "--client-secret-stdin"}, {"auth", "github", "--allow-user", "../bad", "--client-id", "id", "--client-secret-stdin"}} {
		var out, errout bytes.Buffer
		if err := run(t.Context(), append(args, flags...), strings.NewReader("never-print-secret"), &out, &errout); err == nil {
			t.Fatal("invalid GitHub setup accepted")
		}
		if strings.Contains(out.String(), "never-print-secret") || strings.Contains(errout.String(), "never-print-secret") {
			t.Fatal("GitHub secret leaked")
		}
	}
}

func TestEmptyAuthProfileUsesDefaultProfileLock(t *testing.T) {
	root := t.TempDir()
	paths, err := authproxy.ResolvePaths("default", filepath.Join(root, "tunnels"), filepath.Join(root, "auth", "auth.json"), filepath.Join(root, "tokens", "tokens.json"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := authproxy.Config{Binding: authproxy.Binding{TunnelID: "id", Hostname: "demo.test", APIOrigin: opentunnel.DefaultAPI}, Upstream: "http://127.0.0.1:8000", Mode: "password"}
	cfg.Password, err = authproxy.NewPasswordVerifier([]byte("fixture-password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	err = authproxy.WithProfileLock(filepath.Join(paths.TunnelRoot, "default", "otgo-proxy"), func() error {
		flags := []string{"--profile", "", "--data-dir", paths.TunnelRoot, "--auth-config", paths.AuthConfig, "--token-file", paths.TokenFile}
		if err := run(t.Context(), append([]string{"auth", "reset"}, flags...), strings.NewReader(""), io.Discard, io.Discard); err == nil || !strings.Contains(err.Error(), "lock") {
			t.Errorf("empty profile bypasses running proxy lock: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := authproxy.LoadConfig(paths.AuthConfig); err != nil {
		t.Fatal("running default profile's config was removed")
	}
}

func TestFreshAuthInitRevokesOrphanedMachineTokens(t *testing.T) {
	for _, tc := range []struct {
		name           string
		failSave, json bool
	}{
		{"successful-save", false, false}, {"successful-json-save", false, true}, {"failed-save", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			failSave := tc.failSave
			flags, paths := authFixture(t)
			cfg, err := authproxy.LoadConfig(paths.AuthConfig)
			if err != nil {
				t.Fatal(err)
			}
			tokens := authproxy.NewTokenStore(paths.TokenFile, cfg)
			old, _, err := tokens.Create(time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(paths.AuthConfig); err != nil {
				t.Fatal(err)
			}
			key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			expiry := time.Now().Add(time.Hour)
			template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"test.opentunnel.test", "*.test.opentunnel.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expiry}
			der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
			if err != nil {
				t.Fatal(err)
			}
			pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
			if err != nil {
				t.Fatal(err)
			}
			cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
			api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" || r.URL.Path != "/api/tunnel/id/certificate" {
					t.Error("unexpected provisioning request")
					w.WriteHeader(400)
					return
				}
				_ = json.NewEncoder(w).Encode(opentunnel.CertificateInfo{ID: "cert", State: opentunnel.CertificateState{Type: "ready", Certificate: cert, Chain: cert, Expiry: expiry}})
			}))
			defer api.Close()
			id := opentunnel.Identity{ID: "id", Hostname: "test.opentunnel.test", Token: "fixture-token", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), Certificate: cert, Chain: cert, CertificateExpiry: expiry}
			if err := opentunnel.NewFileStorage(paths.TunnelRoot).Save(t.Context(), "inbox", id); err != nil {
				t.Fatal(err)
			}
			if failSave {
				if err := os.Remove(paths.AuthConfig + ".lock"); err != nil {
					t.Fatal(err)
				}
				if err := os.Mkdir(paths.AuthConfig+".lock", 0700); err != nil {
					t.Fatal(err)
				}
			}
			args := append([]string{"auth", "init", "--api", api.URL, "--upstream", "http://127.0.0.1:8001", "--password-stdin"}, flags...)
			if tc.json {
				args = append(args, "--json")
			}
			var output, progress bytes.Buffer
			err = run(t.Context(), args, strings.NewReader("replacement-password\n"), &output, &progress)
			if strings.Contains(output.String(), "replacement-password") || strings.Contains(progress.String(), "replacement-password") {
				t.Fatal("stdin password leaked")
			}
			if !failSave {
				if tc.json {
					if !json.Valid(output.Bytes()) || progress.Len() != 0 {
						t.Fatalf("JSON output polluted: %q stderr=%q", output.String(), progress.String())
					}
				} else if !strings.Contains(progress.String(), "Saving authentication configuration") || !strings.Contains(progress.String(), "Authentication configured") || !strings.Contains(output.String(), "configured inbox:") {
					t.Fatalf("missing completion/progress: stdout=%q stderr=%q", output.String(), progress.String())
				}
			}
			if (err != nil) != failSave {
				t.Fatalf("setup result: %v", err)
			}
			if _, err := tokens.Authenticate(old); err == nil {
				t.Fatal("old token authorized the new backend")
			}
			if !failSave {
				cfg, err := authproxy.LoadConfig(paths.AuthConfig)
				if err != nil || cfg.Upstream != "http://127.0.0.1:8001" {
					t.Fatalf("new backend not saved: %v", err)
				}
			}
		})
	}
}

func TestProxyServerTimeoutConfiguration(t *testing.T) {
	server := newProxyServer(http.NotFoundHandler())
	if server.IdleTimeout <= 0 || server.IdleTimeout > 30*time.Second {
		t.Fatal("idle clients can hold a visitor channel indefinitely")
	}
	if server.ReadTimeout != 0 || server.WriteTimeout != 0 {
		t.Fatal("server timeouts expire authenticated SSE/WebSocket streams")
	}
	if server.ReadHeaderTimeout <= 0 {
		t.Fatal("slow headers are unbounded")
	}
}
