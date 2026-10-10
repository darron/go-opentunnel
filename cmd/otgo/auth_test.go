package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
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
func TestAuthTokenCommandsAndReset(t *testing.T) {
	flags, paths := authFixture(t)
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
	if _, err := authproxy.NewTokenStore(paths.TokenFile).Authenticate(result.Token); err == nil {
		t.Fatal("CLI revocation failed")
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
	if err := run(t.Context(), append([]string{"proxy"}, flags...), strings.NewReader(""), &out, &errout); err == nil || !strings.Contains(err.Error(), "lock") {
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
