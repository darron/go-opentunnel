package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/internal/authproxy"
)

func TestProfilesInventoryIsLocalRedactedAndIncludesPendingAndAuthOnly(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	paths, err := authproxy.ResolvePaths("inbox", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	store := opentunnel.NewFileStorage(paths.TunnelRoot)
	ctx := context.Background()
	id := opentunnel.Identity{ID: "saved-id", Hostname: "saved.opentunnel.test", Token: "tunnel-token-canary", PrivateKey: "private-key-canary", Certificate: "cert", Chain: "chain", CertificateExpiry: time.Now().Add(time.Hour)}
	if err := store.Save(ctx, "inbox", id); err != nil {
		t.Fatal(err)
	}
	verifier, err := authproxy.NewPasswordVerifier([]byte("test-password-canary"))
	if err != nil {
		t.Fatal(err)
	}
	cfg := authproxy.Config{Binding: authproxy.Binding{TunnelID: id.ID, Hostname: id.Hostname, APIOrigin: opentunnel.DefaultAPI}, Upstream: "http://127.0.0.1:57732", Mode: "password", Password: verifier}
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	orphanPaths, err := authproxy.ResolvePaths("orphan", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Mode = "github"
	cfg.Password = authproxy.PasswordVerifier{}
	// #nosec G101 -- Test-only credential canary; never used with a real provider.
	cfg.GitHub = authproxy.GitHubConfig{ClientID: "id", ClientSecret: "github-secret-canary", Users: []authproxy.GitHubAccount{{ID: 1, Login: "owner"}}}
	if err := authproxy.SaveConfig(orphanPaths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePending(ctx, "waiting", opentunnel.PendingIdentity{ID: "pending", Hostname: "pending.opentunnel.test", Token: "pending-token-canary", PrivateKey: "pending-key-canary", CSR: "csr"}); err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); w.WriteHeader(500) }))
	defer api.Close()
	var out, errout bytes.Buffer
	if err := run(ctx, []string{"profiles", "--api", api.URL, "--json"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 0 {
		t.Fatal("inventory contacted remote API")
	}
	for _, secret := range []string{id.Token, id.PrivateKey, "test-password-canary", "github-secret-canary", "pending-token-canary", "pending-key-canary", verifier.Digest, verifier.Salt} {
		if strings.Contains(out.String()+errout.String(), secret) {
			t.Fatal("inventory leaked a credential")
		}
	}
	var rows []struct{ Profile, URL, Upstream, Auth, Status, Command string }
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 3 || rows[0].Profile != "inbox" || rows[1].Profile != "orphan" || rows[2].Profile != "waiting" {
		t.Fatalf("profiles missing or unsorted: %s", out.String())
	}
	// --api selects the launch API, so a conflicting saved binding cannot be launched.
	if rows[0].Status != "api-mismatch" || rows[0].Command != "" || rows[0].URL != "https://saved.opentunnel.test" || rows[0].Upstream != "http://127.0.0.1:57732" || rows[0].Auth != "password" {
		t.Fatalf("unsafe launch inventory: %+v", rows[0])
	}
	if rows[1].Status != "auth-only" || rows[1].Command != "" || rows[2].Status != "pending" || rows[2].URL != "https://pending.opentunnel.test" || rows[2].Command != "" {
		t.Fatalf("incomplete profiles misrepresented: %s", out.String())
	}
	out.Reset()
	if err := run(ctx, []string{"profiles", "--json"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].Status != "ready" || rows[0].Command != "otgo proxy --profile inbox" {
		t.Fatalf("missing launch command: %+v", rows[0])
	}
}

func TestProfilesEmptyNamesAndUnsafeConfig(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	var out, errout bytes.Buffer
	if err := run(context.Background(), []string{"profiles", "--json"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if out.String() != "[]\n" {
		t.Fatalf("empty inventory: %s", out.String())
	}
	paths, err := authproxy.ResolvePaths("unsafe", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(paths.AuthConfig), 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(root, "secret")
	if err := os.WriteFile(target, []byte("secret-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, paths.AuthConfig); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := run(context.Background(), []string{"profiles", "--json"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Profile, Status, Command string }
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Profile != "unsafe" || rows[0].Status != "invalid-auth" || rows[0].Command != "" || strings.Contains(out.String(), "secret-canary") {
		t.Fatalf("unsafe config inventory: %s", out.String())
	}
	out.Reset()
	if err := run(context.Background(), []string{"profiles", "--names", "--json"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if out.String() != "[\"unsafe\"]\n" {
		t.Fatalf("names: %s", out.String())
	}
}

func TestProfilesKeepsCustomConfigAttachedToSelectedProfile(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "xdg-data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "xdg-config"))
	flags, paths := authFixture(t)
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Binding.APIOrigin = "https://custom-api.test"
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	id := opentunnel.Identity{ID: "other", Hostname: "other.opentunnel.test", Token: "other-token-canary", PrivateKey: "other-private-canary", Certificate: "cert", Chain: "chain", CertificateExpiry: time.Now().Add(time.Hour)}
	if err := opentunnel.NewFileStorage(paths.TunnelRoot).Save(t.Context(), "other", id); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if err := run(t.Context(), append([]string{"profiles", "--json", "--api", "https://custom-api.test/prefix"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	var rows []struct{ Profile, Auth, Status, Command string }
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || rows[0].Profile != "inbox" || rows[0].Auth != "password" || rows[0].Status != "ready" || !strings.Contains(rows[0].Command, "--api https://custom-api.test/prefix") || !strings.Contains(rows[0].Command, "--auth-config "+paths.AuthConfig) || !strings.Contains(rows[0].Command, "--token-file "+paths.TokenFile) {
		t.Fatalf("custom launch selection lost: %s", out.String())
	}
	if rows[1].Profile != "other" || rows[1].Status != "unprotected" || rows[1].Auth != "" || rows[1].Command != "" {
		t.Fatalf("custom config reused for another profile: %s", out.String())
	}
	out.Reset()
	if err := run(t.Context(), append([]string{"profiles", "--json"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	rows = nil // Decode omitted fields into fresh rows, not the previous command.
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if rows[0].Status != "api-required" || rows[0].Command != "" {
		t.Fatal("custom API origin was mistaken for its complete base URL")
	}
}

func TestProfilesDoesNotOfferLaunchForMismatchedOrCorruptIdentity(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	flags, paths := authFixture(t)
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Binding.TunnelID = "another-id"
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	check := func(want string) {
		t.Helper()
		out.Reset()
		if err := run(t.Context(), append([]string{"profiles", "--json"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
			t.Fatal(err)
		}
		var rows []struct{ Profile, Status, Command string }
		if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Profile != "inbox" || rows[0].Status != want || rows[0].Command != "" {
			t.Fatalf("unsafe launch suggested: %s", out.String())
		}
	}
	check("identity-mismatch")
	if err := os.WriteFile(filepath.Join(paths.TunnelRoot, "inbox", "tunnel.json"), []byte(`{"id":"bad-secret-canary"}`), 0600); err != nil {
		t.Fatal(err)
	}
	check("incomplete")
	if strings.Contains(out.String(), "bad-secret-canary") {
		t.Fatal("raw corrupt metadata reflected")
	}
}

func TestProfilesPreservesPendingStateWhenAuthConfigExists(t *testing.T) {
	root := t.TempDir()
	t.Setenv("XDG_DATA_HOME", filepath.Join(root, "data"))
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(root, "config"))
	flags, paths := authFixture(t)
	store := opentunnel.NewFileStorage(paths.TunnelRoot)
	if err := store.Remove(t.Context(), "inbox"); err != nil {
		t.Fatal(err)
	}
	if err := store.SavePending(t.Context(), "inbox", opentunnel.PendingIdentity{ID: "id", Hostname: "pending.opentunnel.test", Token: "pending-token-canary", PrivateKey: "pending-key-canary", CSR: "csr"}); err != nil {
		t.Fatal(err)
	}
	check := func(status, url string) {
		t.Helper()
		var out, errout bytes.Buffer
		if err := run(t.Context(), append([]string{"profiles", "--json"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
			t.Fatal(err)
		}
		var rows []struct{ Profile, Status, URL, Auth, Command string }
		if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 || rows[0].Status != status || rows[0].URL != url || rows[0].Auth != "password" || rows[0].Command != "" {
			t.Fatalf("auth overwrote tunnel state: %s", out.String())
		}
		if strings.Contains(out.String(), "pending-secret-canary") {
			t.Fatal("corrupt pending contents leaked")
		}
	}
	check("pending", "https://pending.opentunnel.test")
	if err := os.WriteFile(filepath.Join(paths.TunnelRoot, "inbox", "pending.json"), []byte("pending-secret-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	check("incomplete", "")
}
