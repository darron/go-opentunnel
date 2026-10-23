package authproxy

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestPasswordVerificationAndBounds(t *testing.T) {
	p := []byte("correct horse battery staple")
	a, err := NewPasswordVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewPasswordVerifier(p)
	if err != nil {
		t.Fatal(err)
	}
	if a.Salt == b.Salt || a.Iterations < 600000 || a.Version != 1 {
		t.Fatal("weak password parameters")
	}
	if !VerifyPassword(a, p) || VerifyPassword(a, []byte("wrong")) {
		t.Fatal("password verification")
	}
	for _, input := range [][]byte{nil, []byte("a"), bytes.Repeat([]byte("a"), 11), bytes.Repeat([]byte("a"), 1025)} {
		if _, err := NewPasswordVerifier(input); err == nil {
			t.Fatal("accepted invalid size")
		}
	}
	for _, bad := range []PasswordVerifier{{Version: 2}, {Version: 1, Iterations: 600000000}, {Version: 1, Iterations: 600000, Salt: "bad", Digest: "bad"}} {
		if VerifyPassword(bad, p) {
			t.Fatal("accepted malformed verifier")
		}
	}
	secret, err := GeneratePassword()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(secret)
	if err != nil || len(raw) != 32 {
		t.Fatal("weak generated password")
	}
}

func TestSessionsExpiryRevocationAndCapacity(t *testing.T) {
	now := time.Now()
	s := newSessions(2, func() time.Time { return now })
	defer s.Close()
	a, err := s.Create(Principal{ID: "a", Mechanism: "password"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	b, err := s.Create(Principal{ID: "b", Mechanism: "password"}, time.Second)
	if err != nil || a == b {
		t.Fatal("random session IDs")
	}
	if _, err := s.Create(Principal{}, time.Second); err == nil {
		t.Fatal("unbounded sessions")
	}
	if _, err := s.Authenticate(a); err != nil {
		t.Fatal(err)
	}
	s.Revoke(a)
	if _, err := s.Authenticate(a); err == nil {
		t.Fatal("revoked session")
	}
	now = now.Add(time.Second)
	if _, err := s.Authenticate(b); err == nil {
		t.Fatal("expired session")
	}
	if _, err := s.Create(Principal{}, time.Second); err != nil {
		t.Fatal("did not prune expired sessions")
	}
	s.Close()
	if _, err := s.Create(Principal{}, time.Second); err == nil {
		t.Fatal("closed sessions")
	}
}

func TestSessionsRestartInvalidates(t *testing.T) {
	first := NewSessions(1024)
	secret, err := first.Create(Principal{}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	second := NewSessions(1024)
	defer second.Close()
	if _, err := second.Authenticate(secret); err == nil {
		t.Fatal("session survived restart")
	}
	first.Close()
}

func TestTokenLifecycleAndHashOnlyPersistence(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "tokens.json")
	now := time.Now()
	s := newTokenStore(path, fixtureConfig(), func() time.Time { return now })
	secret, id, err := s.Create(0)
	if err != nil {
		t.Fatal(err)
	}
	p, err := s.Authenticate(secret)
	if err != nil || p.ID != id || p.Expires.Sub(now) != time.Hour {
		t.Fatalf("auth: %v", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(secret)) || strings.Contains(fmt.Sprintf("%+v", s), secret) {
		t.Fatal("plaintext token persisted")
	}
	if _, err := NewTokenStore(filepath.Join(secureTempDir(t), "tokens.json"), fixtureConfig()).Authenticate(secret); err == nil {
		t.Fatal("cross-profile token")
	}
	if _, err := s.Authenticate("bad"); err == nil {
		t.Fatal("bad prefix")
	}
	for _, ttl := range []time.Duration{-time.Second, 24*time.Hour + time.Second} {
		if _, _, err := s.Create(ttl); err == nil {
			t.Fatal("bad TTL")
		}
	}
	if err := s.Revoke(id); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(secret); err == nil {
		t.Fatal("revoked token")
	}
	secret, _, err = s.Create(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Second)
	if _, err := s.Authenticate(secret); err == nil {
		t.Fatal("expired token")
	}
	if err := os.WriteFile(path, []byte(`{"version":1,"tokens":[`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(secret); err == nil {
		t.Fatal("corrupt registry")
	}
	if _, _, err := s.Create(time.Hour); err == nil {
		t.Fatal("overwrote corrupt registry")
	}
}

func TestLegacyTokenRegistryFailsClosedWithoutMigration(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "tokens.json")
	store := NewTokenStore(path, fixtureConfig())
	secret, id, err := store.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	registry, err := store.load()
	if err != nil {
		t.Fatal(err)
	}
	registry.Version = 1
	registry.Scope = ""
	if err := store.save(registry); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.Authenticate(secret); err == nil {
		t.Fatal("legacy unbound token authenticated")
	}
	checks := []struct {
		name string
		run  func() error
	}{
		{"create", func() error { _, _, err := store.Create(time.Hour); return err }},
		{"list", func() error { _, err := store.List(); return err }},
		{"revoke", func() error { return store.Revoke(id) }},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			err := check.run()
			if err == nil || !strings.Contains(err.Error(), "otgo auth token reset") {
				t.Fatalf("legacy registry error is not actionable: %v", err)
			}
		})
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("legacy token registry was silently migrated or overwritten")
	}
}

func TestTokenRegistryBindingAndGitHubTransition(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "tokens.json")
	passwordConfig := fixtureConfig()
	passwordConfig.Upstream = "http://127.0.0.1:8001"
	original := NewTokenStore(path, passwordConfig)
	secret, _, err := original.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	otherConfig := passwordConfig
	otherConfig.Upstream = "http://127.0.0.1:8002"
	other := NewTokenStore(path, otherConfig)
	if _, err := other.Authenticate(secret); err == nil {
		t.Fatal("token authenticated for a different upstream")
	}
	if _, err := other.List(); err == nil || !strings.Contains(err.Error(), "does not match this auth configuration") {
		t.Fatalf("scope mismatch did not fail clearly: %v", err)
	}
	if _, _, err := other.Create(time.Hour); err == nil || !strings.Contains(err.Error(), "does not match this auth configuration") {
		t.Fatalf("scope mismatch overwrote registry: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("mismatched token store changed the original registry")
	}
	if _, err := original.Authenticate(secret); err != nil {
		t.Fatalf("mismatch damaged original token: %v", err)
	}

	githubConfig := passwordConfig
	githubConfig.Mode = "github"
	githubConfig.Password = PasswordVerifier{}
	githubConfig.GitHub = GitHubConfig{
		ClientID:     "client",
		ClientSecret: "secret",
		Users:        []GitHubAccount{{ID: 1, Login: "allowed"}},
	}
	if _, err := NewTokenStore(path, githubConfig).Authenticate(secret); err != nil {
		t.Fatalf("password-to-GitHub transition invalidated machine token: %v", err)
	}
}

func TestTokenConcurrentMutationsAndBounds(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "tokens.json")
	s := NewTokenStore(path, fixtureConfig())
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := NewTokenStore(path, fixtureConfig()).Create(time.Hour); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	entries, err := s.List()
	if err != nil || len(entries) != 12 {
		t.Fatalf("lost update: %d %v", len(entries), err)
	}
	for len(entries) < 256 {
		if _, _, err := s.Create(time.Hour); err != nil {
			t.Fatal(err)
		}
		entries, err = s.List()
		if err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := s.Create(time.Hour); err == nil {
		t.Fatal("unbounded registry")
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64<<10 {
		t.Fatal("registry exceeds size limit")
	}
}

func TestTokenProcessHelper(t *testing.T) {
	path := os.Getenv("OTGO_TEST_TOKEN_PATH")
	if path == "" {
		return
	}
	if os.Getenv("OTGO_TEST_HOLD_LOCK") == "1" {
		err := withFileLock(path, func() error {
			fmt.Println("locked")
			for {
				time.Sleep(time.Hour)
			}
		})
		if err != nil {
			t.Fatal(err)
		}
	} else if _, _, err := NewTokenStore(path, fixtureConfig()).Create(time.Hour); err != nil {
		t.Fatal(err)
	}
}

func TestTokenInterprocessSerializationAndCrashRelease(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "tokens\n.json")
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// #nosec G204 G702 -- Runs this test binary, never a caller-selected executable.
			cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTokenProcessHelper$")
			cmd.Env = append(os.Environ(), "OTGO_TEST_TOKEN_PATH="+path)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Errorf("child: %v %s", err, out)
			}
		}()
	}
	wg.Wait()
	entries, err := NewTokenStore(path, fixtureConfig()).List()
	if err != nil || len(entries) != 5 {
		t.Fatalf("process lost update: %d %v", len(entries), err)
	}
	// #nosec G204 G702 -- Runs this test binary, never a caller-selected executable.
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestTokenProcessHelper$")
	cmd.Env = append(os.Environ(), "OTGO_TEST_TOKEN_PATH="+path, "OTGO_TEST_HOLD_LOCK=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	line := make([]byte, 7)
	if _, err = stdout.Read(line); err != nil || string(line) != "locked\n" {
		t.Fatal("lock not held")
	}
	if _, _, err = NewTokenStore(path, fixtureConfig()).Create(time.Hour); err == nil {
		t.Fatal("did not time out waiting for lock")
	}
	for _, want := range []string{fmt.Sprintf("%q", path+".lock"), "2s", "might already be running", "do not delete the lock file"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("lock diagnostic missing %q: %v", want, err)
		}
	}
	if !lockBusy(err) {
		t.Errorf("lock diagnostic lost OS cause: %v", err)
	}
	if strings.ContainsAny(err.Error(), "\n\r\x1b") {
		t.Errorf("unescaped control character in lock diagnostic: %q", err)
	}
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	if _, _, err = NewTokenStore(path, fixtureConfig()).Create(time.Hour); err != nil {
		t.Fatalf("crash retained lock: %v", err)
	}
}

func TestStorageLockRejectsUnsafeFileWithDiagnostic(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "profile\tname")
	if err := os.WriteFile(path+".lock", nil, 0600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Deliberately unsafe, empty fixture verifies rejection regardless of the process umask.
	if err := os.Chmod(path+".lock", 0644); err != nil {
		t.Fatal(err)
	}
	err := WithProfileLock(path, func() error {
		t.Fatal("unsafe lock admitted operation")
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("%q", path+".lock")) || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("missing lock path or permission diagnostic: %v", err)
	}
	if strings.Contains(err.Error(), "might already be running") || strings.ContainsAny(err.Error(), "\t\n\r\x1b") {
		t.Fatalf("misleading or unescaped lock diagnostic: %q", err)
	}
}

func TestStorageLockPathErrorPreservesCauseAndEscapesPath(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "\n"+strings.Repeat("x", 256))
	err := WithProfileLock(path, func() error {
		t.Fatal("invalid lock path admitted operation")
		return nil
	})
	if !errors.Is(err, syscall.ENAMETOOLONG) || !strings.Contains(err.Error(), fmt.Sprintf("%q", path+".lock")) {
		t.Fatalf("missing OS cause or quoted lock path: %v", err)
	}
	if strings.Contains(err.Error(), "might already be running") || strings.ContainsAny(err.Error(), "\n\r\x1b") {
		t.Fatalf("misleading or unescaped path error: %q", err)
	}
}

func TestTokenRejectsDuplicateIDsAndConcurrentRevocation(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "tokens.json")
	s := NewTokenStore(path, fixtureConfig())
	secret, id, err := s.Create(time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := s.Revoke(id); err != nil {
			t.Error(err)
		}
	}()
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := NewTokenStore(path, fixtureConfig()).Create(time.Hour); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if _, err := s.Authenticate(secret); err == nil {
		t.Fatal("concurrent create resurrected revoked token")
	}
	registry, err := s.load()
	if err != nil {
		t.Fatal(err)
	}
	registry.Tokens = append(registry.Tokens, registry.Tokens[0])
	if err := s.save(registry); err != nil {
		t.Fatal(err)
	}
	if _, err := s.List(); err == nil {
		t.Fatal("accepted duplicate token ID")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Authenticate(secret); err == nil {
		t.Fatal("missing registry accepted token")
	}
}
