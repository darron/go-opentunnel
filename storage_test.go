package opentunnel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func storageIdentity() Identity {
	return Identity{
		ID:                "demo",
		Hostname:          "demo.opentunnel.xyz",
		Token:             "token-secret",
		PrivateKey:        "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n",
		Certificate:       "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
		Chain:             "-----BEGIN CERTIFICATE-----\nCHAIN\n-----END CERTIFICATE-----\n",
		CertificateExpiry: time.Date(2099, 1, 1, 1, 2, 3, 0, time.FixedZone("non-UTC", 3600)),
	}
}

func storagePending() PendingIdentity {
	return PendingIdentity{ID: "demo", Hostname: "demo.opentunnel.xyz", Token: "token-secret", PrivateKey: "KEY", CSR: "CSR"}
}

func TestMemoryStorageRoundTripCopiesAndTransitions(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()
	pending := storagePending()
	if err := s.SavePending(ctx, "pending", pending); err != nil {
		t.Fatal(err)
	}
	pending.Token = "mutated"
	gotPending, err := s.LoadPending(ctx, "pending")
	if err != nil {
		t.Fatal(err)
	}
	if gotPending == nil || gotPending.Token != "token-secret" {
		t.Fatalf("pending = %#v", gotPending)
	}

	identity := storageIdentity()
	if err := s.Save(ctx, "pending", identity); err != nil {
		t.Fatal(err)
	}
	identity.Token = "mutated"
	got, err := s.Load(ctx, "pending")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Token != "token-secret" || got.CertificateExpiry.Location() != time.UTC {
		t.Fatalf("identity = %#v", got)
	}
	got.Token = "changed"
	gotAgain, err := s.Load(ctx, "pending")
	if err != nil || gotAgain.Token != "token-secret" {
		t.Fatalf("copy failure: %#v, %v", gotAgain, err)
	}
	cleared, err := s.LoadPending(ctx, "pending")
	if err != nil || cleared != nil {
		t.Fatalf("pending after save = %#v, %v", cleared, err)
	}
}

func TestMemoryStoragePendingCannotReplaceCompletedIdentity(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()
	identity := storageIdentity()
	if err := s.Save(ctx, "default", identity); err != nil {
		t.Fatal(err)
	}
	pending := storagePending()
	pending.PrivateKey = "different-key"
	if err := s.SavePending(ctx, "default", pending); !errors.Is(err, ErrExists) {
		t.Fatalf("mismatched pending error = %v, want ErrExists", err)
	}
	got, err := s.Load(ctx, "default")
	if err != nil || got == nil || got.ID != "demo" {
		t.Fatalf("completed identity was replaced: %#v, %v", got, err)
	}
}

func TestMemoryStorageConcurrentUseAndSortedResults(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryStorage()
	profiles := []string{"zeta", "alpha", "middle"}
	var wg sync.WaitGroup
	for _, profile := range profiles {
		wg.Add(1)
		go func(profile string) {
			defer wg.Done()
			if err := s.Save(ctx, profile, storageIdentity()); err != nil {
				t.Errorf("Save(%s): %v", profile, err)
			}
		}(profile)
	}
	wg.Wait()
	got, err := s.Profiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, []string{"alpha", "middle", "zeta"}) {
		t.Fatalf("profiles = %v", got)
	}
	listed, err := s.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 3 || listed[0].Profile != "alpha" || listed[2].Profile != "zeta" {
		t.Fatalf("list = %#v", listed)
	}
}

func TestFileStorageRoundTripMatchesUpstreamLayoutAndPermissions(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s := NewFileStorage(root)
	if err := s.SavePending(ctx, "default", storagePending()); err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	got, err := s.Load(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.CertificateExpiry.Location() != time.UTC || !got.CertificateExpiry.Equal(time.Date(2099, 1, 1, 0, 2, 3, 0, time.UTC)) {
		t.Fatalf("identity = %#v", got)
	}
	if pending, err := s.LoadPending(ctx, "default"); err != nil || pending != nil {
		t.Fatalf("pending = %#v, %v", pending, err)
	}
	metadata, err := os.ReadFile(filepath.Join(root, "default", "tunnel.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(metadata) != "{\n  \"id\": \"demo\",\n  \"hostname\": \"demo.opentunnel.xyz\",\n  \"certificateExpiry\": \"2099-01-01T00:02:03Z\"\n}\n" {
		t.Fatalf("unexpected upstream-compatible metadata: %q", metadata)
	}
	if runtime.GOOS != "windows" {
		for _, path := range []string{filepath.Join(root, "default"), filepath.Join(root, "default", "token"), filepath.Join(root, "default", "tunnel.json")} {
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			want := os.FileMode(0o600)
			if info.IsDir() {
				want = 0o700
			}
			if info.Mode().Perm() != want {
				t.Errorf("%s permissions = %o, want %o", path, info.Mode().Perm(), want)
			}
		}
	}
}

func TestFileStorageRejectsInvalidProfilesAndSymlinks(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s := NewFileStorage(root)
	for _, profile := range []string{"../escape", "/absolute", "Uppercase", "has space"} {
		if err := s.Save(ctx, profile, storageIdentity()); !errors.Is(err, ErrInvalid) {
			t.Errorf("Save(%q) error = %v, want ErrInvalid", profile, err)
		}
	}
	if err := os.Mkdir(filepath.Join(root, "real"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "real"), filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "linked"); err == nil {
		t.Fatal("Load accepted symlink profile directory")
	}
	if err := os.Mkdir(filepath.Join(root, "default"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "outside"), filepath.Join(root, "default", "token")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "default", "tunnel.json"), []byte(`{"id":"demo","hostname":"demo.opentunnel.xyz","certificateExpiry":"2099-01-01T00:02:03Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "default"); err == nil {
		t.Fatal("Load accepted symlink secret")
	}
}

func TestFileStorageReportsMissingCorruptIncompleteAndCancellation(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s := NewFileStorage(root)
	if got, err := s.Load(ctx, "default"); err != nil || got != nil {
		t.Fatalf("missing = %#v, %v", got, err)
	}
	if err := os.Mkdir(filepath.Join(root, "default"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "default", "tunnel.json"), []byte("not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "default"); err == nil {
		t.Fatal("corrupt metadata accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "default", "tunnel.json"), []byte(`{"id":"demo","hostname":"demo.opentunnel.xyz","certificateExpiry":"2099-01-01T00:02:03Z"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "default"); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete error = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Save(cancelled, "other", storageIdentity()); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled Save error = %v", err)
	}
}

func TestFileStorageRejectsEmptyCredentialFiles(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s := NewFileStorage(root)
	if err := s.Save(ctx, "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "default", "token"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(ctx, "default"); err == nil || !strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("empty token error = %v", err)
	}
}

func TestFileStoragePendingSaveCannotReplaceCompletedCredentials(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	s := NewFileStorage(root)
	identity := storageIdentity()
	if err := s.Save(ctx, "default", identity); err != nil {
		t.Fatal(err)
	}
	pending := storagePending()
	pending.Token = "different-token"
	pending.PrivateKey = "different-key"
	if err := s.SavePending(ctx, "default", pending); !errors.Is(err, ErrExists) {
		t.Fatalf("mismatched pending error = %v, want ErrExists", err)
	}
	got, err := s.Load(ctx, "default")
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Token != identity.Token || got.PrivateKey != identity.PrivateKey {
		t.Fatalf("completed credentials were replaced: %#v", got)
	}
	if pending, err := s.LoadPending(ctx, "default"); err != nil || pending != nil {
		t.Fatalf("pending marker = %#v, %v", pending, err)
	}
}

func TestCompletedIdentityCanStoreMatchingPendingRecovery(t *testing.T) {
	ctx := context.Background()
	for name, newStorage := range map[string]func() Storage{
		"memory": NewMemoryStorage,
		"file":   func() Storage { return NewFileStorage(t.TempDir()) },
	} {
		t.Run(name, func(t *testing.T) {
			s := newStorage()
			identity := storageIdentity()
			if err := s.Save(ctx, "default", identity); err != nil {
				t.Fatal(err)
			}
			identity.CertificateExpiry = identity.CertificateExpiry.UTC()
			pending := PendingIdentity{ID: identity.ID, Hostname: identity.Hostname, Token: identity.Token, PrivateKey: identity.PrivateKey, CSR: "replacement CSR"}
			if err := s.SavePending(ctx, "default", pending); err != nil {
				t.Fatal(err)
			}
			got, err := s.LoadPending(ctx, "default")
			if err != nil || !reflect.DeepEqual(got, &pending) {
				t.Fatalf("pending = %#v, %v", got, err)
			}
			completed, err := s.Load(ctx, "default")
			if err != nil || !reflect.DeepEqual(completed, &identity) {
				t.Fatalf("completed = %#v, %v", completed, err)
			}
		})
	}
}

func TestFileStorageRejectsSymlinkedRoot(t *testing.T) {
	ctx := context.Background()
	parent := t.TempDir()
	realRoot := filepath.Join(parent, "real")
	if err := os.Mkdir(realRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	symlinkRoot := filepath.Join(parent, "link")
	if err := os.Symlink(realRoot, symlinkRoot); err != nil {
		t.Fatal(err)
	}
	if err := NewFileStorage(symlinkRoot).Save(ctx, "default", storageIdentity()); err == nil {
		t.Fatal("Save accepted symlinked storage root")
	}
}

func TestXDGStorageUsesConfiguredDataHome(t *testing.T) {
	ctx := context.Background()
	dataHome := t.TempDir()
	t.Setenv("XDG_DATA_HOME", dataHome)
	s, err := NewXDGStorage()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(ctx, "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dataHome, "opentunnel", "default", "tunnel.json")); err != nil {
		t.Fatalf("XDG layout missing: %v", err)
	}
}

func TestXDGStorageIgnoresRelativeDataHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_DATA_HOME", "relative")
	s, err := NewXDGStorage()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(context.Background(), "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(home, ".local", "share", "opentunnel", "default", "tunnel.json")); err != nil {
		t.Fatalf("XDG fallback missing: %v", err)
	}
}
