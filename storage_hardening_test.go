package opentunnel

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFileStoragePreservesNonWritableExistingRootPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix permission bits")
	}

	root := filepath.Join(t.TempDir(), "shared")
	// #nosec G301 -- The test verifies a pre-existing readable but non-writable root.
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Force exact test fixture permissions independent of umask.
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}

	if err := NewFileStorage(root).Save(context.Background(), "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	info, statErr := os.Stat(root)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o755 {
		t.Fatalf("storage root permissions = %o, want unchanged 755", got)
	}
}

func TestFileStorageRejectsWritableExistingRootWithoutChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix permission bits")
	}

	root := filepath.Join(t.TempDir(), "shared")
	// #nosec G301 -- The test intentionally creates an unsafe writable root.
	if err := os.Mkdir(root, 0o777); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Force exact unsafe test fixture permissions independent of umask.
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}

	err := NewFileStorage(root).Save(context.Background(), "default", storageIdentity())
	if err == nil || !strings.Contains(err.Error(), "writable by group or others") {
		t.Fatalf("Save error = %v, want writable storage root error", err)
	}
	info, statErr := os.Stat(root)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o777 {
		t.Fatalf("storage root permissions = %o, want unchanged 777", got)
	}
}

func TestFileStorageAcceptsPrivateExistingRootWithoutChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix permission bits")
	}

	root := filepath.Join(t.TempDir(), "private")
	if err := os.Mkdir(root, 0o300); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- The test verifies a private nonstandard directory mode is preserved.
	if err := os.Chmod(root, 0o300); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(root, 0o700) //nolint:gosec // Restore traversal so testing can clean up the fixture.
	})

	if err := NewFileStorage(root).Save(context.Background(), "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o300 {
		t.Fatalf("storage root permissions = %o, want unchanged 300", got)
	}
}

func TestFileStorageRemovePreservesUnrelatedContents(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	store := NewFileStorage(root)
	if err := store.Save(ctx, "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	profileDir := filepath.Join(root, "default")
	unrelatedFile := filepath.Join(profileDir, "notes.txt")
	unrelatedDir := filepath.Join(profileDir, "backups")
	if err := os.WriteFile(unrelatedFile, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(unrelatedDir, 0o700); err != nil {
		t.Fatal(err)
	}

	if err := store.Remove(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(unrelatedFile); err != nil || string(got) != "keep me" {
		t.Fatalf("unrelated file = %q, %v; want preserved", got, err)
	}
	if info, err := os.Stat(unrelatedDir); err != nil || !info.IsDir() {
		t.Fatalf("unrelated directory was not preserved: %v", err)
	}
	for _, name := range []string{"token", "private-key.pem", "certificate.pem", "chain.pem", "tunnel.json", "pending.json"} {
		if _, err := os.Lstat(filepath.Join(profileDir, name)); !os.IsNotExist(err) {
			t.Errorf("owned file %q still exists or cannot be inspected: %v", name, err)
		}
	}
}

func TestFileStorageRemoveIgnoresUnmarkedDirectory(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	profileDir := filepath.Join(root, "default")
	if err := os.Mkdir(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unrelatedFile := filepath.Join(profileDir, "notes.txt")
	if err := os.WriteFile(unrelatedFile, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	store := NewFileStorage(root)

	for range 2 {
		if err := store.Remove(ctx, "default"); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := os.ReadFile(unrelatedFile); err != nil || string(got) != "keep me" {
		t.Fatalf("unmarked directory content = %q, %v; want preserved", got, err)
	}
}

func TestFileStorageRemoveWithCorruptMarkerDeletesOnlyOwnedFiles(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	profileDir := filepath.Join(root, "default")
	if err := os.Mkdir(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"tunnel.json": "{",
		"token":       "secret",
		"notes.txt":   "keep me",
	} {
		if err := os.WriteFile(filepath.Join(profileDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if err := NewFileStorage(root).Remove(ctx, "default"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(profileDir, "tunnel.json")); !os.IsNotExist(err) {
		t.Fatalf("corrupt owned marker still exists or cannot be inspected: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(profileDir, "token")); !os.IsNotExist(err) {
		t.Fatalf("owned token still exists or cannot be inspected: %v", err)
	}
	if got, err := os.ReadFile(filepath.Join(profileDir, "notes.txt")); err != nil || string(got) != "keep me" {
		t.Fatalf("unrelated file = %q, %v; want preserved", got, err)
	}
}

func TestFileStorageRemoveRejectsUnsafeMarkerBeforeDeletingFiles(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()
	profileDir := filepath.Join(root, "default")
	if err := os.Mkdir(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	unsafeMarker := filepath.Join(profileDir, "tunnel.json")
	if err := os.Mkdir(unsafeMarker, 0o700); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(profileDir, "token")
	if err := os.WriteFile(token, []byte("keep until ownership is established"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := NewFileStorage(root).Remove(ctx, "default")
	if err == nil || !strings.Contains(err.Error(), "unsafe file tunnel.json") {
		t.Fatalf("Remove error = %v, want unsafe marker error", err)
	}
	if _, err := os.Stat(unsafeMarker); err != nil {
		t.Fatalf("unsafe marker was removed: %v", err)
	}
	if got, err := os.ReadFile(token); err != nil || string(got) != "keep until ownership is established" {
		t.Fatalf("token = %q, %v; want untouched", got, err)
	}
}

func TestFileStorageRemoveRejectsSymlinkMarkerBeforeDeletingFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation may require elevated privileges on Windows")
	}

	ctx := context.Background()
	root := t.TempDir()
	profileDir := filepath.Join(root, "default")
	if err := os.Mkdir(profileDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.json")
	if err := os.WriteFile(outside, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(profileDir, "tunnel.json")
	if err := os.Symlink(outside, marker); err != nil {
		t.Fatal(err)
	}
	token := filepath.Join(profileDir, "token")
	if err := os.WriteFile(token, []byte("keep until ownership is established"), 0o600); err != nil {
		t.Fatal(err)
	}

	err := NewFileStorage(root).Remove(ctx, "default")
	if err == nil || !strings.Contains(err.Error(), "unsafe file tunnel.json") {
		t.Fatalf("Remove error = %v, want unsafe marker error", err)
	}
	if got, err := os.ReadFile(outside); err != nil || string(got) != "outside" {
		t.Fatalf("symlink target = %q, %v; want untouched", got, err)
	}
	if info, err := os.Lstat(marker); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("symlink marker was not preserved: %v", err)
	}
	if got, err := os.ReadFile(token); err != nil || string(got) != "keep until ownership is established" {
		t.Fatalf("token = %q, %v; want untouched", got, err)
	}
}

func TestFileStorageRemoveMissingProfileIsIdempotent(t *testing.T) {
	store := NewFileStorage(t.TempDir())
	for range 2 {
		if err := store.Remove(context.Background(), "missing"); err != nil {
			t.Fatal(err)
		}
	}
}

func TestFileStorageRemoveOwnedProfileAndPendingProfile(t *testing.T) {
	ctx := context.Background()
	for name, save := range map[string]func(Storage) error{
		"completed": func(store Storage) error { return store.Save(ctx, "default", storageIdentity()) },
		"pending":   func(store Storage) error { return store.SavePending(ctx, "default", storagePending()) },
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			store := NewFileStorage(root)
			if err := save(store); err != nil {
				t.Fatal(err)
			}
			if err := store.Remove(ctx, "default"); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(filepath.Join(root, "default")); !os.IsNotExist(err) {
				t.Fatalf("owned profile still exists or cannot be inspected: %v", err)
			}
			if err := store.Remove(ctx, "default"); err != nil {
				t.Fatalf("second Remove: %v", err)
			}
		})
	}
}

func TestFileStorageRemoveHonorsCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	root := t.TempDir()
	store := NewFileStorage(root)
	if err := store.Save(ctx, "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := store.Remove(ctx, "default"); !errors.Is(err, context.Canceled) {
		t.Fatalf("Remove error = %v, want context.Canceled", err)
	}
	if _, err := os.Stat(filepath.Join(root, "default", "tunnel.json")); err != nil {
		t.Fatalf("cancelled Remove changed stored profile: %v", err)
	}
}

func TestFileStorageCreatesPrivateRootAndProfile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix permission bits")
	}

	root := filepath.Join(t.TempDir(), "storage")
	if err := NewFileStorage(root).Save(context.Background(), "default", storageIdentity()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{root, filepath.Join(root, "default")} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s permissions = %o, want 700", path, got)
		}
	}
}
