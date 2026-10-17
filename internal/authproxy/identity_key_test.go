package authproxy

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func TestIdentityKeyPersistenceAndFailClosed(t *testing.T) {
	paths := Paths{AuthConfig: filepath.Join(secureTempDir(t), "auth.json")}
	cfg := fixtureConfig()
	if err := SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	key, err := EnsureIdentityKey(paths, cfg)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 5 {
		wg.Go(func() {
			again, err := EnsureIdentityKey(paths, cfg)
			if err != nil || !key.Equal(again) {
				t.Errorf("key changed: %v", err)
			}
		})
	}
	wg.Wait()
	saved, err := LoadConfig(paths.AuthConfig)
	if err != nil || saved.IdentityKeyID == "" {
		t.Fatalf("key not pinned in config: %v", err)
	}
	info, err := os.Stat(IdentityKeyPath(paths))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe key: %v", err)
	}
	if len(key) != ed25519.PrivateKeySize {
		t.Fatal("wrong key type")
	}
	if err := os.Remove(IdentityKeyPath(paths)); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureIdentityKey(paths, saved); err == nil {
		t.Fatal("silently replaced a missing pinned key")
	}
	if err := os.WriteFile(IdentityKeyPath(paths), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureIdentityKey(paths, saved); err == nil {
		t.Fatal("silently replaced corrupt key")
	}
}

func TestIdentityKeyRejectsUnsafeOrForeignStorage(t *testing.T) {
	for _, mode := range []string{"permissions", "symlink", "different tunnel", "wrong fingerprint"} {
		t.Run(mode, func(t *testing.T) {
			paths := Paths{AuthConfig: filepath.Join(secureTempDir(t), "auth.json")}
			cfg := fixtureConfig()
			if err := SaveConfig(paths.AuthConfig, cfg); err != nil {
				t.Fatal(err)
			}
			if _, err := EnsureIdentityKey(paths, cfg); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(paths.AuthConfig)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "permissions":
				// #nosec G302 -- Deliberately unsafe fixture; loading must reject it.
				if err := os.Chmod(IdentityKeyPath(paths), 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				b, err := os.ReadFile(IdentityKeyPath(paths))
				if err != nil {
					t.Fatal(err)
				}
				target := filepath.Join(secureTempDir(t), "target")
				// #nosec G703 -- Test-only path in a private temporary directory.
				if err := os.WriteFile(target, b, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(IdentityKeyPath(paths)); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, IdentityKeyPath(paths)); err != nil {
					t.Fatal(err)
				}
			case "different tunnel":
				cfg.Binding.TunnelID = "other"
				if err := SaveConfig(paths.AuthConfig, cfg); err != nil {
					t.Fatal(err)
				}
			case "wrong fingerprint":
				cfg.IdentityKeyID = "wrong"
				if err := SaveConfig(paths.AuthConfig, cfg); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := EnsureIdentityKey(paths, cfg); err == nil {
				t.Fatalf("accepted %s", mode)
			}
		})
	}
}

func TestIdentityKeyRejectsChangedBackendAndStaleExportConfig(t *testing.T) {
	paths := Paths{AuthConfig: filepath.Join(secureTempDir(t), "auth.json")}
	original := fixtureConfig()
	if err := SaveConfig(paths.AuthConfig, original); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureIdentityKey(paths, original); err != nil {
		t.Fatal(err)
	}
	changed, err := LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	changed.Upstream = "http://127.0.0.1:9001"
	if err := SaveConfig(paths.AuthConfig, changed); err != nil {
		t.Fatal(err)
	}
	if _, err := EnsureIdentityKey(paths, original); err == nil {
		t.Error("accepted stale export metadata")
	}
	if _, err := EnsureIdentityKey(paths, changed); err == nil {
		t.Error("reused key for a different backend")
	}
}

func TestGitHubHandlerRequiresSigningKey(t *testing.T) {
	cfg := fixtureConfig()
	cfg.Mode = "github"
	cfg.GitHub.Users = []GitHubAccount{{ID: 123, Login: "allowed"}}
	h, err := NewHandler(Options{Config: cfg})
	if err == nil {
		_ = h.Close()
		t.Fatal("GitHub mode admitted an unsigned handler")
	}
}

func TestResolvePathsRejectsIdentityKeyTokenCollision(t *testing.T) {
	root := t.TempDir()
	config := filepath.Join(root, "auth.json")
	if _, err := ResolvePaths("inbox", root, config, config+".identity.json"); err == nil {
		t.Fatal("accepted token registry at the identity key path")
	}
}
