package authproxy

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func fixtureConfig() Config {
	return Config{Binding: Binding{TunnelID: "id", Hostname: "demo.test", APIOrigin: "https://api.test"}, Upstream: "http://127.0.0.1:8000", Mode: "password", Password: PasswordVerifier{Version: 1, Salt: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", Iterations: 600000, Digest: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, GitHub: GitHubConfig{ClientID: "client", ClientSecret: "secret-never-print"}}
}

func TestResolvePathsXDGAndOverrides(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	p, err := ResolvePaths("inbox", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if p.AuthConfig != filepath.Join(home, ".config", "otgo", "inbox", "auth.json") || p.TokenFile != filepath.Join(home, ".local", "share", "otgo", "inbox", "tokens.json") || p.TunnelRoot != filepath.Join(home, ".local", "share", "opentunnel") {
		t.Fatalf("paths: %+v", p)
	}
	if _, err = os.Stat(filepath.Dir(p.AuthConfig)); !os.IsNotExist(err) {
		t.Fatal("path resolution created files")
	}
	t.Setenv("XDG_CONFIG_HOME", "relative")
	t.Setenv("XDG_DATA_HOME", "relative")
	relative, err := ResolvePaths("inbox", "", "", "")
	if err != nil || relative != p {
		t.Fatalf("relative overrides: %+v %v", relative, err)
	}
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, "cfg"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	absolute, err := ResolvePaths("other", "", "", "")
	if err != nil || absolute.AuthConfig != filepath.Join(home, "cfg", "otgo", "other", "auth.json") {
		t.Fatalf("absolute overrides: %+v %v", absolute, err)
	}
	explicit, err := ResolvePaths("inbox", filepath.Join(home, "tunnel"), filepath.Join(home, "auth"), filepath.Join(home, "tokens"))
	if err != nil || explicit.AuthConfig != filepath.Join(home, "auth") {
		t.Fatalf("explicit: %+v %v", explicit, err)
	}
	for _, bad := range []string{"../x", "UPPER", "a/b", "-a", strings.Repeat("x", 64)} {
		if _, err := ResolvePaths(bad, "", "", ""); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}

func TestConfigProtectedRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "profile", "auth.json")
	cfg := fixtureConfig()
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadConfig(path)
	if err != nil || loaded.GitHub.ClientSecret != cfg.GitHub.ClientSecret {
		t.Fatalf("round trip: %v", err)
	}
	if runtime.GOOS != "windows" {
		info, e := os.Stat(path)
		if e != nil || info.Mode().Perm() != 0600 {
			t.Fatal("file permissions")
		}
		info, e = os.Stat(filepath.Dir(path))
		if e != nil || info.Mode().Perm() != 0700 {
			t.Fatal("directory permissions")
		}
	}
	public, _ := json.Marshal(cfg)
	for _, out := range []string{string(public), fmt.Sprintf("%+v", cfg), fmt.Sprintf("%#v", cfg)} {
		if strings.Contains(out, cfg.GitHub.ClientSecret) || strings.Contains(out, "\"digest\"") {
			t.Fatalf("secret leaked: %s", out)
		}
	}
}

func TestConfigRejectsUnsafeFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix mode and symlink checks")
	}
	root := secureTempDir(t)
	target := filepath.Join(root, "auth.json")
	if err := SaveConfig(target, fixtureConfig()); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(link); err == nil {
		t.Fatal("loaded symlink")
	}
	if err := SaveConfig(link, fixtureConfig()); err == nil {
		t.Fatal("replaced symlink")
	}
	// #nosec G302 -- Deliberately public credentials must be rejected.
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(target); err == nil {
		t.Fatal("loaded public credentials")
	}
	if err := os.Chmod(target, 0600); err != nil {
		t.Fatal(err)
	}
	// #nosec G302 -- Deliberately unsafe directory must be rejected.
	if err := os.Chmod(root, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(target); err == nil {
		t.Fatal("loaded unsafe profile directory")
	}
}

func TestConfigAtomicWriteFailure(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "auth.json")
	if err := SaveConfig(path, fixtureConfig()); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	bad := fixtureConfig()
	bad.Upstream = "http://evil.test"
	if err := SaveConfig(path, bad); err == nil {
		t.Fatal("accepted plaintext remote upstream")
	}
	after, _ := os.ReadFile(path)
	if string(before) != string(after) {
		t.Fatal("failed update changed config")
	}
	if err := os.WriteFile(path, []byte(strings.Repeat(" ", maxFileBytes+1)), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadConfig(path); err == nil {
		t.Fatal("loaded oversized file")
	}
}

func TestConfigBindingMismatch(t *testing.T) {
	cfg := fixtureConfig()
	if err := ValidateBinding(cfg, cfg.Binding); err != nil {
		t.Fatal(err)
	}
	for _, b := range []Binding{{"different", cfg.Binding.Hostname, cfg.Binding.APIOrigin}, {cfg.Binding.TunnelID, "other.test", cfg.Binding.APIOrigin}, {cfg.Binding.TunnelID, cfg.Binding.Hostname, "https://other.test"}} {
		if err := ValidateBinding(cfg, b); err == nil {
			t.Fatal("accepted changed identity")
		}
	}
}

func secureTempDir(t *testing.T) string {
	t.Helper()
	p := t.TempDir()
	// #nosec G302 -- Directory needs owner read/write/search permissions.
	if err := os.Chmod(p, 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestConfigStrictJSONAndFailedReplacement(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "auth.json")
	if err := SaveConfig(path, fixtureConfig()); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range [][]byte{append(append([]byte{}, original...), []byte("{}")...), []byte(`{"unexpected":true}`)} {
		// #nosec G703 -- Test-owned temporary credential file.
		if err := os.WriteFile(path, b, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadConfig(path); err == nil {
			t.Fatal("accepted malformed configuration")
		}
	}
	// #nosec G703 -- Restore the test-owned temporary credential file.
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	// A compromised lock must prevent mutation of the previous valid config.
	if err := os.Remove(path + ".lock"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path+".lock", 0700); err != nil {
		t.Fatal(err)
	}
	if err := SaveConfig(path, fixtureConfig()); err == nil {
		t.Fatal("accepted non-file lock")
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(original) {
		t.Fatal("failed replacement changed config")
	}
}
