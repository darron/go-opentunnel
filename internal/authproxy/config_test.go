package authproxy

import (
	"bytes"
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

func TestConfigNestedSecretRedaction(t *testing.T) {
	cfg := fixtureConfig()
	for _, v := range []any{cfg.GitHub, cfg.Password} {
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), cfg.GitHub.ClientSecret) || strings.Contains(string(b), cfg.Password.Digest) {
			t.Fatal("nested credential JSON leaked")
		}
	}
}

func TestConfigMetricsAddressRoundTripAndValidation(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "auth.json")
	for _, address := range []string{"", "localhost:0", "127.0.0.1:9090", "[::1]:9090"} {
		cfg := fixtureConfig()
		cfg.MetricsListen = address
		if e := SaveConfig(path, cfg); e != nil {
			t.Fatal(e)
		}
		got, e := LoadConfig(path)
		if e != nil || got.MetricsListen != address {
			t.Fatalf("roundtrip %q: %+v %v", address, got, e)
		}
		raw, e := os.ReadFile(path)
		if e != nil {
			t.Fatal(e)
		}
		if address == "" && strings.Contains(string(raw), "metrics_listen") {
			t.Fatal("old config shape changed")
		}
		public, e := json.Marshal(got)
		if e != nil {
			t.Fatal(e)
		}
		if strings.Contains(string(public), "secret-never-print") || strings.Contains(string(public), "digest") {
			t.Fatal("redaction changed")
		}
	}
	before, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	for _, address := range []string{"0.0.0.0:90", "[::]:90", "evil.test:90", "192.0.2.1:90", "localhost", "localhost:99999", "localhost:http"} {
		cfg := fixtureConfig()
		cfg.MetricsListen = address
		if e := SaveConfig(path, cfg); e == nil {
			t.Fatalf("unsafe config accepted: %s", address)
		}
		after, e := os.ReadFile(path)
		if e != nil || string(before) != string(after) {
			t.Fatal("invalid value changed config")
		}
	}
	// #nosec G703 -- path is an isolated test fixture, not user input.
	if e := os.WriteFile(path, []byte(strings.Replace(string(before), `"metrics_listen":`, `"unknown_metrics":`, 1)), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := LoadConfig(path); e == nil {
		t.Fatal("unknown field accepted")
	}
}

func TestConfigCACertRoundTripAndValidation(t *testing.T) {
	path := filepath.Join(secureTempDir(t), "auth.json")
	cfg := fixtureConfig()
	cfg.CACertFile = filepath.Join(secureTempDir(t), "ca.pem")
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	got, err := LoadConfig(path)
	if err != nil || got.CACertFile != cfg.CACertFile {
		t.Fatalf("roundtrip: %v %+v", err, got)
	}
	public, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(public), "ca_cert") || strings.Contains(string(public), "secret-never-print") || strings.Contains(string(public), "digest") {
		t.Fatal("CA config damaged redaction")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"relative.pem", "/tmp/invalid\x00.pem"} {
		cfg.CACertFile = value
		if err := SaveConfig(path, cfg); err == nil {
			t.Fatalf("accepted %q", value)
		}
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("invalid CA path changed config")
		}
	}
	cfg.CACertFile = ""
	if err := SaveConfig(path, cfg); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "ca_cert") {
		t.Fatal("empty CA changed old config shape")
	}
}
