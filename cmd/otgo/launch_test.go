package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestLaunchCommandQuotesStoragePathsWithoutExecutingThem(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell command")
	}
	marker := filepath.Join(t.TempDir(), "must-not-exist")
	path := "relative dir/' $(touch " + marker + ") `touch " + marker + "` <script>"
	a := authFlags{commonFlags: commonFlags{profile: "inbox", dataDir: path, api: "https://api.example.test/base", requestTimeout: 7 * time.Second}, configPath: path + "/auth.json", tokenPath: path + "/tokens.json"}
	// Let a real shell parse the displayed command, replacing execution with an
	// argument dump. A quoting regression would execute the canary substitutions.
	// #nosec G204 -- Deliberate real-shell quoting test; every input is a test-owned canary.
	cmd := exec.CommandContext(t.Context(), "sh", "-c", "set -- "+a.launchCommand()+"; printf '%s\\000' \"$@\"")
	got, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"otgo", "proxy", "--profile", "inbox", "--api", "https://api.example.test/base", "--data-dir", absolute, "--auth-config", absolute + "/auth.json", "--token-file", absolute + "/tokens.json", "--request-timeout", "7s"}
	if args := strings.Split(strings.TrimSuffix(string(got), "\x00"), "\x00"); !reflect.DeepEqual(args, want) {
		t.Fatalf("arguments corrupted: %q", args)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("displayed command executed path contents")
	}
	var parsed authFlags
	fs := newFlagSet("proxy", &bytes.Buffer{})
	parsed.bind(fs)
	if err := parseAuthFlags(fs, want[2:], &parsed); err != nil {
		t.Fatal(err)
	}
	a.dataDir = absolute
	a.configPath = absolute + "/auth.json"
	a.tokenPath = absolute + "/tokens.json"
	if parsed != a {
		t.Fatal("launch command changed selected storage or API")
	}
}
