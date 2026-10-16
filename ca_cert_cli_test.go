package opentunnel

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCACertCLIAuthInitAndSavedProxyRestart(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "otgo")
	// #nosec G204 -- Build and run this repository's CLI with test-owned paths.
	if data, err := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/otgo").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, data)
	}
	f, caFile := newTLSRelay(t)
	var hits atomic.Int32
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = io.WriteString(w, "protected response")
	}))
	defer backend.Close()
	root := t.TempDir()
	config := filepath.Join(root, "config", "auth.json")
	flags := []string{"--api", f.api.server.URL, "--profile", "test", "--data-dir", filepath.Join(root, "tunnels"), "--auth-config", config, "--token-file", filepath.Join(root, "tokens", "tokens.json")}
	environment := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "OPENTUNNEL_CA_CERT=") {
			environment = append(environment, entry)
		}
	}
	run := func(args ...string) []byte {
		t.Helper()
		// #nosec G204 -- Only the freshly built CLI, fixed commands and fixture paths.
		command := exec.CommandContext(t.Context(), binary, append(args, flags...)...)
		command.Env = environment
		command.Stdin = strings.NewReader("test-password-for-fixture\n")
		var stderr bytes.Buffer
		command.Stderr = &stderr
		data, err := command.Output()
		if err != nil {
			t.Fatalf("CLI %s: %v %s", args[0], err, stderr.String())
		}
		return data
	}
	_ = run("auth", "init", "--ca-cert", caFile, "--upstream", backend.URL, "--password-stdin", "--json")
	raw, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	var saved struct {
		CACert string `json:"ca_cert"`
	}
	if err := json.Unmarshal(raw, &saved); err != nil || saved.CACert != caFile {
		t.Fatalf("CA path not persisted: %v", err)
	}
	var token struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(run("auth", "token", "create", "--json"), &token); err != nil || token.Token == "" {
		t.Fatal("missing machine token")
	}
	for attempt := int32(0); attempt < 2; attempt++ {
		func() {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			// No CA flag or variable: startup must use the saved auth config.
			// #nosec G204 -- Only the fixture CLI and test-owned configuration.
			command := exec.CommandContext(ctx, binary, append([]string{"proxy", "--json"}, flags...)...)
			command.Env = environment
			command.Stdout, command.Stderr = io.Discard, io.Discard
			if err := command.Start(); err != nil {
				t.Fatal(err)
			}
			defer func() { cancel(); _ = command.Wait() }()
			relay := f.next(t)
			for index, credential := range []string{"", token.Token} {
				visitor := relay.public(t, uint32(index+1), "demo.test")
				authorization := ""
				if credential != "" {
					authorization = "Authorization: Bearer " + credential + "\r\n"
				}
				_, err := fmt.Fprintf(visitor, "GET /mcp HTTP/1.1\r\nHost: demo.test\r\nConnection: close\r\n%s\r\n", authorization)
				if err != nil {
					t.Fatal(err)
				}
				response, err := http.ReadResponse(bufio.NewReader(visitor), nil)
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(response.Body)
				_ = response.Body.Close()
				_ = visitor.Close()
				if err != nil {
					t.Fatal(err)
				}
				if credential == "" {
					if response.StatusCode != http.StatusUnauthorized || hits.Load() != attempt {
						t.Fatal("anonymous request reached backend")
					}
				} else if response.StatusCode != http.StatusOK || string(body) != "protected response" || hits.Load() != attempt+1 {
					t.Fatal("authenticated request failed")
				}
			}
		}()
	}
}
