package opentunnel

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise the real CLI process through an API/relay fixture and real visitor TLS.
func TestCLIProxyProtocolForwarding(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "otgo")
	// #nosec G204 -- Build this repository's CLI into a test-owned directory.
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./cmd/otgo")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			f := newRelay(t)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			// #nosec G204 -- Execute only the CLI built above, with test-owned arguments.
			cmd := exec.CommandContext(ctx, binary, "connect", "--api", f.api.server.URL, "--data-dir", t.TempDir(), "--route", "@="+echoTarget(t), "--proxy-protocol", "@="+version, "--interactive", "--json")
			in, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			out, err := cmd.StdoutPipe()
			if err != nil {
				t.Fatal(err)
			}
			var stderr bytes.Buffer
			cmd.Stderr = &stderr
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			lines := make(chan []byte, 100)
			scanned := make(chan struct{})
			go func() {
				defer close(scanned)
				defer close(lines)
				scanner := bufio.NewScanner(out)
				for scanner.Scan() {
					select {
					case lines <- bytes.Clone(scanner.Bytes()):
					case <-ctx.Done():
						return
					}
				}
			}()
			done := make(chan struct{})
			var processErr error
			go func() { processErr = cmd.Wait(); close(done) }()
			defer func() { cancel(); _ = in.Close(); <-done; <-scanned }()
			s := f.next(t)
			visitor := tls.Client(s.publicRaw(t, 1, "demo.test"), &tls.Config{RootCAs: f.api.authority.roots, ServerName: "demo.test", MinVersion: tls.VersionTLS12})
			defer func() { _ = visitor.Close() }()
			_ = visitor.SetDeadline(time.Now().Add(5 * time.Second))
			if err := visitor.HandshakeContext(t.Context()); err != nil {
				t.Fatal(err)
			}
			header := []byte("PROXY TCP4 127.0.0.1 0.0.0.0 0 443\r\n")
			if version == "v2" {
				header, err = hex.DecodeString("0d0a0d0a000d0a515549540a211100187f00000100000000000001bb02000964656d6f2e74657374")
				if err != nil {
					t.Fatal(err)
				}
			}
			payload := "cli-request"
			if _, err := io.WriteString(visitor, payload); err != nil {
				t.Fatal(err)
			}
			want := append(bytes.Clone(header), payload...)
			got := make([]byte, len(want))
			if _, err := io.ReadFull(visitor, got); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("CLI forwarded %q, want %q", got, want)
			}
			if _, err := io.WriteString(in, "status\n"); err != nil {
				t.Fatal(err)
			}
			timer := time.NewTimer(3 * time.Second)
			defer timer.Stop()
			found := false
			for !found {
				select {
				case line, ok := <-lines:
					if !ok {
						t.Fatal("CLI stdout closed before status")
					}
					var status struct {
						State        string                  `json:"state"`
						RouteOptions map[string]RouteOptions `json:"routeOptions"`
					}
					if err := json.Unmarshal(line, &status); err != nil {
						t.Fatal(err)
					}
					if status.State == "connected" {
						if string(status.RouteOptions["@"].ProxyProtocol) != version {
							t.Fatal("CLI status lost options")
						}
						found = true
					}
				case <-timer.C:
					t.Fatal("CLI did not emit status")
				}
			}
			// Existing channels must not receive a second preamble after options change.
			if _, err := io.WriteString(in, "proxy-protocol\nstatus\n"); err != nil {
				t.Fatal(err)
			}
			found = false
			for !found {
				select {
				case line, ok := <-lines:
					if !ok {
						t.Fatal("CLI stdout closed")
					}
					var status struct {
						State        string                  `json:"state"`
						RouteOptions map[string]RouteOptions `json:"routeOptions"`
					}
					if err := json.Unmarshal(line, &status); err != nil {
						t.Fatal(err)
					}
					if status.State == "connected" && len(status.RouteOptions) == 0 {
						found = true
					}
				case <-timer.C:
					t.Fatal("CLI did not clear options")
				}
			}
			if _, err := io.WriteString(visitor, "after-update"); err != nil {
				t.Fatal(err)
			}
			got = make([]byte, len("after-update"))
			if _, err := io.ReadFull(visitor, got); err != nil {
				t.Fatal(err)
			}
			if string(got) != "after-update" {
				t.Fatal("existing stream received another preamble")
			}
			if _, err := io.WriteString(in, "quit\n"); err != nil {
				t.Fatal(err)
			}
			select {
			case <-done:
			case <-time.After(3 * time.Second):
				t.Fatal("CLI did not stop")
			}
			if processErr != nil || strings.Contains(stderr.String(), "interactive:") {
				t.Fatalf("CLI exit: %v: %s", processErr, stderr.String())
			}
		})
	}
}
