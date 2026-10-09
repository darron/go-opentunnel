package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/darron/go-opentunnel"
)

func TestRunHelpAndRejectsUnknownCommand(t *testing.T) {
	var out, errout bytes.Buffer
	if err := run(context.Background(), []string{"help"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "connect") {
		t.Fatalf("help did not describe commands: %q", out.String())
	}
	if err := run(context.Background(), []string{"wrong"}, strings.NewReader(""), &out, &errout); err == nil || !strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("unknown command error = %v", err)
	}
}

func TestCommandHelpIsSuccessful(t *testing.T) {
	var out, errout bytes.Buffer
	if err := run(context.Background(), []string{"get", "--help"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatalf("help error = %v", err)
	}
	if !strings.Contains(errout.String(), "-profile") {
		t.Fatalf("command help = %q", errout.String())
	}
}

func TestConnectRejectsMalformedRouteBeforeConnecting(t *testing.T) {
	var out, errout bytes.Buffer
	err := run(context.Background(), []string{"connect", "--route", "not-a-route"}, strings.NewReader(""), &out, &errout)
	if err == nil || !strings.Contains(err.Error(), "name=host:port") {
		t.Fatalf("error = %v", err)
	}
}

func TestGetJSONRedactsCredentials(t *testing.T) {
	dir := t.TempDir()
	store := opentunnel.NewFileStorage(dir)
	identity := opentunnel.Identity{ID: "tunnel-id", Hostname: "unit.opentunnel.test", Token: "token-must-not-print", PrivateKey: "private-key-must-not-print", Certificate: "certificate", Chain: "chain", CertificateExpiry: time.Now().Add(time.Hour)}
	if err := store.Save(context.Background(), "unit", identity); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	if err := run(context.Background(), []string{"get", "--data-dir", dir, "--profile", "unit", "--json"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), identity.Token) || strings.Contains(out.String(), identity.PrivateKey) {
		t.Fatalf("credential leaked in %q", out.String())
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["id"] != identity.ID {
		t.Fatalf("JSON id = %v", decoded["id"])
	}
}

func TestMissingGetAndPendingUseJSONNull(t *testing.T) {
	for _, command := range []string{"get", "pending"} {
		var out, errout bytes.Buffer
		err := run(context.Background(), []string{command, "--data-dir", t.TempDir(), "--json"}, strings.NewReader(""), &out, &errout)
		if err != nil {
			t.Fatalf("%s: %v", command, err)
		}
		if out.String() != "null\n" {
			t.Fatalf("%s output = %q", command, out.String())
		}
	}
}

func TestRemoveJSONReportsResult(t *testing.T) {
	var out, errout bytes.Buffer
	err := run(context.Background(), []string{"remove", "--data-dir", t.TempDir(), "--profile", "unit", "--json"}, strings.NewReader(""), &out, &errout)
	if err != nil {
		t.Fatal(err)
	}
	if out.String() != "{\"profile\":\"unit\",\"removed\":true}\n" {
		t.Fatalf("output = %q", out.String())
	}
}

func TestNegativeDurationsAreRejected(t *testing.T) {
	for _, args := range [][]string{{"profiles", "--request-timeout=-1s"}, {"connect", "--timeout=-1s"}} {
		var out, errout bytes.Buffer
		err := run(context.Background(), args, strings.NewReader(""), &out, &errout)
		if err == nil || !strings.Contains(err.Error(), "must not be negative") {
			t.Fatalf("%v error = %v", args, err)
		}
	}
}

func TestPlainOutputSanitizesTerminalControls(t *testing.T) {
	var out bytes.Buffer
	identity := opentunnel.Identity{ID: "id\x1b[2J", Hostname: "host\rname", CertificateExpiry: time.Now()}
	if err := printValue(&out, false, identity, nil); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\r") {
		t.Fatalf("terminal control leaked in %q", out.String())
	}
}

func TestReadCommandsStopsBlockedBurstOnCancel(t *testing.T) {
	reader, writer := io.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	commands := make(chan string, 1)
	done := make(chan struct{})
	go readCommands(ctx, reader, commands, done)
	writeDone := make(chan struct{})
	go func() { _, _ = io.WriteString(writer, "status\nroutes @=127.0.0.1:8080\nquit\n"); close(writeDone) }()
	select {
	case <-commands:
	case <-time.After(time.Second):
		t.Fatal("reader did not deliver first command")
	}
	cancel()
	_ = reader.Close()
	_ = writer.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader did not stop after cancellation")
	}
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("writer remained blocked after reader shutdown")
	}
}

func TestReadCommandsStopsAtQuitWithoutEOF(t *testing.T) {
	reader, writer := io.Pipe()
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	commands := make(chan string, 1)
	done := make(chan struct{})
	go readCommands(t.Context(), reader, commands, done)
	if _, err := io.WriteString(writer, "  quit  \n"); err != nil {
		t.Fatal(err)
	}
	select {
	case command := <-commands:
		if strings.TrimSpace(command) != "quit" {
			t.Fatalf("command = %q", command)
		}
	case <-time.After(time.Second):
		t.Fatal("reader did not deliver quit")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("reader attempted another read after quit while input remained open")
	}
}

func TestNativeStdinCancellationDoesNotWaitForEOF(t *testing.T) {
	if os.Getenv("OTGO_TEST_NATIVE_STDIN") == "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		_, stop := startCommandReader(ctx, os.Stdin)
		<-ctx.Done()
		stop()
		return
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close(); _ = writer.Close() }()
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G204 -- Runs this test binary, never a caller-selected executable.
	command := exec.CommandContext(ctx, executable, "-test.run=^TestNativeStdinCancellationDoesNotWaitForEOF$")
	command.Env = append(os.Environ(), "OTGO_TEST_NATIVE_STDIN=1")
	command.Stdin = reader
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("native stdin shutdown: %v: %s", err, output)
	}
}

func TestInspectRoutesThroughAPIAndRedactsStoredCredentials(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/tunnel/tunnel-id" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer test-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"tunnel-id","hostname":"unit.opentunnel.test","state":"online"}`))
	}))
	defer server.Close()
	dir := t.TempDir()
	store := opentunnel.NewFileStorage(dir)
	if err := store.Save(context.Background(), "unit", opentunnel.Identity{ID: "tunnel-id", Hostname: "unit.opentunnel.test", Token: "test-token", PrivateKey: "private-key-must-not-print", Certificate: "certificate", Chain: "chain", CertificateExpiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	var out, errout bytes.Buffer
	err := run(context.Background(), []string{"inspect", "--api", server.URL, "--data-dir", dir, "--profile", "unit", "--json"}, strings.NewReader(""), &out, &errout)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "test-token") || strings.Contains(out.String(), "private-key-must-not-print") {
		t.Fatalf("credential leaked in %q", out.String())
	}
	if !strings.Contains(out.String(), `"state":"online"`) {
		t.Fatalf("inspect output = %q", out.String())
	}
}

func TestCanceledCommandReturnsContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out, errout bytes.Buffer
	err := run(ctx, []string{"profiles", "--data-dir", t.TempDir()}, strings.NewReader(""), &out, &errout)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v", err)
	}
}
