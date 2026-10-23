package main

import (
	"bytes"
	"context"
	"crypto/tls"
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

func TestRouteConflictFlags(t *testing.T) {
	for _, command := range []string{"connect", "listen"} {
		var out, errout bytes.Buffer
		err := run(t.Context(), []string{command, "--on-route-conflict=unknown", "--data-dir", t.TempDir()}, strings.NewReader(""), &out, &errout)
		if err == nil || !strings.Contains(err.Error(), "must be retry or fail") {
			t.Fatalf("%s invalid conflict policy: %v", command, err)
		}
		out.Reset()
		errout.Reset()
		if err := run(t.Context(), []string{command, "--help"}, strings.NewReader(""), &out, &errout); err != nil || !strings.Contains(errout.String(), "on-route-conflict") {
			t.Fatalf("%s policy missing from help: %v", command, err)
		}
	}
}

func TestEnsureCommandProgressAndJSONSilence(t *testing.T) {
	previous := http.DefaultTransport
	transport := &provisionDeadlineTransport{err: errors.New("progress probe finished")}
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = previous }()
	for _, asJSON := range []bool{false, true} {
		var out, errout bytes.Buffer
		args := []string{"ensure", "--data-dir", t.TempDir()}
		if asJSON {
			args = append(args, "--json")
		}
		err := run(t.Context(), args, strings.NewReader(""), &out, &errout)
		if !errors.Is(err, transport.err) || out.Len() != 0 {
			t.Fatalf("ensure probe: %v, stdout=%q", err, out.String())
		}
		if asJSON && errout.Len() != 0 {
			t.Fatalf("JSON progress output: %q", errout.String())
		}
		if !asJSON && errout.String() != "creating-tunnel\n" {
			t.Fatalf("missing ensure progress: %q", errout.String())
		}
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
	identity := opentunnel.Identity{ID: "id\x1b[2J\u0085", Hostname: "host\rname", CertificateExpiry: time.Now()}
	if err := printValue(&out, false, identity, nil); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(out.String(), "\x1b\r\u0085") {
		t.Fatalf("terminal control leaked in %q", out.String())
	}
}

func TestFormatEventIncludesOperationalDetailsAndSanitizesControls(t *testing.T) {
	expiry := time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)
	event := opentunnel.Event{
		Type:    "reconnecting",
		Attempt: 3,
		Delay:   2 * time.Second,
		Session: "session\u0085",
		Conn:    17,
		Route:   "api",
		Peer:    "peer\x1b[31m",
		Reason:  "retrying",
		Error:   "bridge\rfailed",
		Expiry:  expiry,
	}
	got := formatEvent(event)
	for _, want := range []string{
		"reconnecting", "attempt=3", "delay=2s", "session=session?", "conn=17", "route=api",
		"peer=peer?[31m", "reason=retrying", "error=bridge?failed", "expiry=2030-01-02T03:04:05Z",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("formatEvent() = %q, missing %q", got, want)
		}
	}
	if strings.ContainsAny(got, "\x1b\r\u0085") {
		t.Fatalf("terminal control leaked in %q", got)
	}
}

func TestPrintInteractiveErrorUsesStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if err := printInteractiveError(&stderr, errors.New("bad\u0085 route")); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if got, want := stderr.String(), "interactive: bad? route\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

func TestProvisionProgressReporterWritesOnlyStderr(t *testing.T) {
	var stdout, stderr bytes.Buffer
	report, reportErr := provisionProgressReporter(&stderr)
	report(opentunnel.StageCreatingTunnel)
	if err := reportErr(); err != nil {
		t.Fatal(err)
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout = %q", stdout.String())
	}
	if got, want := stderr.String(), "creating-tunnel\n"; got != want {
		t.Fatalf("stderr = %q, want %q", got, want)
	}
}

type interactiveConnectionFixture struct {
	routes []opentunnel.Routes
}

type validatingInteractiveConnection struct {
	interactiveConnectionFixture
	err error
}

func (c *validatingInteractiveConnection) SetRoutes(routes opentunnel.Routes) error {
	if c.err != nil {
		return c.err
	}
	if err := opentunnel.ValidateRoutes(routes); err != nil {
		return err
	}
	return c.interactiveConnectionFixture.SetRoutes(routes)
}

func TestInteractiveInvalidRoutesAndConflictsAreNonfatal(t *testing.T) {
	for _, line := range []string{"routes @=127.0.0.1:0", "routes UPPER=127.0.0.1:8080", "routes @=127.0.0.1:8080"} {
		t.Run(line, func(t *testing.T) {
			connection := &validatingInteractiveConnection{}
			if line == "routes @=127.0.0.1:8080" {
				connection.err = opentunnel.ErrRouteInUse
			}
			var stdout, stderr bytes.Buffer
			quit, err := processInteractiveCommand(connection, line, true, &stdout, &stderr)
			if err != nil || quit || stderr.Len() == 0 || stdout.Len() != 0 || len(connection.routes) != 0 {
				t.Fatalf("bad route ended or altered tunnel: quit=%t err=%v stderr=%q", quit, err, stderr.String())
			}
			connection.err = nil
			quit, err = processInteractiveCommand(connection, "routes @=127.0.0.1:8081", true, &stdout, &stderr)
			if err != nil || quit || len(connection.routes) != 1 {
				t.Fatalf("valid next command failed: quit=%t err=%v", quit, err)
			}
		})
	}
}

func (c *interactiveConnectionFixture) Status() opentunnel.Status {
	return opentunnel.Status{State: "connected"}
}
func (c *interactiveConnectionFixture) SetRoutes(routes opentunnel.Routes) error {
	c.routes = append(c.routes, routes)
	return nil
}

func TestInteractiveCommandErrorKeepsSessionAndJSONStdoutClean(t *testing.T) {
	connection := &interactiveConnectionFixture{}
	var stdout, stderr bytes.Buffer
	quit, err := processInteractiveCommand(connection, "routes malformed", true, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if quit {
		t.Fatal("malformed route quit the session")
	}
	if stdout.Len() != 0 {
		t.Fatalf("malformed command wrote stdout: %q", stdout.String())
	}
	if got := stderr.String(); !strings.Contains(got, "interactive:") || !strings.Contains(got, "name=host:port") {
		t.Fatalf("stderr = %q", got)
	}
	quit, err = processInteractiveCommand(connection, "routes @=127.0.0.1:8080", true, &stdout, &stderr)
	if err != nil {
		t.Fatal(err)
	}
	if quit || len(connection.routes) != 1 {
		t.Fatalf("post-error command quit=%t routes=%v", quit, connection.routes)
	}
}

func TestInteractiveQuitIsClean(t *testing.T) {
	quit, err := processInteractiveCommand(&interactiveConnectionFixture{}, "quit", false, io.Discard, io.Discard)
	if err != nil || !quit {
		t.Fatalf("quit=%t err=%v", quit, err)
	}
}

type failingWriter struct{ err error }

func (w failingWriter) Write([]byte) (int, error) { return 0, w.err }

func TestInteractiveOutputFailurePropagates(t *testing.T) {
	want := errors.New("stdout unavailable")
	_, err := processInteractiveCommand(&interactiveConnectionFixture{}, "status", false, failingWriter{err: want}, io.Discard)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
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

func TestListenCommandValidation(t *testing.T) {
	for _, args := range [][]string{{"listen"}, {"listen", "--route", "@=127.0.0.1:8080"}, {"listen", "--route", "Bad"}, {"listen", "--route", "@", "--route", "@"}} {
		var out, errout bytes.Buffer
		err := run(t.Context(), append(args, "--data-dir", t.TempDir()), strings.NewReader(""), &out, &errout)
		if err == nil || strings.Contains(err.Error(), "unknown command") {
			t.Fatalf("%v: %v", args, err)
		}
	}
	var out, errout bytes.Buffer
	if err := run(t.Context(), []string{"listen", "--help"}, strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errout.String(), "route name") {
		t.Fatal(errout.String())
	}
}

func TestListenerDiagnosticUsesTLSAndRelayMetadata(t *testing.T) {
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "https://demo.test/", nil)
	request.RemoteAddr = "203.0.113.7:443"
	request.TLS = &tls.ConnectionState{HandshakeComplete: true, ServerName: "demo.test"}
	request.Header.Set("X-Forwarded-For", "forged")
	request.Header.Set("X-Forwarded-Proto", "http")
	response := httptest.NewRecorder()
	listenerDiagnostic(response, request)
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["tls"] != true || result["sni"] != "demo.test" || result["origin"] != "https://demo.test" || result["peer"] != request.RemoteAddr {
		t.Fatal(result)
	}
	request.TLS = nil
	response = httptest.NewRecorder()
	listenerDiagnostic(response, request)
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["tls"] != false || result["origin"] != "" {
		t.Fatal(result)
	}
}

func TestListenAcceptsRouteNamesBeforeStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out, errout bytes.Buffer
	err := run(ctx, []string{"listen", "--route", "@", "--route", "api", "--data-dir", t.TempDir()}, strings.NewReader(""), &out, &errout)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("valid route names rejected: %v", err)
	}
}
