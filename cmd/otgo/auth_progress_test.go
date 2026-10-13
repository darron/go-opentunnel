package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

type progressOutput struct {
	mu      sync.Mutex
	buf     bytes.Buffer
	changed chan struct{}
}

func (w *progressOutput) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(p)
	select {
	case w.changed <- struct{}{}:
	default:
	}
	return n, err
}
func (w *progressOutput) text() string { w.mu.Lock(); defer w.mu.Unlock(); return w.buf.String() }

func TestAuthInitProgressBeforeAPICompletes(t *testing.T) {
	for _, jsonMode := range []bool{false, true} {
		t.Run(map[bool]string{false: "text", true: "json"}[jsonMode], func(t *testing.T) {
			flags, _ := authFixture(t)
			entered := make(chan struct{})
			api := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				close(entered)
				<-r.Context().Done()
			}))
			defer api.Close()
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			output := &progressOutput{changed: make(chan struct{}, 8)}
			var out bytes.Buffer
			args := append([]string{"auth", "init", "--replace", "--upstream", "http://127.0.0.1:8001", "--password-stdin", "--api", api.URL}, flags...)
			if jsonMode {
				args = append(args, "--json")
			}
			done := make(chan error, 1)
			go func() { done <- run(ctx, args, strings.NewReader("private-password\n"), &out, output) }()
			select {
			case <-entered:
			case <-time.After(3 * time.Second):
				t.Fatal("API not reached")
			}
			before := output.text()
			if jsonMode {
				if before != "" {
					t.Fatalf("JSON progress: %q", before)
				}
			} else {
				for _, step := range []string{"Preparing password", "Provisioning tunnel and certificate"} {
					if !strings.Contains(before, step) {
						t.Errorf("missing %q while provisioning: %q", step, before)
					}
				}
				if strings.Contains(before, "private-password") || strings.Contains(before, "do-not-print") {
					t.Fatal("progress leaked credentials")
				}
				if strings.ContainsAny(before, "\r\x1b") {
					t.Fatal("redirected output contains terminal animation")
				}
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("cancellation: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation hung")
			}
			if out.Len() != 0 {
				t.Fatalf("failed provisioning reported success: %q", out.String())
			}
		})
	}
}

func TestAnimatedProgressStopsBeforeNextOutput(t *testing.T) {
	output := &progressOutput{changed: make(chan struct{}, 8)}
	p := newAuthProgress(output, true, true)
	p.step("Provisioning tunnel and certificate")
	first := output.text()
	timer := time.NewTimer(time.Second)
	defer timer.Stop()
	for output.text() == first {
		select {
		case <-output.changed:
		case <-timer.C:
			t.Fatal("spinner did not advance")
		}
	}
	if err := p.stop(); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(output.text(), "\n") {
		t.Fatal("spinner left an unfinished line")
	}
	_, _ = io.WriteString(output, "next output\n")
	stopped := output.text()
	time.Sleep(200 * time.Millisecond)
	if output.text() != stopped {
		t.Fatal("spinner wrote after stop")
	}
	if err := p.stop(); err != nil {
		t.Fatal(err)
	}
}

func TestBrowserCommandUsesSeparateURLArgument(t *testing.T) {
	address := "http://127.0.0.1:12345/__otgo/github/setup?token=one&other='$(echo secret)'"
	for _, tc := range []struct {
		platform, executable string
		prefix               []string
	}{
		{"darwin", "open", nil}, {"linux", "xdg-open", nil}, {"windows", "rundll32", []string{"url.dll,FileProtocolHandler"}},
	} {
		command, args, err := browserCommand(tc.platform, address)
		if err != nil || command != tc.executable || len(args) != len(tc.prefix)+1 || args[len(args)-1] != address {
			t.Fatalf("%s: %s %q %v", tc.platform, command, args, err)
		}
		for i, want := range tc.prefix {
			if args[i] != want {
				t.Errorf("%s argument %d", tc.platform, i)
			}
		}
	}
	if _, _, err := browserCommand("unsupported", address); err == nil {
		t.Fatal("unsupported platform accepted")
	}
}

func TestOpenBrowserLauncherFailureAndCancellation(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("fixture targets supported Unix launchers")
	}
	root := t.TempDir()
	command, _, err := browserCommand(runtime.GOOS, "http://127.0.0.1/")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, command)
	t.Setenv("PATH", root)
	address := "http://127.0.0.1:12345/__otgo/github/setup?token=private-token"
	for _, tc := range []struct {
		name, script string
		cancel, fail bool
	}{
		{"success", "#!/bin/sh\nexit 0\n", false, false},
		{"failure", "#!/bin/sh\nprintf '%s' \"$1\" >&2\nexit 1\n", false, true},
		{"canceled", "#!/bin/sh\nexec /bin/sleep 30\n", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(tc.script), 0700); err != nil { // #nosec G306 -- Owner-executable test launcher in a private temporary directory.
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if tc.cancel {
				cancel()
			}
			started := time.Now()
			err := openBrowser(ctx, address)
			if (err != nil) != tc.fail {
				t.Fatalf("launcher result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "private-token") {
				t.Fatal("launcher error leaked token")
			}
			if tc.cancel && time.Since(started) > time.Second {
				t.Fatal("launcher ignored cancellation")
			}
		})
	}
}

// Only the external GitHub HTTP boundary is replaced; flag parsing, profile
// binding, the real loopback wizard and OS launcher invocation all execute.
func TestAuthGitHubBrowserDefaultOptOutAndFailure(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Unix launcher fixture")
	}
	original := http.DefaultTransport
	http.DefaultTransport = githubUserTransport{fallback: original}
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, tc := range []struct {
		name            string
		noBrowser, fail bool
	}{
		{"default", false, false}, {"no-browser", true, false}, {"launcher-failure", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flags, _ := authFixture(t)
			root := t.TempDir()
			marker := filepath.Join(root, "opened-url")
			launcher, _, err := browserCommand(runtime.GOOS, "")
			if err != nil {
				t.Fatal(err)
			}
			// The marker is a generated tempfile path, not interpolated user input.
			script := "#!/bin/sh\nprintf '%s' \"$1\" > '" + marker + "'\n"
			if tc.fail {
				script += "exit 1\n"
			}
			if err := os.WriteFile(filepath.Join(root, launcher), []byte(script), 0700); err != nil {
				t.Fatal(err)
			} // #nosec G306 -- Owner-executable test launcher in a private temporary directory.
			t.Setenv("PATH", root)
			output := &progressOutput{changed: make(chan struct{}, 8)}
			stderr := &progressOutput{changed: make(chan struct{}, 8)}
			args := append([]string{"auth", "github", "--allow-user", "allowed"}, flags...)
			if tc.noBrowser {
				args = append(args, "--no-browser")
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- run(ctx, args, strings.NewReader(""), output, stderr) }()
			deadline := time.NewTimer(3 * time.Second)
			defer deadline.Stop()
			for !strings.HasPrefix(output.text(), "Open ") {
				select {
				case <-output.changed:
				case err := <-done:
					t.Fatalf("wizard stopped early: %v", err)
				case <-deadline.C:
					t.Fatal("setup URL not printed")
				}
			}
			address := strings.Fields(output.text())[1]
			if !tc.noBrowser {
				for {
					data, err := os.ReadFile(marker)
					if err == nil && string(data) == address {
						break
					}
					select {
					case <-time.After(time.Millisecond):
					case <-deadline.C:
						t.Fatal("default launcher not invoked with setup URL")
					}
				}
				if tc.fail {
					for stderr.text() == "" {
						select {
						case <-stderr.changed:
						case <-deadline.C:
							t.Fatal("missing browser fallback warning")
						}
					}
					if strings.Contains(stderr.text(), address) || strings.Contains(stderr.text(), "token=") {
						t.Fatal("launcher warning exposed setup token")
					}
				}
			}
			// A failed launcher must still leave a usable wizard, not return an error.
			jar, err := cookiejar.New(nil)
			if err != nil {
				t.Fatal(err)
			}
			req, err := http.NewRequestWithContext(ctx, "GET", address, nil)
			if err != nil {
				t.Fatal(err)
			}
			res, err := (&http.Client{Jar: jar, Timeout: time.Second}).Do(req)
			if err != nil {
				t.Fatal(err)
			}
			_ = res.Body.Close()
			if res.StatusCode != http.StatusOK {
				t.Fatalf("fallback setup unusable: HTTP%d", res.StatusCode)
			}
			cancel()
			select {
			case err := <-done:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("wizard result: %v", err)
				}
			case <-deadline.C:
				t.Fatal("wizard did not stop")
			}
			if tc.noBrowser {
				if _, err := os.Stat(marker); !os.IsNotExist(err) {
					t.Fatal("--no-browser launched a browser")
				}
			}
		})
	}
}

type githubUserTransport struct{ fallback http.RoundTripper }

func (t githubUserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Scheme == "https" && req.URL.Host == "api.github.com" && req.URL.Path == "/users/allowed" {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"id":123,"login":"allowed"}`)), Request: req}, nil
	}
	if req.URL.Hostname() == "127.0.0.1" {
		return t.fallback.RoundTrip(req)
	}
	return nil, errors.New("unexpected external test request")
}
