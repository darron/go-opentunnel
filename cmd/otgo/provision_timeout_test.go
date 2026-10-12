package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/darron/go-opentunnel"
)

type provisionDeadlineTransport struct {
	remaining time.Duration
	err       error
	calls     int
}

func (p *provisionDeadlineTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	p.calls++
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	deadline, ok := req.Context().Deadline()
	if ok {
		p.remaining = time.Until(deadline)
	}
	return nil, p.err
}

// Losing the provisioning deadline, using the short request default instead,
// or ignoring a caller's override/cancellation must fail at the HTTP boundary.
func TestProvisionCommandsApplyDeadlineToRequests(t *testing.T) {
	for _, command := range [][]string{{"create"}, {"resume"}, {"ensure"}, {"auth", "init"}} {
		for _, test := range []struct {
			name   string
			flag   string
			parent time.Duration
			want   time.Duration
		}{
			{name: "default", want: 5 * time.Minute},
			{name: "override", flag: "7m", want: 7 * time.Minute},
			{name: "disabled", flag: "0", want: 10 * time.Minute},
			{name: "parent", parent: 30 * time.Second, want: 30 * time.Second},
		} {
			t.Run(strings.Join(command, "_")+"/"+test.name, func(t *testing.T) {
				root := filepath.Join(t.TempDir(), "private")
				if err := os.Mkdir(root, 0700); err != nil {
					t.Fatal(err)
				}
				if command[0] == "resume" {
					pending := opentunnel.PendingIdentity{ID: "deadline-probe", Hostname: "deadline.opentunnel.test", Token: "fixture-token", PrivateKey: "fixture-key", CSR: "fixture-csr"}
					if err := opentunnel.NewFileStorage(root).SavePending(t.Context(), "unit", pending); err != nil {
						t.Fatal(err)
					}
				}
				args := append([]string(nil), command...)
				args = append(args, "--data-dir", root, "--profile", "unit", "--request-timeout", "10m")
				if test.flag != "" {
					args = append(args, "--timeout", test.flag)
				}
				if command[0] == "auth" {
					args = append(args, "--upstream", "http://127.0.0.1:8000", "--password-stdin", "--auth-config", filepath.Join(root, "auth.json"), "--token-file", filepath.Join(root, "tokens.json"))
				}
				ctx := context.Background()
				if test.parent > 0 {
					var cancel context.CancelFunc
					ctx, cancel = context.WithTimeout(ctx, test.parent)
					defer cancel()
				}
				transport := &provisionDeadlineTransport{err: errors.New("deadline probe finished")}
				previous := http.DefaultTransport
				http.DefaultTransport = transport
				t.Cleanup(func() { http.DefaultTransport = previous })
				var out, errout bytes.Buffer
				err := run(ctx, args, strings.NewReader("deadline-test-password\n"), &out, &errout)
				if !errors.Is(err, transport.err) {
					t.Fatalf("request did not reach deadline probe: %v", err)
				}
				if transport.remaining > test.want || transport.remaining < test.want-2*time.Second {
					t.Fatalf("request budget = %s, want close to %s", transport.remaining, test.want)
				}
				canceled, cancel := context.WithCancel(context.Background())
				cancel()
				calls := transport.calls
				if err := run(canceled, args, strings.NewReader("deadline-test-password\n"), &out, &errout); err == nil || transport.calls != calls {
					t.Fatalf("cancellation not preserved: %v", err)
				}
			})
		}
	}
}

type pendingTimeoutTransport struct{}

func (pendingTimeoutTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	<-r.Context().Done()
	return nil, r.Context().Err()
}
func TestPendingTimeoutResumeMessageIsVerifiedAndQuoted(t *testing.T) {
	previous := http.DefaultTransport
	http.DefaultTransport = pendingTimeoutTransport{}
	defer func() { http.DefaultTransport = previous }()
	for _, stored := range []bool{true, false} {
		root := filepath.Join(t.TempDir(), "state's $(unsafe)")
		if stored {
			if e := opentunnel.NewFileStorage(root).SavePending(t.Context(), "unit", opentunnel.PendingIdentity{ID: "pending", Hostname: "pending.test", Token: "secret-token", PrivateKey: "secret-key", CSR: "secret-csr"}); e != nil {
				t.Fatal(e)
			}
		}
		command := "create"
		if stored {
			command = "resume"
		}
		var out, errout bytes.Buffer
		e := run(t.Context(), []string{command, "--json", "--data-dir", root, "--profile", "unit", "--api", "http://127.0.0.1:1/custom", "--timeout", "35ms"}, strings.NewReader(""), &out, &errout)
		if !errors.Is(e, context.DeadlineExceeded) {
			t.Fatal(e)
		}
		want := "Provisioning timed out; the stored pending request remains resumable. Run: otgo resume --profile unit --api http://127.0.0.1:1/custom --data-dir '" + strings.ReplaceAll(root, "'", "'\"'\"'") + "'\n"
		if stored && errout.String() != want {
			t.Fatalf("got %q want %q", errout.String(), want)
		}
		if !stored && errout.Len() != 0 {
			t.Fatalf("advertised nonexistent pending: %s", errout.String())
		}
		if out.Len() != 0 || strings.Contains(errout.String(), "secret-") {
			t.Fatal("credentials or stdout contract damaged")
		}
	}
}
