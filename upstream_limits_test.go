package opentunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func routeLimitFixture(count int) (Routes, []string) {
	routes, names := make(Routes, count), make([]string, 0, count)
	for i := range count {
		name := fmt.Sprintf("route-%d", i)
		routes[name] = "127.0.0.1:8080"
		names = append(names, name)
	}
	return routes, names
}

func TestRouteLimitBeforeProvisioning(t *testing.T) {
	allowed, names := routeLimitFixture(128)
	if err := ValidateRoutes(allowed); err != nil {
		t.Fatalf("128 routes rejected: %v", err)
	}
	if _, err := listenerRoutes(names); err != nil {
		t.Fatalf("128 listener routes rejected: %v", err)
	}
	tooMany, names := routeLimitFixture(129)
	if err := ValidateRoutes(tooMany); !errors.Is(err, ErrInvalid) {
		t.Errorf("129 routes: %v, want ErrInvalid", err)
	}
	for _, mode := range []string{"connect", "listen"} {
		t.Run(mode, func(t *testing.T) {
			api := newTestAPI(t)
			client := testClient(t, api, NewMemoryStorage())
			ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancel()
			var err error
			if mode == "connect" {
				_, err = client.Connect(ctx, ConnectOptions{Routes: tooMany})
			} else {
				_, err = client.Listen(ctx, ListenOptions{Routes: names})
			}
			if !errors.Is(err, ErrInvalid) {
				t.Errorf("129 routes: %v, want ErrInvalid", err)
			}
			if got := api.creates.Load(); got != 0 {
				t.Errorf("invalid route set provisioned %d tunnels", got)
			}
		})
	}
}

func TestOversizedRouteUpdatePreservesExistingConnection(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	_ = f.next(t)
	tooMany, _ := routeLimitFixture(129)
	if err := x.SetRoutes(tooMany); !errors.Is(err, ErrInvalid) {
		t.Fatalf("oversized update: %v, want ErrInvalid", err)
	}
	if routes := x.Status().Routes; len(routes) != 1 || routes["api"] == "" {
		t.Fatalf("invalid update replaced existing routes: %v", routes)
	}
}

func TestTooManyRoutesDiagnosticAndRecovery(t *testing.T) {
	f := newRelay(t)
	var attempts atomic.Int32
	f.api.bridge = func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.attachCode = ""
		if attempts.Add(1) == 1 {
			f.attachCode = "too_many_routes"
		}
		f.mu.Unlock()
		f.accept(w, r)
	}
	c := tunnelClient(t, f, TransportOptions{BackoffMin: time.Millisecond, BackoffMax: 5 * time.Millisecond})
	x := connectTest(t, c, Routes{"api": echoTarget(t)})
	if attempts.Load() < 2 {
		t.Fatal("temporary route limit was not retried")
	}
	event := nextEventType(t, x.Events(), "disconnected")
	if event.Reason != `opentunnel: attach failed: "too_many_routes"` {
		t.Fatalf("route limit diagnostic: %q", event.Reason)
	}
	if x.Status().State != "connected" {
		t.Fatal("route limit became a fatal attachment failure")
	}
}

func TestAdmissionLimitRetriesAndSafeDiagnostics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		tag    string
	}{
		{"rate limit", 429, "RateLimitedError"},
		{"issuance backlog", 503, "ServiceUnavailableError"},
	} {
		for _, operation := range []string{"create", "bind"} {
			t.Run(tc.name+"/"+operation, func(t *testing.T) {
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(tc.status)
					_, _ = fmt.Fprintf(w, `{"_tag":%q,"message":"private-token"}`, tc.tag)
				}))
				t.Cleanup(server.Close)
				api, err := NewAPI(server.URL, nil, time.Second)
				if err != nil {
					t.Fatal(err)
				}
				if operation == "create" {
					_, err = api.Create(t.Context())
				} else {
					_, err = api.BindCertificate(t.Context(), "demo", "private-token", "fixture-csr")
				}
				var remote *APIError
				if !errors.As(err, &remote) || remote.StatusCode != tc.status || remote.Tag != tc.tag {
					t.Fatalf("admission error: %v", err)
				}
				if calls.Load() != 7 {
					t.Fatalf("requests = %d, want initial attempt and six retries", calls.Load())
				}
				if strings.Contains(err.Error(), "private-token") {
					t.Fatalf("remote response leaked into diagnostic: %v", err)
				}
			})
		}
	}
}
