package opentunnel

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicURLAndRouteNames(t *testing.T) {
	for _, route := range []string{RootRoute, "api", "a", strings.Repeat("a", 63)} {
		if !IsValidRouteName(route) {
			t.Fatalf("valid route rejected: %q", route)
		}
	}
	for _, route := range []string{"", "API", "-api", "api-", "api.x", strings.Repeat("a", 64), "api\n"} {
		if IsValidRouteName(route) {
			t.Fatalf("invalid route accepted: %q", route)
		}
		if _, err := PublicURL(route, "demo.test"); !errors.Is(err, ErrInvalid) {
			t.Fatalf("route %q: %v", route, err)
		}
	}
	for _, host := range []string{"", "https://demo.test", "demo.test/path", "demo.test:443", "user@demo.test", "demo.test?x", "demo.test#x", "demo.test\n", "demo..test", "-demo.test", "demo_test", "K.test", "demo.test.", strings.Repeat("a", 64) + ".test"} {
		if _, err := PublicURL("api", host); !errors.Is(err, ErrInvalid) {
			t.Fatalf("hostname %q: %v", host, err)
		}
	}
	for route, want := range map[string]string{"@": "https://demo.test", "api": "https://api.demo.test"} {
		got, err := PublicURL(route, "demo.test")
		if err != nil || got != want {
			t.Fatalf("PublicURL(%q) = %q, %v", route, got, err)
		}
	}
	longHost := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if _, err := PublicURL(RootRoute, longHost); err != nil {
		t.Fatal(err)
	}
	if _, err := PublicURL("api", longHost); !errors.Is(err, ErrInvalid) {
		t.Fatalf("combined hostname length: %v", err)
	}
}

func TestConnectionURLSnapshots(t *testing.T) {
	f := newRelay(t)
	x := connectTest(t, tunnelClient(t, f, TransportOptions{}), Routes{"@": echoTarget(t)})
	f.next(t)
	urls := x.URLs()
	if urls["@"] != "https://demo.test" {
		t.Fatal(urls)
	}
	urls["@"] = "caller mutation"
	if x.URLs()["@"] != "https://demo.test" {
		t.Fatal("URL map aliases connection")
	}
	if err := x.SetRoutes(Routes{"api": "127.0.0.1:9"}); err != nil {
		t.Fatal(err)
	}
	if got := x.URLs(); !reflect.DeepEqual(got, map[string]string{"api": "https://api.demo.test"}) {
		t.Fatal(got)
	}
	if err := x.SetRoutes(nil); err != nil || len(x.URLs()) != 0 {
		t.Fatalf("paused URLs: %v, %v", x.URLs(), err)
	}
}

func TestRouteConflictPoliciesAndStartupEvents(t *testing.T) {
	for _, listener := range []bool{false, true} {
		for _, policy := range []RouteConflictPolicy{"", RouteConflictRetry, RouteConflictFail} {
			t.Run(string(policy)+"/listener="+map[bool]string{false: "false", true: "true"}[listener], func(t *testing.T) {
				f := newRelay(t)
				f.attachCode = "route_conflict"
				c := tunnelClient(t, f, TransportOptions{BackoffMin: time.Millisecond, BackoffMax: time.Millisecond})
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var events []string
				conflicts := 0
				observe := func(e Event) {
					events = append(events, e.Type)
					if e.Type == "route-conflict" {
						conflicts++
						if !reflect.DeepEqual(e.Routes, []string{"@", "api"}) {
							t.Errorf("conflict routes: %v", e.Routes)
						}
						if policy != RouteConflictFail && conflicts == 2 {
							cancel()
							return
						}
					}
				}
				var err error
				if listener {
					_, err = c.Listen(ctx, ListenOptions{Routes: []string{"api", "@"}, OnRouteConflict: policy, OnEvent: observe})
				} else {
					_, err = c.Connect(ctx, ConnectOptions{Routes: Routes{"api": "127.0.0.1:9", "@": "127.0.0.1:9"}, OnRouteConflict: policy, OnEvent: observe})
				}
				if policy == RouteConflictFail {
					var attach *AttachError
					if !errors.As(err, &attach) || attach.Code != "route_conflict" || conflicts != 1 {
						t.Fatalf("fail policy: conflicts=%d, err=%v", conflicts, err)
					}
				} else if !errors.Is(err, context.Canceled) || conflicts != 2 {
					t.Fatalf("retry policy: conflicts=%d, err=%v", conflicts, err)
				}
				if len(events) == 0 || events[0] != "connecting" || events[len(events)-1] != "stopped" {
					t.Fatal(events)
				}
				f.mu.Lock()
				f.attachCode = ""
				f.mu.Unlock()
				// A failed startup must release its route claims and join callbacks.
				x := connectTest(t, c, Routes{"api": "127.0.0.1:9"})
				if x.Status().State != "connected" {
					t.Fatal(x.Status())
				}
			})
		}
	}
}

func TestRouteConflictAfterReconnect(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{BackoffMin: time.Millisecond, BackoffMax: time.Millisecond})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	x, err := c.Connect(ctx, ConnectOptions{Routes: Routes{"api": "127.0.0.1:9"}, OnRouteConflict: RouteConflictFail})
	if err != nil {
		t.Fatal(err)
	}
	s := f.next(t)
	f.mu.Lock()
	f.attachCode = "route_conflict"
	f.mu.Unlock()
	s.close()
	select {
	case <-x.Done():
	case <-ctx.Done():
		t.Fatal("conflict did not stop reconnect")
	}
	var attach *AttachError
	if !errors.As(x.Err(), &attach) || attach.Code != "route_conflict" {
		t.Fatal(x.Err())
	}
}

func TestInvalidConflictPolicyBeforeProvisioning(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	_, err := c.Connect(context.Background(), ConnectOptions{Routes: Routes{"@": "127.0.0.1:9"}, OnRouteConflict: "unknown"})
	if !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	_, err = c.Listen(context.Background(), ListenOptions{Routes: []string{"@"}, OnRouteConflict: "unknown"})
	if !errors.Is(err, ErrInvalid) || f.api.creates.Load() != 0 {
		t.Fatalf("invalid option caused provisioning: %v, creates=%d", err, f.api.creates.Load())
	}
}

func TestEventObserverIsolationAndSerialization(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{EventBuffer: 1})
	var active atomic.Int32
	var seen atomic.Int32
	x := &Connection{client: c, events: make(chan Event, 1), routes: Routes{}, onEvent: func(e Event) {
		if active.Add(1) != 1 {
			t.Error("concurrent observer callbacks")
		}
		seen.Add(1)
		if len(e.Routes) != 0 {
			e.Routes[0] = "changed"
		}
		active.Add(-1)
	}}
	// Status is safe inside the observer: it must not run under the state lock.
	original := x.onEvent
	x.onEvent = func(e Event) { _ = x.Status(); original(e) }
	routes := []string{"api"}
	x.emit(Event{Type: "connected", Routes: routes})
	if e := <-x.events; e.Routes[0] != "api" || routes[0] != "api" {
		t.Fatal("observer mutated buffered event or source routes")
	}
	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() { x.emit(Event{Type: "test"}) })
	}
	wg.Wait()
	if seen.Load() != 21 || x.Status().DroppedEvents != 19 {
		t.Fatalf("observer should receive events lost by channel: seen=%d dropped=%d", seen.Load(), x.Status().DroppedEvents)
	}
}

func TestEnsureProgress(t *testing.T) {
	a := newTestAPI(t)
	c := testClient(t, a, NewMemoryStorage())
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var stages []ProvisionStage
	o := ProvisionOptions{OnProgress: func(s ProvisionStage) { stages = append(stages, s) }}
	if _, err := c.EnsureWithOptions(ctx, "", o); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stages, []ProvisionStage{StageCreatingTunnel, StageGeneratingKey, StageGeneratingCSR, StageWaitingCertificate, StageRequestingCertificate, StageWaitingCertificate, StageSavingIdentity, StageReady}) {
		t.Fatal(stages)
	}
	stages = nil
	if _, err := c.EnsureWithOptions(ctx, "", o); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stages, []ProvisionStage{StageCheckingCertificate, StageReady}) {
		t.Fatal(stages)
	}
	// A changed remote certificate must be stored before reporting readiness.
	a.mu.Lock()
	replacement, err := a.authority.issue(a.csr, 42)
	if err != nil {
		a.mu.Unlock()
		t.Fatal(err)
	}
	a.cert = replacement
	a.mu.Unlock()
	stages = nil
	id, err := c.EnsureWithOptions(ctx, "", o)
	if err != nil {
		t.Fatal(err)
	}
	stored, err := c.Get(ctx, "")
	if err != nil || stored == nil || stored.Certificate != replacement.State.Certificate || id.Certificate != stored.Certificate {
		t.Fatalf("replacement not persisted: %v", err)
	}
	if !reflect.DeepEqual(stages, []ProvisionStage{StageCheckingCertificate, StageSavingIdentity, StageReady}) {
		t.Fatal(stages)
	}
	stages = nil
	a.mu.Lock()
	a.cert = CertificateInfo{ID: "test-certificate", State: CertificateState{Type: "failed", Reason: "test failure"}}
	a.mu.Unlock()
	if _, err := c.EnsureWithOptions(ctx, "", o); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(stages, []ProvisionStage{StageCheckingCertificate, StageGeneratingCSR, StageRequestingCertificate, StageWaitingCertificate, StageSavingIdentity, StageReady}) {
		t.Fatal(stages)
	}
	stages = nil
	canceled, stop := context.WithCancel(ctx)
	stop()
	if _, err := c.EnsureWithOptions(canceled, "", o); err == nil {
		t.Fatal("canceled ensure succeeded")
	}
	for _, stage := range stages {
		if stage == StageReady {
			t.Fatal("failed operation reported ready")
		}
	}
}

func TestListenerURLsAndObserverShutdown(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	stopping, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	startup, stop := context.WithTimeout(context.Background(), 5*time.Second)
	defer stop()
	l, err := c.Listen(startup, ListenOptions{Routes: []string{"@"}, Lifetime: ctx, OnEvent: func(e Event) {
		if e.Type == "stopped" {
			close(stopping)
			<-release
		}
	}})
	if err != nil {
		t.Fatal(err)
	}
	if l.URLs()["@"] != "https://demo.test" {
		t.Fatal(l.URLs())
	}
	if err := l.SetRoutes([]string{"api"}); err != nil || l.URLs()["api"] != "https://api.demo.test" || len(l.URLs()) != 1 {
		t.Fatalf("listener update URLs: %v, %v", l.URLs(), err)
	}
	cancel()
	select {
	case <-stopping:
	case <-startup.Done():
		t.Fatal("no stopped callback")
	}
	select {
	case <-l.Done():
		t.Fatal("Done closed before observer returned")
	default:
	}
	once.Do(func() { close(release) })
	select {
	case <-l.Done():
	case <-startup.Done():
		t.Fatal("shutdown did not join observer")
	}
}
