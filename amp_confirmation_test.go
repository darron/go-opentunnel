package opentunnel

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAmbiguousInitialBindCooldownSurvivesResume(t *testing.T) {
	a := newTestAPI(t)
	var binds atomic.Int32
	a.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/certificate") {
			binds.Add(1)
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"_tag": "ServiceUnavailableError"})
			return
		}
		a.serve(w, r)
	})
	c := testClient(t, a, NewMemoryStorage())
	if _, err := c.Create(t.Context(), "", ProvisionOptions{}); err == nil {
		t.Fatal("ambiguous bind unexpectedly succeeded")
	}
	for range 4 {
		if _, err := c.Resume(t.Context(), "", ProvisionOptions{}); !errors.Is(err, ErrCertificateIssuance) {
			t.Fatalf("Resume: %v", err)
		}
	}
	if binds.Load() != 1 {
		t.Fatalf("%d binds inside cooldown", binds.Load())
	}
	pending, err := c.Pending(t.Context(), "")
	if err != nil || pending == nil || pending.Token == "" || pending.PrivateKey == "" {
		t.Fatal("lost pending recovery credentials")
	}
}

func TestAmbiguousRuntimeBindCooldownSharedByPublicCalls(t *testing.T) {
	f := newRelay(t)
	var failing atomic.Bool
	var binds atomic.Int32
	f.api.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failing.Load() && strings.HasSuffix(r.URL.Path, "/certificate") {
			if r.Method == http.MethodPost {
				binds.Add(1)
				w.WriteHeader(http.StatusServiceUnavailable)
				_ = json.NewEncoder(w).Encode(map[string]string{"_tag": "ServiceUnavailableError"})
			} else {
				_ = json.NewEncoder(w).Encode(CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test failure"}})
			}
			return
		}
		f.api.serve(w, r)
	})
	c := tunnelClient(t, f, TransportOptions{})
	x := connectTest(t, c, Routes{"@": echoTarget(t)})
	_ = f.next(t)
	failing.Store(true)
	if err := x.refreshOnce(); err == nil {
		t.Fatal("ambiguous bind unexpectedly succeeded")
	}
	for range 4 {
		_ = x.refreshOnce()
		if _, err := c.Ensure(t.Context(), ""); !errors.Is(err, ErrCertificateIssuance) {
			t.Fatalf("Ensure: %v", err)
		}
		if _, err := c.Resume(t.Context(), "", ProvisionOptions{}); !errors.Is(err, ErrCertificateIssuance) {
			t.Fatalf("Resume: %v", err)
		}
		connected, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"api": "127.0.0.1:8080"}})
		if err != nil {
			t.Fatalf("Connect with still-valid local certificate: %v", err)
		}
		_ = f.next(t)
		if err := connected.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if binds.Load() != 1 {
		t.Fatalf("%d binds inside shared cooldown", binds.Load())
	}
}

func TestResumeDoesNotRebindActiveIssuance(t *testing.T) {
	a := newTestAPI(t)
	a.hold.Store(true)
	c := testClient(t, a, NewMemoryStorage())
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Millisecond)
	_, err := c.Create(ctx, "", ProvisionOptions{})
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	base := a.submissions.Load()
	for range 3 {
		ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
		_, err := c.Resume(ctx, "", ProvisionOptions{})
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal(err)
		}
	}
	if a.submissions.Load() != base {
		t.Fatal("Resume rebound active issuance")
	}
}

func TestCleanupQueueSaturationClosesSession(t *testing.T) {
	owner := &Connection{ctx: t.Context()}
	s := newSession(owner, nil)
	defer s.cancel()
	for i := range cap(s.controls) {
		s.enqueueControl(controlMessage{Type: "reset", Conn: uint32(i), Code: "client_io_error"})
	}
	if s.ctx.Err() != nil {
		t.Fatal("canceled before saturation")
	}
	s.enqueueControl(controlMessage{Type: "reset", Conn: 100, Code: "client_io_error"})
	if s.ctx.Err() == nil {
		t.Fatal("saturated cleanup queue dropped reset without canceling")
	}
}
