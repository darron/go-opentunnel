package opentunnel

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestForegroundCertificateCooldownPreservesObservedReason(t *testing.T) {
	const reason = "urn:ietf:params:acme:error:dns: foreground-private-marker | HTTP 400"
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	x := manualRefreshConnection(t, c)
	base := f.api.submissions.Load()
	f.api.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certificate") {
			_ = json.NewEncoder(w).Encode(CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: reason}})
			return
		}
		f.api.serve(w, r)
	})
	if err := x.refreshOnce(); err != nil {
		t.Fatalf("establish recovery cooldown: %v", err)
	}

	operations := []struct {
		name string
		run  func() error
	}{
		{name: "Ensure", run: func() error { _, err := c.Ensure(t.Context(), ""); return err }},
		{name: "Resume", run: func() error { _, err := c.Resume(t.Context(), "", ProvisionOptions{}); return err }},
	}
	for _, operation := range operations {
		err := operation.run()
		assertCertificateIssuanceFailure(t, operation.name, err, reason, "dns_error", 400)
	}
	connected, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"api": echoTarget(t)}})
	if err != nil {
		t.Fatalf("Connect with still-valid local certificate: %v", err)
	}
	_ = f.next(t)
	if err := connected.Close(); err != nil {
		t.Fatal(err)
	}
	if got := f.api.submissions.Load() - base; got != 1 {
		t.Fatalf("submitted %d CSRs during one cooldown, want 1", got)
	}
}

func TestResumeAmbiguousBindCooldownReturnsTypedUnknownFailure(t *testing.T) {
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
	_, err := c.Resume(t.Context(), "", ProvisionOptions{})
	assertCertificateIssuanceFailure(t, "Resume", err, "", "unknown", 0)
	if binds.Load() != 1 {
		t.Fatalf("performed %d binds inside cooldown, want 1", binds.Load())
	}
}

func assertCertificateIssuanceFailure(t *testing.T, operation string, err error, reason, code string, statusCode int) {
	t.Helper()
	if !errors.Is(err, ErrCertificateIssuance) {
		t.Fatalf("%s error = %v, want ErrCertificateIssuance", operation, err)
	}
	var failure *CertificateIssuanceError
	if !errors.As(err, &failure) {
		t.Fatalf("%s error type = %T, want *CertificateIssuanceError", operation, err)
	}
	if failure.Reason != reason || failure.Code != code || failure.StatusCode != statusCode {
		t.Fatalf("%s failure = %#v, want reason length %d, code %q, HTTP %d", operation, failure, len(reason), code, statusCode)
	}
	if reason != "" && strings.Contains(err.Error(), "foreground-private-marker") {
		t.Fatalf("%s error exposed raw reason: %v", operation, err)
	}
}
