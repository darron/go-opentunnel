package opentunnel

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCertificateRefreshRetainsFailureReasonDuringCooldown(t *testing.T) {
	const reason = "urn:ietf:params:acme:error:dns: private-sensitive-marker | HTTP 400"
	f := newRelay(t)
	var failed atomic.Bool
	f.api.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if failed.Load() && r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certificate") {
			_ = json.NewEncoder(w).Encode(CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: reason}})
			return
		}
		f.api.serve(w, r)
	})
	c := tunnelClient(t, f, TransportOptions{})
	x := manualRefreshConnection(t, c)
	failed.Store(true)
	if err := x.refreshOnce(); err != nil {
		t.Fatalf("initial recovery: %v", err)
	}
	before := f.api.submissions.Load()
	err := x.refreshOnce()
	var failure *CertificateIssuanceError
	if !errors.Is(err, ErrCertificateIssuance) || !errors.As(err, &failure) {
		t.Fatalf("untyped cooldown failure: %v", err)
	}
	if failure.Reason != reason || failure.Code != "dns_error" || failure.StatusCode != 400 {
		t.Fatal("cooldown lost provider details")
	}
	if strings.Contains(err.Error(), "private-sensitive-marker") {
		t.Fatal("cooldown leaked reason")
	}
	if f.api.submissions.Load() != before {
		t.Fatal("diagnostics bypassed retry cooldown")
	}
}
