package opentunnel

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestClientCompleteReturnsTypedTerminalCertificateFailure(t *testing.T) {
	const reason = "urn:ietf:params:acme:error:rateLimited: account marker-sensitive; HTTP 429"
	a := newTestAPI(t)
	a.hold.Store(true)
	submitted := make(chan struct{})
	a.onSubmit = func() { close(submitted) }
	c := testClient(t, a, NewMemoryStorage())

	done := make(chan error, 1)
	go func() {
		_, err := c.Create(context.Background(), "", ProvisionOptions{})
		done <- err
	}()
	<-submitted
	deadline := time.Now().Add(time.Second)
	for {
		a.mu.Lock()
		if a.csr != "" {
			a.cert.State = CertificateState{Type: "failed", Reason: reason}
			a.mu.Unlock()
			break
		}
		a.mu.Unlock()
		if time.Now().After(deadline) {
			t.Fatal("certificate submission was not recorded")
		}
		time.Sleep(time.Millisecond)
	}
	a.hold.Store(false)

	var err error
	select {
	case err = <-done:
	case <-time.After(time.Second):
		t.Fatal("Create did not observe terminal certificate failure")
	}
	if !errors.Is(err, ErrCertificateIssuance) {
		t.Fatalf("Create error = %v, want ErrCertificateIssuance", err)
	}
	var issuance *CertificateIssuanceError
	if !errors.As(err, &issuance) {
		t.Fatalf("Create error type = %T, want *CertificateIssuanceError", err)
	}
	if issuance.Reason != reason || issuance.Code != "rate_limited" || issuance.StatusCode != 429 {
		t.Fatalf("typed failure = %#v", issuance)
	}
	if strings.Contains(err.Error(), "marker-sensitive") {
		t.Fatalf("Error exposed raw reason: %s", err)
	}
}
