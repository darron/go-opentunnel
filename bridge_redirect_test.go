package opentunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestBridgeRedirectDoesNotReachDifferentTLSOrigin(t *testing.T) {
	var secondRequests atomic.Int32
	second := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		secondRequests.Add(1)
	}))
	defer second.Close()
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, second.URL, http.StatusFound)
	}))
	defer first.Close()

	roots := x509.NewCertPool()
	roots.AddCert(first.Certificate())
	roots.AddCert(second.Certificate())
	api, err := NewAPI(first.URL, &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	x := &Connection{
		client:   &Client{api: api, options: TransportOptions{AttachTimeout: time.Second, MaxConnections: 1}, ctx: context.Background()},
		ctx:      ctx,
		identity: Identity{ID: "demo", Token: "attach-secret-marker"},
	}
	if err := newSession(x, Routes{"@": "127.0.0.1:8080"}).run(); err == nil {
		t.Fatal("bridge redirect succeeded")
	}
	if got := secondRequests.Load(); got != 0 {
		t.Fatalf("cross-origin bridge received %d request(s), so it could receive attach credentials", got)
	}
}
