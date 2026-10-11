package opentunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// testAuthority generates keys at runtime; no working credentials are committed.
type testAuthority struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	roots *x509.CertPool
}

func newTestAuthority(t *testing.T) *testAuthority {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(365 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	b, err := x509.CreateCertificate(rand.Reader, template, template, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(b)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	return &testAuthority{cert, k, roots}
}
func (a *testAuthority) issue(csrPEM string, serial int64) (CertificateInfo, error) {
	b, _ := pem.Decode([]byte(csrPEM))
	if b == nil {
		return CertificateInfo{}, errors.New("missing CSR")
	}
	csr, err := x509.ParseCertificateRequest(b.Bytes)
	if err != nil {
		return CertificateInfo{}, err
	}
	if err = csr.CheckSignature(); err != nil {
		return CertificateInfo{}, err
	}
	expiry := time.Now().UTC().Add(100 * 24 * time.Hour).Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: csr.Subject, DNSNames: csr.DNSNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, a.cert, csr.PublicKey, a.key)
	if err != nil {
		return CertificateInfo{}, err
	}
	return CertificateInfo{ID: "test-certificate", State: CertificateState{Type: "ready", Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), Chain: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.cert.Raw})), Expiry: expiry}}, nil
}

type testAPI struct {
	t           *testing.T
	authority   *testAuthority
	server      *httptest.Server
	mu          sync.Mutex
	cert        CertificateInfo
	csr         string
	token       string
	info        TunnelInfo
	creates     atomic.Int32
	submissions atomic.Int32
	hold        atomic.Bool
	deleteFail  atomic.Bool
	bridge      func(http.ResponseWriter, *http.Request)
	onSubmit    func()
}

func newTestAPI(t *testing.T) *testAPI {
	t.Helper()
	a := &testAPI{t: t, authority: newTestAuthority(t), token: "generated-test-token", info: TunnelInfo{ID: "demo", Hostname: "demo.test", State: "offline"}}
	a.server = httptest.NewServer(http.HandlerFunc(a.serve))
	t.Cleanup(a.server.Close)
	return a
}
func (a *testAPI) serve(w http.ResponseWriter, r *http.Request) {
	if strings.HasSuffix(r.URL.Path, "/connect") {
		a.mu.Lock()
		bridge := a.bridge
		a.mu.Unlock()
		if bridge != nil {
			bridge(w, r)
			return
		}
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Path == "/api/tunnel" && r.Method == "POST" {
		a.creates.Add(1)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(CreateTunnelResponse{a.info, a.token})
		return
	}
	if r.Header.Get("Authorization") != "Bearer "+a.token {
		w.WriteHeader(401)
		_, _ = io.WriteString(w, `{"_tag":"UnauthorizedError","message":"unauthorized"}`)
		return
	}
	if r.URL.Path == "/api/tunnel/demo" {
		if r.Method == "DELETE" {
			if a.deleteFail.Load() {
				w.WriteHeader(503)
				_, _ = io.WriteString(w, `{"_tag":"ServiceUnavailableError","message":"try later"}`)
			} else {
				w.WriteHeader(204)
			}
			return
		}
		_ = json.NewEncoder(w).Encode(a.info)
		return
	}
	if r.URL.Path != "/api/tunnel/demo/certificate" {
		http.NotFound(w, r)
		return
	}
	if r.Method == "POST" {
		a.submissions.Add(1)
		if a.onSubmit != nil {
			a.onSubmit()
		}
		var b struct {
			CSR string `json:"csr"`
		}
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			w.WriteHeader(400)
			return
		}
		a.mu.Lock()
		defer a.mu.Unlock()
		if a.csr != "" && a.cert.State.Type != "failed" {
			w.WriteHeader(409)
			_, _ = io.WriteString(w, `{"_tag":"CertificateInProgressError","message":"already issuing"}`)
			return
		}
		cert, err := a.authority.issue(b.CSR, 2)
		if err != nil {
			a.t.Errorf("issue: %v", err)
			w.WriteHeader(400)
			return
		}
		a.csr = b.CSR
		a.cert = cert
		w.WriteHeader(202)
		_ = json.NewEncoder(w).Encode(CertificateInfo{ID: "test-certificate", State: CertificateState{Type: "issuing"}})
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.csr == "" {
		w.WriteHeader(404)
		_, _ = io.WriteString(w, `{"_tag":"CertificateNotFoundError","message":"absent"}`)
		return
	}
	if a.hold.Load() {
		_ = json.NewEncoder(w).Encode(CertificateInfo{ID: "test-certificate", State: CertificateState{Type: "issuing"}})
		return
	}
	_ = json.NewEncoder(w).Encode(a.cert)
}
func testClient(t *testing.T, a *testAPI, s Storage) *Client {
	t.Helper()
	c, err := NewClient(ClientOptions{API: a.server.URL, Storage: s, Transport: TransportOptions{CertificatePollInterval: 5 * time.Millisecond}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestClientProvisionResumeAndRemove(t *testing.T) {
	a := newTestAPI(t)
	s := NewMemoryStorage()
	c := testClient(t, a, s)
	ctx := context.Background()
	a.onSubmit = func() {
		p, e := s.LoadPending(ctx, "default")
		if e != nil || p == nil {
			t.Errorf("CSR submitted before persistence: %v", e)
		}
	}
	a.hold.Store(true)
	deadline, cancel := context.WithTimeout(ctx, 40*time.Millisecond)
	defer cancel()
	_, err := c.Create(deadline, "", ProvisionOptions{})
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("create: %v", err)
	}
	p, err := c.Pending(ctx, "")
	if err != nil || p == nil {
		t.Fatalf("pending: %v", err)
	}
	a.hold.Store(false)
	var stages []ProvisionStage
	id, err := c.Resume(ctx, "", ProvisionOptions{OnProgress: func(s ProvisionStage) { stages = append(stages, s) }})
	if err != nil {
		t.Fatal(err)
	}
	if id.ID != "demo" || a.creates.Load() != 1 || len(stages) == 0 || stages[len(stages)-1] != StageReady {
		t.Fatal("resume did not reuse identity")
	}
	if p, e := c.Pending(ctx, ""); e != nil || p != nil {
		t.Fatalf("pending not cleared: %v", e)
	}
	if _, e := c.Create(ctx, "", ProvisionOptions{}); !errors.Is(e, ErrExists) {
		t.Fatalf("overwrite: %v", e)
	}
	a.deleteFail.Store(true)
	if e := c.Remove(ctx, ""); e == nil {
		t.Fatal("delete failure ignored")
	}
	if id, e := c.Get(ctx, ""); e != nil || id == nil {
		t.Fatal("failed delete lost credentials")
	}
	a.deleteFail.Store(false)
	if e := c.Remove(ctx, ""); e != nil {
		t.Fatal(e)
	}
	if id, e := c.Get(ctx, ""); e != nil || id != nil {
		t.Fatal("delete retained identity")
	}
}
func TestClientEnsureConcurrentAndClose(t *testing.T) {
	a := newTestAPI(t)
	c := testClient(t, a, NewMemoryStorage())
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, e := c.Ensure(context.Background(), "default"); e != nil {
				t.Errorf("ensure: %v", e)
			}
		}()
	}
	wg.Wait()
	if a.creates.Load() != 1 {
		t.Fatalf("created %d", a.creates.Load())
	}
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	if _, e := c.Get(context.Background(), ""); !errors.Is(e, ErrClosed) {
		t.Fatalf("closed get: %v", e)
	}
}
func TestClientCloseCancelsProvision(t *testing.T) {
	a := newTestAPI(t)
	a.hold.Store(true)
	c := testClient(t, a, NewMemoryStorage())
	started := make(chan struct{})
	a.onSubmit = func() { close(started) }
	done := make(chan error, 1)
	go func() { _, e := c.Ensure(context.Background(), ""); done <- e }()
	<-started
	if e := c.Close(); e != nil {
		t.Fatal(e)
	}
	select {
	case e := <-done:
		if !errors.Is(e, context.Canceled) {
			t.Fatalf("cancel: %v", e)
		}
	case <-time.After(time.Second):
		t.Fatal("close leaked provisioning")
	}
}
func TestClientRemovePending(t *testing.T) {
	a := newTestAPI(t)
	a.hold.Store(true)
	c := testClient(t, a, NewMemoryStorage())
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	_, _ = c.Ensure(ctx, "")
	if e := c.Remove(context.Background(), ""); e != nil {
		t.Fatal(e)
	}
	p, e := c.Pending(context.Background(), "")
	if e != nil || p != nil {
		t.Fatal("pending credentials retained")
	}
}
func TestClientInputBeforeSideEffects(t *testing.T) {
	a := newTestAPI(t)
	c := testClient(t, a, NewMemoryStorage())
	if _, e := c.Ensure(context.Background(), "../bad"); e == nil {
		t.Fatal("invalid profile accepted")
	}
	if _, e := c.Connect(context.Background(), ConnectOptions{Routes: Routes{"api": "http://localhost:80"}}); e == nil {
		t.Fatal("invalid routes accepted")
	}
	if _, e := c.Connect(context.Background(), ConnectOptions{}); e == nil {
		t.Fatal("empty routes accepted")
	}
	if a.creates.Load() != 0 {
		t.Fatal("invalid input created remote tunnel")
	}
}

func TestClientFailedIssuanceReusesKey(t *testing.T) {
	a := newTestAPI(t)
	c := testClient(t, a, NewMemoryStorage())
	ctx := context.Background()
	original, e := c.Ensure(ctx, "")
	if e != nil {
		t.Fatal(e)
	}
	a.mu.Lock()
	a.cert.State = CertificateState{Type: "failed", Reason: "test failure"}
	a.mu.Unlock()
	reissued, e := c.Ensure(ctx, "")
	if e != nil {
		t.Fatal(e)
	}
	if reissued.ID != original.ID || reissued.PrivateKey != original.PrivateKey {
		t.Fatal("failed issuance rotated the local key")
	}
}

type cancelAtRemovalStore struct {
	Storage
	cancel context.CancelFunc
}

func (s *cancelAtRemovalStore) Remove(ctx context.Context, p string) error {
	s.cancel()
	return s.Storage.Remove(ctx, p)
}
func TestClientConfirmedDeletionReconcilesAfterCancellation(t *testing.T) {
	a := newTestAPI(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store := &cancelAtRemovalStore{Storage: NewMemoryStorage(), cancel: cancel}
	c := testClient(t, a, store)
	if _, e := c.Ensure(ctx, ""); e != nil {
		t.Fatal(e)
	}
	if e := c.Remove(ctx, ""); e != nil {
		t.Fatalf("confirmed deletion skipped reconciliation: %v", e)
	}
	if id, e := store.Load(context.Background(), "default"); e != nil || id != nil {
		t.Fatal("stale deleted identity retained")
	}
}
