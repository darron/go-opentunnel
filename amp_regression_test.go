package opentunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestChannelAbortUnblocksQueuedWriteWithoutStoppingSession(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s := &session{ctx: ctx, queue: make(chan outbound, 1), owner: &Connection{client: &Client{options: TransportOptions{WriteTimeout: time.Second}}}}
	b := newBridgeConn(s, 1, "peer", 1024)
	done := make(chan error, 1)
	go func() { _, err := b.Write([]byte("application bytes")); done <- err }()
	deadline := time.Now().Add(time.Second)
	for len(s.queue) == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.queue) == 0 {
		t.Fatal("write was not queued")
	}
	b.abort(ErrIdleTimeout)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("aborted write succeeded")
		}
	case <-time.After(100 * time.Millisecond):
		cancel()
		<-done
		t.Fatal("channel abort did not unblock queued write")
	}
	if ctx.Err() != nil {
		t.Fatal("channel abort stopped the shared session")
	}
}

func TestChannelResetDoesNotWaitBehindFullDataQueue(t *testing.T) {
	owner := &Connection{ctx: t.Context(), client: &Client{options: TransportOptions{WriteTimeout: time.Second}}}
	s := newSession(owner, nil)
	defer s.cancel()
	for range cap(s.queue) {
		s.queue <- outbound{ctx: s.ctx}
	}
	ch := &channel{id: 7, session: s}
	done := make(chan struct{})
	go func() { ch.reset("client_io_error"); close(done) }()
	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		s.cancel()
		<-done
		t.Fatal("reset blocked channel cleanup behind data")
	}
	if s.ctx.Err() != nil {
		t.Fatal("one reset stopped the healthy session")
	}
	select {
	case msg := <-s.controls:
		control, ok := decodeControl(msg.data)
		if !ok || control.Type != "reset" || control.Conn != 7 {
			t.Fatal("reset was not delivered to the cleanup queue")
		}
	default:
		t.Fatal("reset was dropped")
	}
}

func TestWriterDiscardsCanceledSendAndPreservesSharedWebSocket(t *testing.T) {
	received := make(chan []byte, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = ws.CloseNow() }()
		for {
			_, data, err := ws.Read(r.Context())
			if err != nil {
				return
			}
			received <- data
		}
	}))
	defer server.Close()
	ws, resp, err := websocket.Dial(t.Context(), server.URL, nil)
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	if err != nil {
		t.Fatal(err)
	}
	owner := &Connection{ctx: t.Context(), client: &Client{options: TransportOptions{WriteTimeout: time.Second}}}
	s := newSession(owner, nil)
	s.ws = ws
	logical, cancel := context.WithCancel(t.Context())
	cancel()
	result := make(chan error, 1)
	s.queue <- outbound{ctx: logical, kind: websocket.MessageBinary, data: []byte("discard"), result: result}
	done := make(chan struct{})
	go func() { defer close(done); s.writer() }()
	defer func() { s.cancel(); _ = ws.CloseNow(); <-done }()
	if err := s.send(websocket.MessageBinary, []byte("healthy")); err != nil {
		t.Fatal(err)
	}
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled send result: %v", err)
	}
	select {
	case data := <-received:
		if string(data) != "healthy" {
			t.Fatal("canceled payload reached the shared socket")
		}
	case <-time.After(time.Second):
		t.Fatal("healthy send did not reach peer")
	}
	if s.ctx.Err() != nil {
		t.Fatal("discarding one channel's send stopped the session")
	}
}

func TestQueuedSendTimeoutIncludesQueueAdmission(t *testing.T) {
	for _, full := range []bool{false, true} {
		t.Run(map[bool]string{false: "waiting-result", true: "waiting-admission"}[full], func(t *testing.T) {
			owner := &Connection{ctx: t.Context(), client: &Client{options: TransportOptions{WriteTimeout: 30 * time.Millisecond}}}
			s := newSession(owner, nil)
			defer s.cancel()
			if full {
				for range cap(s.queue) {
					s.queue <- outbound{ctx: s.ctx}
				}
			}
			ctx, cancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
			defer cancel()
			start := time.Now()
			if err := s.sendContext(ctx, websocket.MessageBinary, []byte("blocked")); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("queue timeout: %v", err)
			}
			if time.Since(start) >= 200*time.Millisecond || ctx.Err() != nil || s.ctx.Err() != nil {
				t.Fatal("send waited for caller/session cancellation instead of its write timeout")
			}
		})
	}
}

func TestWriteDeadlineUpdateInterruptsPendingChannelSend(t *testing.T) {
	owner := &Connection{ctx: t.Context(), client: &Client{options: TransportOptions{WriteTimeout: time.Second}}}
	s := newSession(owner, nil)
	defer s.cancel()
	b := newBridgeConn(s, 1, "peer", 1024)
	defer func() { _ = b.Close() }()
	done := make(chan error, 1)
	go func() { _, err := b.Write([]byte("blocked")); done <- err }()
	until := time.Now().Add(time.Second)
	for len(s.queue) == 0 && time.Now().Before(until) {
		time.Sleep(time.Millisecond)
	}
	if err := b.SetWriteDeadline(time.Now().Add(10 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("write deadline: %v", err)
		}
	case <-time.After(150 * time.Millisecond):
		_ = b.Close()
		<-done
		t.Fatal("changing write deadline did not affect the pending send")
	}
	if s.ctx.Err() != nil {
		t.Fatal("channel write deadline stopped shared session")
	}
}

func TestForegroundCertificateRecoverySharesRuntimeCooldown(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	x := manualRefreshConnection(t, c)
	base := f.api.submissions.Load()
	f.api.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/certificate") {
			_ = json.NewEncoder(w).Encode(CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test failure"}})
			return
		}
		f.api.serve(w, r)
	})
	if err := x.refreshOnce(); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if _, err := c.Ensure(t.Context(), ""); !errors.Is(err, ErrCertificateIssuance) {
			t.Fatalf("Ensure: %v", err)
		}
		if _, err := c.Resume(t.Context(), "", ProvisionOptions{}); !errors.Is(err, ErrCertificateIssuance) {
			t.Fatalf("Resume: %v", err)
		}
		x, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"api": echoTarget(t)}})
		if err != nil {
			t.Fatalf("Connect with still-valid local certificate: %v", err)
		}
		_ = f.next(t)
		if err := x.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.api.submissions.Load() - base; got != 1 {
		t.Fatalf("submitted %d CSRs during one cooldown, want 1", got)
	}
}

func TestRemoveDuringForegroundIssuanceCannotResurrectProfile(t *testing.T) {
	a := newTestAPI(t)
	c := testClient(t, a, NewMemoryStorage())
	if _, err := c.Create(t.Context(), "", ProvisionOptions{}); err != nil {
		t.Fatal(err)
	}
	a.mu.Lock()
	a.cert = CertificateInfo{ID: "failed", State: CertificateState{Type: "failed", Reason: "test failure"}}
	a.mu.Unlock()
	submitted := make(chan struct{})
	a.onSubmit = func() { a.hold.Store(true); close(submitted) }
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { _, err := c.Ensure(ctx, ""); done <- err }()
	select {
	case <-submitted:
	case <-time.After(time.Second):
		t.Fatal("recovery did not submit")
	}
	removeCtx, removeCancel := context.WithTimeout(t.Context(), 250*time.Millisecond)
	defer removeCancel()
	removeErr := c.Remove(removeCtx, "")
	// A later ready response must not let the foreground worker restore storage.
	a.hold.Store(false)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("removed provisioning operation succeeded")
		}
	case <-time.After(time.Second):
		cancel()
		<-done
		t.Fatal("foreground worker did not notice removal")
	}
	if removeErr != nil {
		t.Fatalf("foreground issuance blocked Remove: %v", removeErr)
	}
	if id, err := c.Get(t.Context(), ""); err != nil || id != nil {
		t.Fatalf("removed identity returned: present=%t err=%v", id != nil, err)
	}
	if pending, err := c.Pending(t.Context(), ""); err != nil || pending != nil {
		t.Fatalf("removed pending identity returned: present=%t err=%v", pending != nil, err)
	}
}

func TestDifferentExpiredRemoteCertificateCanTriggerRenewal(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	old, err := c.Create(t.Context(), "", ProvisionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	local := expiredFixtureCertificate(t, f.api, time.Now().Add(-2*time.Hour))
	remote := expiredFixtureCertificate(t, f.api, time.Now().Add(-time.Hour))
	old.Certificate, old.Chain, old.CertificateExpiry = local.State.Certificate, local.State.Chain, local.State.Expiry
	if err := c.store.Save(t.Context(), "default", *old); err != nil {
		t.Fatal(err)
	}
	f.api.mu.Lock()
	f.api.cert = remote
	f.api.mu.Unlock()
	if _, err := c.Ensure(t.Context(), ""); !errors.Is(err, ErrCertificateExpired) {
		t.Fatalf("Ensure accepted expired replacement: %v", err)
	}
	f.api.bridge = func(w http.ResponseWriter, r *http.Request) {
		f.api.mu.Lock()
		renewed, issueErr := f.api.authority.issue(f.api.csr, 91)
		if issueErr == nil {
			f.api.cert = renewed
		}
		f.api.mu.Unlock()
		if issueErr != nil {
			t.Error(issueErr)
		}
		f.accept(w, r)
	}
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	x, err := c.Connect(ctx, ConnectOptions{Routes: Routes{"@": echoTarget(t)}})
	if err != nil {
		t.Fatalf("attachment could not trigger renewal: %v", err)
	}
	if _, err := parseCertificate(x.Identity()); err != nil {
		t.Fatalf("Connect returned without a valid replacement: %v", err)
	}
	_ = x.Close()
}

func TestCancellationAfterRemoteCreatePreservesPendingCredentials(t *testing.T) {
	a := newTestAPI(t)
	c := testClient(t, a, NewMemoryStorage())
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	_, err := c.Create(ctx, "", ProvisionOptions{OnProgress: func(stage ProvisionStage) {
		if stage == StageGeneratingKey {
			cancel()
		}
	}})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Create: %v", err)
	}
	pending, err := c.Pending(t.Context(), "")
	if err != nil || pending == nil || pending.Token == "" || pending.PrivateKey == "" {
		t.Fatalf("successful creation lost credentials: present=%t err=%v", pending != nil, err)
	}
	if err := c.Remove(t.Context(), ""); err != nil {
		t.Fatalf("could not remove canceled creation: %v", err)
	}
}

type pendingSaveFailure struct{ Storage }

func (s pendingSaveFailure) SavePending(context.Context, string, PendingIdentity) error {
	return errors.New("test pending persistence failed")
}

func TestPendingPersistenceFailureCompensatesOrReturnsRecoveryCredentials(t *testing.T) {
	for _, deleteFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "deleted", true: "recoverable"}[deleteFails], func(t *testing.T) {
			a := newTestAPI(t)
			a.deleteFail.Store(deleteFails)
			var deletes atomic.Int32
			a.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deletes.Add(1)
				}
				a.serve(w, r)
			})
			c := testClient(t, a, pendingSaveFailure{NewMemoryStorage()})
			_, err := c.Create(t.Context(), "", ProvisionOptions{})
			if err == nil || deletes.Load() != 1 || a.submissions.Load() != 0 {
				t.Fatalf("failed persistence left creation uncompensated: err=%v deletes=%d submissions=%d", err, deletes.Load(), a.submissions.Load())
			}
			if deleteFails {
				var recovery interface{ RecoveryIdentity() PendingIdentity }
				if !errors.As(err, &recovery) {
					t.Fatal("persistence and deletion failures lost the known credentials")
				}
				pending := recovery.RecoveryIdentity()
				if pending.ID != "demo" || pending.Token != a.token || pending.PrivateKey == "" || pending.CSR == "" {
					t.Fatal("incomplete recovery credentials")
				}
				if strings.Contains(err.Error(), a.token) || strings.Contains(err.Error(), "PRIVATE KEY") {
					t.Fatal("recovery error printed credentials")
				}
				a.deleteFail.Store(false)
				if err := c.API().Remove(t.Context(), pending.ID, pending.Token); err != nil {
					t.Fatalf("returned credentials could not delete creation: %v", err)
				}
			}
		})
	}
}

func TestMalformedKnownCreationIsCompensated(t *testing.T) {
	for _, badState := range []bool{false, true} {
		t.Run(map[bool]string{false: "invalid-hostname", true: "invalid-state"}[badState], func(t *testing.T) {
			a := newTestAPI(t)
			if badState {
				a.info.State = "invalid-state"
			} else {
				a.info.Hostname = "/invalid-hostname"
			}
			var deletes atomic.Int32
			a.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodDelete {
					deletes.Add(1)
				}
				a.serve(w, r)
			})
			c := testClient(t, a, NewMemoryStorage())
			if _, err := c.Create(t.Context(), "", ProvisionOptions{}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("malformed creation: %v", err)
			}
			if a.creates.Load() != 1 || deletes.Load() != 1 {
				t.Fatalf("known credentials were lost: creations=%d deletions=%d", a.creates.Load(), deletes.Load())
			}
		})
	}
}

func TestTinyInboundFragmentsHaveBoundedAllocationAndPreserveBytes(t *testing.T) {
	const size = 64 * 1024
	b := newBridgeConn(nil, 1, "peer", size)
	for i := range size {
		if !b.push([]byte{byte(i)}) {
			t.Fatal("tiny fragments exhausted payload capacity")
		}
	}
	allocated := 24 * cap(b.chunks) // slice headers on the supported 64-bit targets
	for _, chunk := range b.chunks {
		allocated += cap(chunk)
	}
	if allocated > 2*size {
		t.Fatalf("%d payload bytes retained at least %d allocated bytes", size, allocated)
	}
	if b.push([]byte{1}) {
		t.Fatal("accepted payload beyond the byte limit")
	}
	b.endInbound()
	got, err := io.ReadAll(b)
	if err != nil || len(got) != size {
		t.Fatalf("read: bytes=%d err=%v", len(got), err)
	}
	for i, value := range got {
		if value != byte(i) {
			t.Fatalf("fragment reordering at %d", i)
		}
	}
}

func TestAPIErrorTagCannotReflectCredential(t *testing.T) {
	a := newTestAPI(t)
	a.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"_tag": r.Header.Get("Authorization")})
	})
	api, err := NewAPI(a.server.URL, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Get(t.Context(), "demo", "review-secret-marker")
	if err == nil || strings.Contains(err.Error(), "review-secret-marker") {
		t.Fatalf("credential reflected into error: %v", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatal("missing structured API error")
	}
	encoded, err := json.Marshal(apiErr)
	if err != nil || bytes.Contains(encoded, []byte("review-secret-marker")) {
		t.Fatal("structured API error retained a reflected credential")
	}
}

func TestRecognizedAPITagsRemainAvailableToCallers(t *testing.T) {
	for _, tag := range []string{"InvalidRequestError", "UnauthorizedError", "TunnelNotFoundError", "CertificateNotFoundError", "InvalidHostnameError", "HostnameUnavailableError", "CertificateInProgressError", "ServiceUnavailableError"} {
		t.Run(tag, func(t *testing.T) {
			a := newTestAPI(t)
			a.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]string{"_tag": tag})
			})
			api, err := NewAPI(a.server.URL, nil, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			_, err = api.Get(t.Context(), "demo", "token")
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.Tag != tag {
				t.Fatalf("recognized tag lost: %v", err)
			}
		})
	}
}

func TestAttachErrorCodeCannotReflectCredential(t *testing.T) {
	f := newRelay(t)
	f.attachCode = "Bearer " + f.api.token
	c := tunnelClient(t, f, TransportOptions{})
	id, err := c.Create(t.Context(), "", ProvisionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	owner := &Connection{client: c, ctx: t.Context(), identity: *id}
	s := newSession(owner, Routes{"@": "127.0.0.1:8080"})
	err = s.run()
	var attach *AttachError
	if !errors.As(err, &attach) || attach.Code != "unknown" || strings.Contains(err.Error(), f.api.token) {
		t.Fatalf("credential reflected by attachment error: %v", err)
	}
}
