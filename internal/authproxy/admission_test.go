package authproxy

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProxyAdmissionLimitRejectsOverflowAndRecovers exercises the Handler's
// active-request admission limit. Every admitted request is authenticated and
// reaches a real upstream handler that remains blocked until the test releases
// it; an overflow must therefore be rejected before the upstream is called.
func TestProxyAdmissionLimitRejectsOverflowAndRecovers(t *testing.T) {
	const limit = 256

	var calls atomic.Int32
	started := make(chan int, limit+1)
	release := make([]chan struct{}, limit+1)
	for i := range release {
		release[i] = make(chan struct{})
	}
	releaseOnce := make([]sync.Once, len(release))
	releaseGate := func(id int) {
		releaseOnce[id].Do(func() { close(release[id]) })
	}
	releaseAll := func() {
		for id := range release {
			releaseGate(id)
		}
	}

	h, sessions, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var id int
		if _, err := fmt.Sscanf(r.Header.Get("X-Test-Request"), "%d", &id); err != nil || id < 0 || id >= len(release) {
			http.Error(w, "invalid test request", http.StatusBadRequest)
			return
		}
		calls.Add(1)
		started <- id
		select {
		case <-release[id]:
			w.WriteHeader(http.StatusNoContent)
		case <-r.Context().Done():
		}
	}))
	secret := browserSession(t, sessions)

	type result struct {
		done   chan struct{}
		status int
	}
	done := make([]*result, limit+1)
	serve := func(id int) {
		done[id] = &result{done: make(chan struct{})}
		go func() {
			r := publicRequest(http.MethodGet, "/held")
			addSession(r, secret)
			r.Header.Set("X-Test-Request", fmt.Sprint(id))
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			done[id].status = w.Code
			close(done[id].done)
		}()
	}
	waitResult := func(id int) int {
		t.Helper()
		select {
		case <-done[id].done:
			return done[id].status
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d did not complete", id)
			return 0
		}
	}
	t.Cleanup(func() {
		releaseAll()
		for id, result := range done {
			if result == nil {
				continue
			}
			select {
			case <-result.done:
			case <-time.After(5 * time.Second):
				t.Errorf("request %d did not stop during cleanup", id)
			}
		}
	})

	// Admit each request in turn. Starting 256 simultaneous TCP dials makes the
	// test measure host scheduling and the httptest accept backlog rather than
	// the Handler's active-request limit.
	for id := 0; id < limit; id++ {
		serve(id)
		select {
		case got := <-started:
			if got != id {
				t.Fatalf("upstream request = %d, want %d", got, id)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("request %d did not reach upstream", id)
		}
	}
	if got := calls.Load(); got != limit {
		t.Fatalf("upstream calls = %d, want %d", got, limit)
	}

	serve(limit)
	select {
	case id := <-started:
		t.Fatalf("overflow request %d reached upstream", id)
	case <-done[limit].done:
		if got := done[limit].status; got != http.StatusServiceUnavailable {
			t.Fatalf("overflow status = %d, want %d", got, http.StatusServiceUnavailable)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("overflow request did not complete")
	}
	if got := calls.Load(); got != limit {
		t.Fatalf("overflow reached upstream: calls = %d, want %d", got, limit)
	}

	releaseGate(0)
	if got := waitResult(0); got != http.StatusNoContent {
		t.Fatalf("released request status = %d, want %d", got, http.StatusNoContent)
	}

	serve(limit)
	select {
	case id := <-started:
		if id != limit {
			t.Fatalf("replacement upstream request = %d, want %d", id, limit)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("replacement request was not admitted")
	}
	if got := calls.Load(); got != limit+1 {
		t.Fatalf("upstream calls after recovery = %d, want %d", got, limit+1)
	}
	releaseGate(limit)
	if got := waitResult(limit); got != http.StatusNoContent {
		t.Fatalf("replacement status = %d, want %d", got, http.StatusNoContent)
	}
}
