package authproxy

import (
	"context"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestProxyLongPollWaitsForHeaders(t *testing.T) {
	t.Parallel()
	// Exercise a real response after the former 15-second header deadline.
	// Long-poll backends intentionally send no headers until their hold ends.
	h, sessions, _ := testHandler(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(16 * time.Second)
		defer timer.Stop()
		select {
		case <-timer.C:
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"events":[]}`)
		case <-r.Context().Done():
		}
	}))
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()
	r := publicRequest("GET", "/events?wait=30").WithContext(ctx)
	addSession(r, browserSession(t, sessions))
	w := runRequest(h, r)
	if w.Code != http.StatusOK || w.Body.String() != `{"events":[]}` {
		t.Fatalf("long poll: status=%d body=%q", w.Code, w.Body.String())
	}
}

func TestProxyPendingHeadersCancellation(t *testing.T) {
	for _, mode := range []string{"client cancel", "session logout", "handler close"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			canceled := make(chan struct{})
			h, sessions, _ := testHandler(t, http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
				close(started)
				<-r.Context().Done()
				close(canceled)
			}))
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			secret := browserSession(t, sessions)
			r := publicRequest("GET", "/events?wait=30").WithContext(ctx)
			addSession(r, secret)
			finished := make(chan struct{})
			go func() {
				runRequest(h, r)
				close(finished)
			}()
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("backend did not receive poll")
			}
			switch mode {
			case "client cancel":
				cancel()
			case "session logout":
				sessions.Revoke(secret)
			case "handler close":
				if err := h.Close(); err != nil {
					t.Fatal(err)
				}
			}
			timer := time.NewTimer(2 * time.Second)
			defer timer.Stop()
			for _, done := range []<-chan struct{}{canceled, finished} {
				select {
				case <-done:
				case <-timer.C:
					t.Fatal("pending poll survived cancellation")
				}
			}
		})
	}
}
