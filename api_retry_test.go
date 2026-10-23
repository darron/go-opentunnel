package opentunnel

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestAPIRetryUpstreamVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors/api-retry.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Backoff struct {
			BaseMS  int `json:"base_ms"`
			MaxMS   int `json:"max_ms"`
			Retries int
		}
		Delays []struct {
			Attempt    int
			RetryAfter string `json:"retry_after"`
			MinMS      int    `json:"min_ms"`
			MaxMS      int    `json:"max_ms"`
		}
		Statuses []struct {
			Status           int
			Idempotent, Once bool
		}
		Messages []struct {
			Status        int
			Body, Message string
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if apiMaxRetries != vectors.Backoff.Retries {
		t.Fatal("retry limit differs from upstream")
	}
	for _, v := range vectors.Statuses {
		if retryAPIStatus(v.Status, true) != v.Idempotent || retryAPIStatus(v.Status, false) != v.Once {
			t.Errorf("HTTP %d policy differs from upstream", v.Status)
		}
	}
	for _, v := range vectors.Delays {
		for range 100 {
			delay := apiRetryDelay(v.Attempt, v.RetryAfter)
			if delay < time.Duration(v.MinMS)*time.Millisecond || delay > time.Duration(v.MaxMS)*time.Millisecond {
				t.Fatalf("retry %d Retry-After %q: %v", v.Attempt, v.RetryAfter, delay)
			}
		}
	}
	for _, v := range vectors.Messages {
		if v.Status >= 520 && v.Status <= 527 && apiStatusMessage(v.Status) != v.Message {
			t.Errorf("HTTP %d diagnostic differs from upstream", v.Status)
		}
	}
}

func TestAPIRetryStatusAndRequestReplay(t *testing.T) {
	for _, tc := range []struct {
		name        string
		status      int
		safe, retry bool
	}{
		{"get-502", 502, true, true}, {"get-429", 429, true, true}, {"get-401", 401, true, false},
		{"create-503", 503, false, true}, {"create-502", 502, false, false}, {"create-520", 520, false, false}, {"create-521", 521, false, true},
		{"bind-502", 502, true, true}, {"remove-503", 503, false, true}, {"remove-504", 504, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls atomic.Int32
			apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				n := calls.Add(1)
				if r.UserAgent() != "opentunnel-go/"+Version {
					t.Errorf("wrong Go user agent: %q", r.UserAgent())
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
				}
				switch {
				case strings.HasPrefix(tc.name, "create"):
					if r.Method != "POST" || string(data) != "{}" || r.ContentLength != 2 {
						t.Errorf("create replay: %s %q length=%d", r.Method, data, r.ContentLength)
					}
				case strings.HasPrefix(tc.name, "bind"):
					if r.Method != "POST" || string(data) != `{"csr":"test-csr"}` || r.Header.Get("Authorization") != "Bearer test-token" {
						t.Errorf("CSR replay: %s %q", r.Method, data)
					}
				default:
					if r.Header.Get("Authorization") != "Bearer test-token" {
						t.Error("missing authorization")
					}
				}
				if n == 1 {
					w.Header().Set("Retry-After", "0")
					w.WriteHeader(tc.status)
					_, _ = io.WriteString(w, "private-remote-body")
					return
				}
				switch {
				case strings.HasPrefix(tc.name, "create"):
					w.WriteHeader(201)
					_, _ = io.WriteString(w, `{"tunnel":{"id":"demo","hostname":"demo.test","state":"offline"},"token":"test-token"}`)
				case strings.HasPrefix(tc.name, "bind"):
					w.WriteHeader(202)
					_, _ = io.WriteString(w, `{"id":"cert","state":{"type":"issuing"}}`)
				case strings.HasPrefix(tc.name, "remove"):
					w.WriteHeader(204)
				default:
					_, _ = io.WriteString(w, `{"id":"demo","hostname":"demo.test","state":"offline"}`)
				}
			}))
			defer apiServer.Close()
			api, err := NewAPI(apiServer.URL, nil, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case strings.HasPrefix(tc.name, "create"):
				_, err = api.Create(t.Context())
			case strings.HasPrefix(tc.name, "bind"):
				_, err = api.BindCertificate(t.Context(), "demo", "test-token", "test-csr")
			case strings.HasPrefix(tc.name, "remove"):
				err = api.Remove(t.Context(), "demo", "test-token")
			default:
				_, err = api.Get(t.Context(), "demo", "test-token")
			}
			wantCalls := int32(1)
			if tc.retry {
				wantCalls = 2
			}
			if calls.Load() != wantCalls || (err == nil) != tc.retry {
				t.Fatalf("calls=%d err=%v", calls.Load(), err)
			}
			if err != nil && strings.Contains(err.Error(), "private-remote-body") {
				t.Fatal("remote body leaked")
			}
			stats := api.Stats()
			if stats.APIRequests != 1 || stats.APIErrors != map[bool]uint64{true: 0, false: 1}[tc.retry] {
				t.Fatalf("logical operation stats: %+v", stats)
			}
		})
	}
}

func TestAPIRetryLimitAndCancellation(t *testing.T) {
	var calls atomic.Int32
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(503)
	}))
	defer apiServer.Close()
	api, _ := NewAPI(apiServer.URL, nil, time.Second)
	_, err := api.Create(t.Context())
	var remote *APIError
	if !errors.As(err, &remote) || remote.StatusCode != 503 || calls.Load() != 7 {
		t.Fatalf("retry limit: calls=%d err=%v", calls.Load(), err)
	}
	calls.Store(0)
	backoffServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		w.Header().Set("Retry-After", "8")
		w.WriteHeader(503)
	}))
	defer backoffServer.Close()
	api, _ = NewAPI(backoffServer.URL, nil, time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = api.Create(ctx)
	if !errors.Is(err, context.DeadlineExceeded) || calls.Load() != 1 || time.Since(started) > time.Second {
		t.Fatalf("backoff cancellation: calls=%d err=%v", calls.Load(), err)
	}
}

func TestAPIRetryNetworkSafety(t *testing.T) {
	for _, tc := range []struct {
		name        string
		failure     error
		safe, retry bool
	}{
		{"get-read", &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}, true, true},
		{"create-read", &net.OpError{Op: "read", Net: "tcp", Err: io.ErrUnexpectedEOF}, false, false},
		{"create-dial", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("refused")}, false, true},
		{"create-eof", io.EOF, false, false}, {"get-opaque", errors.New("hook failed"), true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
				calls++
				if calls == 1 {
					return nil, tc.failure
				}
				status := 200
				body := `{"id":"demo","hostname":"demo.test","state":"offline"}`
				if !tc.safe {
					status = 201
					body = `{"tunnel":{"id":"demo","hostname":"demo.test","state":"offline"},"token":"test-token"}`
				}
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
			}}
			api, _ := NewAPI("https://api.example.test", &http.Client{Transport: transport}, time.Second)
			var err error
			if tc.safe {
				_, err = api.Get(t.Context(), "demo", "test-token")
			} else {
				_, err = api.Create(t.Context())
			}
			want := 1
			if tc.retry {
				want = 2
			}
			if calls != want || (err == nil) != tc.retry {
				t.Fatalf("calls=%d err=%v", calls, err)
			}
		})
	}
}

func TestAPIRetryTruncatedResponseSafety(t *testing.T) {
	for _, create := range []bool{false, true} {
		t.Run(map[bool]string{false: "get", true: "create"}[create], func(t *testing.T) {
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				n := calls.Add(1)
				status := 200
				body := `{"id":"demo","hostname":"demo.test","state":"offline"}`
				if create {
					status = 201
					body = `{"tunnel":{"id":"demo","hostname":"demo.test","state":"offline"},"token":"test-token"}`
				}
				if n == 1 {
					w.Header().Set("Content-Length", "1024")
					w.WriteHeader(status)
					_, _ = io.WriteString(w, `{"id":`)
					return
				}
				w.WriteHeader(status)
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			api, _ := NewAPI(server.URL, nil, time.Second)
			var err error
			if create {
				_, err = api.Create(t.Context())
			} else {
				_, err = api.Get(t.Context(), "demo", "test-token")
			}
			if create {
				if calls.Load() != 1 || !errors.Is(err, io.ErrUnexpectedEOF) {
					t.Fatalf("ambiguous create retried: calls=%d err=%v", calls.Load(), err)
				}
			} else if calls.Load() != 2 || err != nil {
				t.Fatalf("GET body not retried: calls=%d err=%v", calls.Load(), err)
			}
		})
	}
}

func TestAPIRetryHugeRetryAfter(t *testing.T) {
	if delay := apiRetryDelay(0, strings.Repeat("9", 1000)); delay != 8*time.Second {
		t.Fatalf("overflowing Retry-After: %v", delay)
	}
	for _, value := range []string{"-1", "2.5", "Fri, 31 Dec 1999 23:59:59 GMT"} {
		delay := apiRetryDelay(0, value)
		if delay < 125*time.Millisecond || delay > 250*time.Millisecond {
			t.Fatalf("invalid Retry-After %q: %v", value, delay)
		}
	}
}

type retryTestBody struct {
	io.Reader
	closed bool
}

func (b *retryTestBody) Close() error { b.closed = true; return nil }
func TestAPIRetryClosesBodiesBeforeNextAttempt(t *testing.T) {
	var bodies []*retryTestBody
	transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
		for _, previous := range bodies {
			if !previous.closed {
				t.Error("retry started with previous response still open")
			}
		}
		body := &retryTestBody{Reader: strings.NewReader("private-remote-body")}
		status := 503
		if len(bodies) == 2 {
			status = 200
			body.Reader = strings.NewReader(`{"id":"demo","hostname":"demo.test","state":"offline"}`)
		}
		bodies = append(bodies, body)
		return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"0"}}, Body: body, Request: req}, nil
	}}
	api, _ := NewAPI("https://api.example.test", &http.Client{Transport: transport}, time.Second)
	if _, err := api.Get(t.Context(), "demo", "test-token"); err != nil {
		t.Fatal(err)
	}
	if len(bodies) != 3 || !bodies[2].closed {
		t.Fatalf("response cleanup: %+v", bodies)
	}
	if stats := api.Stats(); stats.APIRequests != 1 || stats.APIErrors != 0 || len(stats.CertificateFailures) != 0 {
		t.Fatalf("intermediate failures counted: %+v", stats)
	}
}

func TestClientSavedCertificateFallbackOnlyAfterTransientFailure(t *testing.T) {
	fixture := newTestAPI(t)
	store := NewMemoryStorage()
	client := testClient(t, fixture, store)
	if _, err := client.Create(t.Context(), "default", ProvisionOptions{}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		failure  error
		fallback bool
	}{
		{name: "rate-limit", status: 429, fallback: true}, {name: "service-unavailable", status: 503, fallback: true},
		{name: "unauthorized", status: 401}, {name: "missing", status: 404},
		{name: "malformed-success", status: 200, body: `not JSON`},
		{name: "redirect-policy", status: 302},
		{name: "tls-verification", failure: x509.UnknownAuthorityError{}},
		{name: "opaque-hook", failure: errors.New("hook refused")},
		{name: "network-read", failure: io.ErrUnexpectedEOF, fallback: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
				if tc.failure != nil {
					return nil, tc.failure
				}
				header := http.Header{"Retry-After": []string{"0"}}
				if tc.status == 302 {
					header.Set("Location", "https://other.example.test/forbidden")
				}
				return &http.Response{StatusCode: tc.status, Header: header, Body: io.NopCloser(strings.NewReader(tc.body)), Request: req}, nil
			}}
			api, err := NewAPI("https://api.example.test", &http.Client{Transport: transport}, 30*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			client.api = api
			guard, err := client.guardProfile(t.Context(), "default")
			if err != nil {
				t.Fatal(err)
			}
			defer guard.release()
			id, err := client.ensure(t.Context(), "default", true, guard, ProvisionOptions{})
			if (err == nil) != tc.fallback || (id != nil) != tc.fallback {
				t.Fatalf("id=%v err=%v, fallback wanted=%v", id != nil, err, tc.fallback)
			}
			if !tc.fallback && transport.calls != 1 {
				t.Errorf("nontransient failure retried %d times", transport.calls)
			}
		})
	}
}

func TestClientSavedCertificateFallbackAfterInternalBodyDeadline(t *testing.T) {
	fixture := newTestAPI(t)
	store := NewMemoryStorage()
	client := testClient(t, fixture, store)
	if _, err := client.Create(t.Context(), "default", ProvisionOptions{}); err != nil {
		t.Fatal(err)
	}
	stalled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Error(err)
		}
		<-r.Context().Done()
	}))
	defer stalled.Close()
	for _, callerDeadline := range []bool{false, true} {
		t.Run(map[bool]string{false: "internal-deadline", true: "caller-deadline"}[callerDeadline], func(t *testing.T) {
			var err error
			client.api, err = NewAPI(stalled.URL, nil, 30*time.Millisecond)
			if err != nil {
				t.Fatal(err)
			}
			ctx := t.Context()
			if callerDeadline {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 10*time.Millisecond)
				defer cancel()
			}
			guard, err := client.guardProfile(ctx, "default")
			if err != nil {
				t.Fatal(err)
			}
			defer guard.release()
			id, err := client.ensure(ctx, "default", true, guard, ProvisionOptions{})
			if callerDeadline {
				if id != nil || !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("caller deadline bypassed: id=%v err=%v", id != nil, err)
				}
			} else if id == nil || err != nil {
				t.Fatalf("internal network deadline blocked local fallback: id=%v err=%v", id != nil, err)
			}
		})
	}
}

func TestAPIErrorStatusSurvivesUnreadableBody(t *testing.T) {
	for _, status := range []int{401, 503} {
		for _, oversized := range []bool{false, true} {
			t.Run(fmt.Sprintf("HTTP%d/oversized=%v", status, oversized), func(t *testing.T) {
				calls := 0
				transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
					calls++
					var body io.Reader = errorReader{err: io.ErrUnexpectedEOF}
					if oversized {
						body = strings.NewReader(strings.Repeat("x", maxAPIResponse+1))
					}
					return &http.Response{StatusCode: status, Header: http.Header{"Retry-After": []string{"0"}}, Body: io.NopCloser(body), Request: req}, nil
				}}
				api, _ := NewAPI("https://api.example.test", &http.Client{Transport: transport}, time.Second)
				_, err := api.Certificate(t.Context(), "demo", "test-token")
				var remote *APIError
				wantCalls := 1
				if status == 503 {
					wantCalls = 7
				}
				if !errors.As(err, &remote) || remote.StatusCode != status || calls != wantCalls {
					t.Fatalf("error status lost: calls=%d err=%v", calls, err)
				}
				if transientAPIError(err) != (status == 503) {
					t.Fatalf("wrong fallback classification: %v", err)
				}
			})
		}
	}
}

type errorReader struct{ err error }

func (r errorReader) Read([]byte) (int, error) { return 0, r.err }
