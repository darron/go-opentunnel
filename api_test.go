package opentunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPIValidatesBase(t *testing.T) {
	for _, base := range []string{"ftp://example.com", "https://user:pass@example.com", "https://example.com/?x=1", "https://example.com/#x", "http://example.com", "http://127.0.0.1.nip.io", "http://localhost.example"} {
		if _, err := NewAPI(base, nil, time.Second); err == nil {
			t.Fatalf("accepted %q", base)
		}
	}
	for _, base := range []string{"http://localhost", "http://127.0.0.1", "http://[::1]"} {
		if _, err := NewAPI(base, nil, time.Second); err != nil {
			t.Fatalf("rejected loopback %q: %v", base, err)
		}
	}
}

func TestAPIRedirectRejectsHTTPSDowngradeBeforeCustomTransport(t *testing.T) {
	const token = "token-secret-marker"
	transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"http://127.0.0.1/api/tunnel/demo"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	}}
	api, err := NewAPI("https://api.example.test", &http.Client{Transport: transport}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Get(context.Background(), "demo", token); err == nil {
		t.Fatal("HTTPS downgrade redirect succeeded")
	}
	if transport.calls != 1 {
		t.Fatalf("redirect reached custom transport %d times", transport.calls)
	}
}

func TestAPIRedirectRejectsNonLoopbackHTTPDestination(t *testing.T) {
	transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"http://api.example.test/api/tunnel/demo"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	}}
	api, err := NewAPI("http://127.0.0.1", &http.Client{Transport: transport}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Get(context.Background(), "demo", "token"); err == nil {
		t.Fatal("non-loopback HTTP redirect succeeded")
	}
	if transport.calls != 1 {
		t.Fatalf("redirect reached custom transport %d times", transport.calls)
	}
}

func TestAPIRedirectPreservesCallerHook(t *testing.T) {
	sentinel := errors.New("caller redirect hook")
	transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://api.example.test/elsewhere"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	}}
	api, err := NewAPI("https://api.example.test", &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return sentinel
		},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Get(context.Background(), "demo", "token"); !errors.Is(err, sentinel) {
		t.Fatalf("redirect error = %v, want caller hook error", err)
	}
	if transport.calls != 1 {
		t.Fatalf("redirect reached custom transport %d times", transport.calls)
	}
}

func TestAPIRedirectRejectsCrossOriginHTTPSBeforeCustomTransport(t *testing.T) {
	for _, target := range []string{
		"https://other.example.test/api/tunnel/demo",
		"https://sub.api.example.test/api/tunnel/demo",
		"https://api.example.test:8443/api/tunnel/demo",
	} {
		t.Run(target, func(t *testing.T) {
			transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusFound,
					Header:     http.Header{"Location": []string{target}},
					Body:       io.NopCloser(strings.NewReader("redirect")),
					Request:    req,
				}, nil
			}}
			api, err := NewAPI("https://api.example.test", &http.Client{Transport: transport}, time.Second)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.Get(context.Background(), "demo", "token-secret-marker"); err == nil {
				t.Fatal("cross-origin HTTPS redirect succeeded")
			}
			if transport.calls != 1 {
				t.Fatalf("redirect reached custom transport %d times", transport.calls)
			}
		})
	}
}

func TestAPIRedirectAllowsSameOriginHTTPS(t *testing.T) {
	transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
		if req.URL.Path == "/same-origin" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(`{"id":"demo","hostname":"demo.example","state":"online"}`)),
				Request:    req,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://API.EXAMPLE.TEST:443/same-origin"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	}}
	api, err := NewAPI("https://api.example.test", &http.Client{Transport: transport}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Get(context.Background(), "demo", "token-secret-marker"); err != nil {
		t.Fatalf("same-origin HTTPS redirect: %v", err)
	}
	if transport.calls != 2 {
		t.Fatalf("transport calls = %d, want 2", transport.calls)
	}
}

func TestAPIRedirectRejectsCallerHookCrossOriginMutation(t *testing.T) {
	transport := &roundTripFunc{fn: func(req *http.Request) (*http.Response, error) {
		if req.URL.Host != "api.example.test" {
			return nil, errors.New("cross-origin request reached transport")
		}
		return &http.Response{
			StatusCode: http.StatusFound,
			Header:     http.Header{"Location": []string{"https://api.example.test/same-origin"}},
			Body:       io.NopCloser(strings.NewReader("redirect")),
			Request:    req,
		}, nil
	}}
	api, err := NewAPI("https://api.example.test", &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			req.URL.Host = "other.example.test"
			return nil
		},
	}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Get(context.Background(), "demo", "token-secret-marker"); err == nil {
		t.Fatal("caller hook redirected to another origin")
	}
	if transport.calls != 1 {
		t.Fatalf("redirect reached custom transport %d times", transport.calls)
	}
}

type roundTripFunc struct {
	calls int
	fn    func(*http.Request) (*http.Response, error)
}

func (f *roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	f.calls++
	return f.fn(req)
}

func TestAPIStatusAuthEscapingAndRedaction(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != "/api/tunnel/a%2Fb" {
			t.Errorf("escaped path %q", r.URL.EscapedPath())
		}
		if got := r.Header.Get("Authorization"); got != "Bearer tok_secret" {
			t.Errorf("auth %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"_tag":"Denied","message":"tok_secret private-key"}`))
	}))
	defer s.Close()
	api, err := NewAPI(s.URL, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.Get(context.Background(), "a/b", "tok_secret")
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 401 || apiErr.Tag != "Denied" {
		t.Fatalf("error %#v", err)
	}
	if strings.Contains(err.Error(), "tok_secret") || strings.Contains(err.Error(), "private-key") {
		t.Fatalf("secret leaked: %v", err)
	}
}

func TestAPICancellationAndBoundedResponse(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-r.Context().Done()
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write(make([]byte, 1024*1024+1))
	}))
	defer s.Close()
	api, err := NewAPI(s.URL, nil, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := api.Create(ctx); err == nil {
		t.Fatal("cancelled create succeeded")
	}
	if _, err := api.Create(context.Background()); err == nil {
		t.Fatal("oversize response accepted")
	}
}

func TestAPIResponseContextLivesUntilBodyClosed(t *testing.T) {
	body := `{"id":"tunnel","hostname":"demo.opentunnel.xyz","state":"online"}`
	release := make(chan struct{})
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush: %v", err)
		}
		<-release
		_, _ = fmt.Fprint(w, body)
	}))
	defer s.Close()
	api, err := NewAPI(s.URL, nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	go func() { time.Sleep(25 * time.Millisecond); close(release) }()
	if _, err := api.Get(context.Background(), "tunnel", "token"); err != nil {
		t.Fatalf("delayed body: %v", err)
	}
}

func TestAPIRequestTimeoutCanInterruptResponseBody(t *testing.T) {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if err := http.NewResponseController(w).Flush(); err != nil {
			t.Errorf("flush: %v", err)
		}
		time.Sleep(100 * time.Millisecond)
		_, _ = fmt.Fprint(w, `{"id":"tunnel","hostname":"demo.opentunnel.xyz","state":"online"}`)
	}))
	defer s.Close()
	api, err := NewAPI(s.URL, nil, 25*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.Get(context.Background(), "tunnel", "token"); err == nil {
		t.Fatal("slow response body succeeded")
	}
}

func TestAPIEndpointPreservesPrefixAndEscapesIDOnce(t *testing.T) {
	api, err := NewAPI("https://example.test/prefix", nil, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	u := api.endpointURL("a/b", "/certificate")
	if got, want := u.EscapedPath(), "/prefix/api/tunnel/a%2Fb/certificate"; got != want {
		t.Fatalf("escaped path = %q, want %q", got, want)
	}
}

func TestAPIRejectsInvalidTunnelStateAndTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, `{"id":"demo","hostname":"demo.test","state":"ready"}`)
	}))
	defer server.Close()
	api, e := NewAPI(server.URL, nil, time.Second)
	if e != nil {
		t.Fatal(e)
	}
	if _, e := api.Get(context.Background(), "demo", "token"); e == nil {
		t.Fatal("invalid state accepted")
	}
	if _, e := NewAPI(server.URL, nil, -time.Second); e == nil {
		t.Fatal("negative timeout accepted")
	}
}
