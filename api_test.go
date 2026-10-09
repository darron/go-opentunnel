package opentunnel

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPIValidatesBase(t *testing.T) {
	for _, base := range []string{"ftp://example.com", "https://user:pass@example.com", "https://example.com/?x=1", "https://example.com/#x"} {
		if _, err := NewAPI(base, nil, time.Second); err == nil {
			t.Fatalf("accepted %q", base)
		}
	}
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
