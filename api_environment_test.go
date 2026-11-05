package opentunnel

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestClientAPIEnvironmentSelection(t *testing.T) {
	for _, tc := range []struct {
		name, environment, explicit, want string
	}{
		{"hosted default", "", "", "https://opentunnel.xyz"},
		{"environment", "https://relay.example.test/control", "", "https://relay.example.test/control"},
		{"explicit wins", "https://environment.example.test", "https://explicit.example.test", "https://explicit.example.test"},
		{"explicit ignores invalid environment", "invalid", "https://explicit.example.test", "https://explicit.example.test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("OPENTUNNEL_API", tc.environment)
			client, err := NewClient(ClientOptions{API: tc.explicit, Storage: NewMemoryStorage()})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = client.Close() }()
			t.Setenv("OPENTUNNEL_API", "https://changed.example.test")
			if got := client.API().base.String(); got != tc.want {
				t.Fatalf("API URL = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestClientRejectsInvalidAPIEnvironment(t *testing.T) {
	for _, value := range []string{"not-a-url", " ", "http://nonloopback.example.test", "https://user:secret-canary@relay.example.test", "https://relay.example.test?secret-canary"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("OPENTUNNEL_API", value)
			client, err := NewClient(ClientOptions{Storage: NewMemoryStorage()})
			if client != nil {
				_ = client.Close()
			}
			if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "secret-canary") {
				t.Fatalf("invalid environment was accepted or disclosed: %v", err)
			}
		})
	}
}

func TestClientEnvironmentAPIProvisionAndBridge(t *testing.T) {
	f := newRelay(t)
	t.Setenv("OPENTUNNEL_API", f.api.server.URL)
	c, err := NewClient(ClientOptions{Storage: NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if c.API().base.String() != f.api.server.URL {
		t.Fatal("environment API was not selected; refusing external network access")
	}
	t.Setenv("OPENTUNNEL_API", "invalid-after-construction")
	connection := connectTest(t, c, Routes{"@": echoTarget(t)})
	defer func() { _ = connection.Close() }()
	visitor := f.next(t).public(t, 1, "demo.test")
	defer func() { _ = visitor.Close() }()
	const payload = "environment-selected relay"
	if _, err := io.WriteString(visitor, payload); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(payload))
	if _, err := io.ReadFull(visitor, got); err != nil || string(got) != payload {
		t.Fatalf("forwarded bytes = %q, error=%v", got, err)
	}
	if f.api.creates.Load() != 1 || f.api.submissions.Load() != 1 {
		t.Fatalf("provisioning did not use environment API: creates=%d submissions=%d", f.api.creates.Load(), f.api.submissions.Load())
	}
}

func TestNewAPIRetainsExplicitBase(t *testing.T) {
	t.Setenv("OPENTUNNEL_API", "invalid")
	if _, err := NewAPI("", nil, 0); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty low-level base accepted: %v", err)
	}
	if _, err := NewAPI("https://explicit.example.test", nil, 0); err != nil {
		t.Fatal(err)
	}
}
