package opentunnel

import (
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestIdentityFormattingAndSlogRedactCredentials(t *testing.T) {
	const token = "token-secret-marker"
	const key = "private-key-secret-marker"
	identities := []any{
		Identity{ID: "tunnel-id", Hostname: "demo.example", Token: token, PrivateKey: key},
		PendingIdentity{ID: "pending-id", Hostname: "pending.example", Token: token, PrivateKey: key},
	}
	for _, identity := range identities {
		values := identityForms(identity)
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			for _, value := range values {
				got := fmt.Sprintf(format, value)
				if strings.Contains(got, token) || strings.Contains(got, key) {
					t.Fatalf("%T with %q leaked credentials: %s", value, format, got)
				}
			}
		}
	}

	var output strings.Builder
	logger := slog.New(slog.NewTextHandler(&output, nil))
	for _, identity := range identities {
		for _, value := range identityForms(identity) {
			logger.Info("identity", slog.Any("identity", value))
		}
	}
	got := output.String()
	if strings.Contains(got, token) || strings.Contains(got, key) {
		t.Fatalf("slog leaked credentials: %s", got)
	}
	if !strings.Contains(got, "tunnel-id") || !strings.Contains(got, "demo.example") {
		t.Fatalf("slog removed identifying fields: %s", got)
	}
}

func identityForms(identity any) []any {
	switch i := identity.(type) {
	case Identity:
		return []any{i, &i, []any{i}, map[string]any{"identity": i}}
	case PendingIdentity:
		return []any{i, &i, []any{i}, map[string]any{"identity": i}}
	default:
		panic("unexpected identity type")
	}
}
