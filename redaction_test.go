package opentunnel

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
)

func TestProvisioningRecoveryErrorFormattingRedactsPendingSecrets(t *testing.T) {
	const token = "recovery-token-secret-marker"
	const key = "recovery-private-key-secret-marker"
	err := &ProvisioningError{Pending: PendingIdentity{ID: "demo", Hostname: "demo.test", Token: token, PrivateKey: key}, Err: errors.New("persistence and cleanup failed")}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
		text := fmt.Sprintf(format, err)
		for _, secret := range []string{token, key, hex.EncodeToString([]byte(token)), hex.EncodeToString([]byte(key))} {
			if strings.Contains(text, secret) {
				t.Fatalf("recovery error format %q exposed credentials", format)
			}
		}
	}
	encoded, marshalErr := json.Marshal(err)
	if marshalErr != nil || strings.Contains(string(encoded), token) || strings.Contains(string(encoded), key) {
		t.Fatal("recovery error JSON exposed pending credentials")
	}
}

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
