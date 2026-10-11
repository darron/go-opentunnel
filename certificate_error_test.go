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

func TestCertificateIssuanceErrorClassifiesProviderReason(t *testing.T) {
	tests := []struct {
		name       string
		reason     string
		code       string
		statusCode int
	}{
		{name: "rate limited", reason: "urn:ietf:params:acme:error:rateLimited: provider refused request; HTTP 429", code: "rate_limited", statusCode: 429},
		{name: "DNS", reason: "urn:ietf:params:acme:error:dns: DNS problem: NXDOMAIN", code: "dns_error"},
		{name: "authorization", reason: "urn:ietf:params:acme:error:unauthorized: authorization failed", code: "authorization_failed"},
		{name: "bad CSR", reason: "urn:ietf:params:acme:error:badCSR", code: "bad_csr"},
		{name: "bad nonce", reason: "urn:ietf:params:acme:error:badNonce", code: "bad_nonce"},
		{name: "CAA", reason: "urn:ietf:params:acme:error:caa", code: "caa_error"},
		{name: "missing account", reason: "urn:ietf:params:acme:error:accountDoesNotExist", code: "account_error"},
		{name: "account action", reason: "urn:ietf:params:acme:error:userActionRequired", code: "account_action_required"},
		{name: "external account", reason: "urn:ietf:params:acme:error:externalAccountRequired", code: "account_action_required"},
		{name: "challenge", reason: "urn:ietf:params:acme:error:incorrectResponse", code: "challenge_failed"},
		{name: "connection", reason: "urn:ietf:params:acme:error:connection", code: "connection_error"},
		{name: "TLS", reason: "urn:ietf:params:acme:error:tls", code: "tls_error"},
		{name: "malformed", reason: "urn:ietf:params:acme:error:malformed", code: "malformed_request"},
		{name: "server", reason: "urn:ietf:params:acme:error:serverInternal", code: "server_error"},
		{name: "identifier", reason: "urn:ietf:params:acme:error:unsupportedIdentifier", code: "unsupported_identifier"},
		{name: "timeout status", reason: "provider request failed with HTTP 504", code: "timeout", statusCode: 504},
		{name: "unknown", reason: "provider-specific rejection", code: "unknown"},
		{name: "embedded status ignored", reason: "provider ticket HTTP 4290", code: "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var issuance *CertificateIssuanceError
			if !errors.As(certificateIssuanceError(tt.reason), &issuance) {
				t.Fatal("constructor did not return CertificateIssuanceError")
			}
			if issuance.Code != tt.code || issuance.StatusCode != tt.statusCode {
				t.Fatalf("classification = (%q, %d), want (%q, %d)", issuance.Code, issuance.StatusCode, tt.code, tt.statusCode)
			}
			if !errors.Is(issuance, ErrCertificateIssuance) {
				t.Fatal("typed error does not unwrap to ErrCertificateIssuance")
			}
		})
	}
}

func TestCertificateIssuanceErrorBoundsRawReason(t *testing.T) {
	reason := strings.Repeat("x", maxCertificateIssuanceReason+128)
	var issuance *CertificateIssuanceError
	if !errors.As(certificateIssuanceError(reason), &issuance) {
		t.Fatal("constructor did not return CertificateIssuanceError")
	}
	if len(issuance.Reason) != maxCertificateIssuanceReason {
		t.Fatalf("Reason length = %d, want %d", len(issuance.Reason), maxCertificateIssuanceReason)
	}
	if issuance.Reason != reason[:maxCertificateIssuanceReason] {
		t.Fatal("Reason did not retain the bounded raw prefix")
	}
}

func TestCertificateIssuanceErrorFormattingNeverExposesReason(t *testing.T) {
	const secret = "remote-reason-sensitive-marker"
	err := &CertificateIssuanceError{Reason: secret, Code: secret, StatusCode: 999}
	values := []any{err, *err, []any{err, *err}, map[string]any{"failure": err}}
	for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
		for _, value := range values {
			got := fmt.Sprintf(format, value)
			if strings.Contains(got, secret) || strings.Contains(got, hex.EncodeToString([]byte(secret))) {
				t.Fatalf("%T with %q exposed remote reason: %s", value, format, got)
			}
		}
	}
	if got := err.Error(); strings.Contains(got, secret) || !strings.Contains(got, "unknown") {
		t.Fatalf("Error() was not safely normalized: %s", got)
	}
	if got := err.String(); strings.Contains(got, secret) {
		t.Fatalf("String() exposed remote reason: %s", got)
	}
	if got := err.GoString(); strings.Contains(got, secret) {
		t.Fatalf("GoString() exposed remote reason: %s", got)
	}
}

func TestCertificateIssuanceErrorJSONAndSlogNeverExposeReason(t *testing.T) {
	const secret = "remote-reason-sensitive-marker"
	err := &CertificateIssuanceError{Reason: secret, Code: "rate_limited", StatusCode: 429}
	mutated := &CertificateIssuanceError{Reason: secret, Code: secret, StatusCode: 999}
	for _, value := range []any{err, *err, mutated, *mutated, []any{err, *err, mutated}, map[string]any{"failure": mutated}} {
		encoded, marshalErr := json.Marshal(value)
		if marshalErr != nil {
			t.Fatalf("Marshal(%T): %v", value, marshalErr)
		}
		if strings.Contains(string(encoded), secret) || strings.Contains(string(encoded), "Reason") || strings.Contains(string(encoded), "reason") {
			t.Fatalf("Marshal(%T) exposed remote reason: %s", value, encoded)
		}
	}

	var output strings.Builder
	logger := slog.New(slog.NewTextHandler(&output, nil))
	logger.Info("issuance", slog.Any("pointer", err), slog.Any("value", *err), slog.Any("mutated", mutated))
	got := output.String()
	if strings.Contains(got, secret) {
		t.Fatalf("slog exposed remote reason: %s", got)
	}
	if !strings.Contains(got, "rate_limited") || !strings.Contains(got, "429") {
		t.Fatalf("slog omitted actionable safe fields: %s", got)
	}
}
