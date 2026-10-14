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
			wantClass := CertificateFailureRejected
			switch tt.code {
			case "rate_limited":
				wantClass = CertificateFailureHTTP429
			case "dns_error":
				wantClass = CertificateFailureDNS
			case "bad_nonce":
				wantClass = CertificateFailureBadNonce
			case "connection_error":
				wantClass = CertificateFailureNetwork
			case "server_error":
				wantClass = CertificateFailureHTTP5xx
			case "timeout":
				wantClass = CertificateFailureHTTP5xx // terminal HTTP 504 fixture
			case "unknown":
				wantClass = CertificateFailureOther
			}
			if issuance.Class != wantClass {
				t.Fatalf("class = %s, want %s", issuance.Class, wantClass)
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
	err := &CertificateIssuanceError{Reason: secret, Code: secret, Class: CertificateFailureClass(secret), StatusCode: 999}
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
	mutated := &CertificateIssuanceError{Reason: secret, Code: secret, Class: CertificateFailureClass(secret), StatusCode: 999}
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

func TestCertificateFailureClassTerminalReasons(t *testing.T) {
	for _, tc := range []struct {
		reason string
		want   CertificateFailureClass
	}{
		{"ACME server returned no nonce (HTTP 503)", CertificateFailureNonce},
		{"error decoding response body: expected value at line 1 column 1", CertificateFailureBadBody},
		{"ACME authorization ended in pending", CertificateFailureAuthorizationPending},
		{"ACME authorization for example.opentunnel.xyz ended in invalid: urn:ietf:params:acme:error:dns: DNS problem: NXDOMAIN", CertificateFailureDNS},
		{"ACME authorization for example.opentunnel.xyz ended in invalid: urn:ietf:params:acme:error:unauthorized: validation failed", CertificateFailureRejected},
		{"ACME order ended in processing", CertificateFailureAuthorizationPending},
		{"error sending request: connection reset", CertificateFailureNetwork},
		{"connection closed", CertificateFailureNetwork},
		{"request timed out", CertificateFailureTimeout},
		{"HTTP status server error (502 Bad Gateway)", CertificateFailureHTTP5xx},
		{"ACME request failed | HTTP 429 | secret", CertificateFailureHTTP429},
		{"DNS record update failed | HTTP 503 | secret", CertificateFailureDNS},
		{"identical record already exists | HTTP 429", CertificateFailureDNS},
		{"urn:ietf:params:acme:error:dns | HTTP 429", CertificateFailureDNS},
		{"urn:ietf:params:acme:error:badNonce | HTTP 400", CertificateFailureBadNonce},
		{"urn:ietf:params:acme:error:rejectedIdentifier | HTTP 400", CertificateFailureRejected},
		{"urn:ietf:params:acme:error:badCSR", CertificateFailureRejected},
		{"provider-specific mystery", CertificateFailureOther},
	} {
		var e *CertificateIssuanceError
		if !errors.As(certificateIssuanceError(tc.reason), &e) || e.Class != tc.want {
			t.Fatalf("%q => %+v; want class %s", tc.reason, e, tc.want)
		}
	}
	e := CertificateIssuanceError{Reason: "secret", Code: "unknown", Class: CertificateFailureNonce}
	if !strings.Contains(e.Error(), "nonce") {
		t.Fatalf("safe class omitted: %s", e.Error())
	}
	e.Class = CertificateFailureOther
	if !strings.Contains(e.Error(), "failed: other") {
		t.Fatalf("recognized other omitted: %s", e.Error())
	}
	e.Class = "secret"
	encoded, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(e.Error(), "secret") || strings.Contains(string(encoded), "secret") || !strings.Contains(string(encoded), `"class":"other"`) {
		t.Fatalf("unsafe normalized class: %s / %s", e.Error(), encoded)
	}
	var output strings.Builder
	slog.New(slog.NewJSONHandler(&output, nil)).Info("test", "failure", e)
	if strings.Contains(output.String(), "secret") || !strings.Contains(output.String(), `"class":"other"`) {
		t.Fatalf("unsafe slog: %s", output.String())
	}
}
