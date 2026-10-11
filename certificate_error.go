package opentunnel

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strconv"
	"strings"
)

const maxCertificateIssuanceReason = 4096

var (
	certificateACMEProblem = regexp.MustCompile(`(?i)\burn:ietf:params:acme:error:([[:alnum:]]+)\b`)
	certificateHTTPStatus  = regexp.MustCompile(`(?i)\bHTTP[ \t]+([1-5][0-9]{2})\b`)
	certificateRateLimit   = regexp.MustCompile(`(?i)\brate[ -]?limit(?:ed|ing)?\b`)
	certificateDNSFailure  = regexp.MustCompile(`(?i)\bDNS (?:error|failure|problem)\b`)
	certificateAuthFailed  = regexp.MustCompile(`(?i)\bauthori[sz]ation failed\b`)
	certificateTimeout     = regexp.MustCompile(`(?i)\b(?:timeout|timed out)\b`)
)

// CertificateIssuanceError reports failed issuance or deferred recovery during
// its retry cooldown. Reason is available only for deliberate diagnostic inspection;
// ordinary formatting, JSON and structured logging expose safe derived fields.
type CertificateIssuanceError struct {
	// Reason is bounded raw text received from the remote provider. It is
	// untrusted and may contain sensitive data. Do not log or display it without
	// an explicit review and redaction step.
	Reason string `json:"-"`
	// Code is a safe, normalized classification of a recognized ACME problem,
	// rate limit, or timeout. Unrecognized failures use unknown.
	Code string
	// StatusCode is a parsed HTTP status in the range 100 through 599, or zero
	// when the provider reason contained no recognized status.
	StatusCode int
}

func certificateIssuanceError(reason string) error {
	if len(reason) > maxCertificateIssuanceReason {
		reason = reason[:maxCertificateIssuanceReason]
	}
	code, statusCode := classifyCertificateIssuance(reason)
	return &CertificateIssuanceError{Reason: reason, Code: code, StatusCode: statusCode}
}

func classifyCertificateIssuance(reason string) (string, int) {
	statusCode := certificateIssuanceHTTPStatus(reason)
	if statusCode == 429 {
		return "rate_limited", statusCode
	}
	for _, match := range certificateACMEProblem.FindAllStringSubmatch(reason, -1) {
		switch strings.ToLower(match[1]) {
		case "ratelimited":
			return "rate_limited", statusCode
		case "dns":
			return "dns_error", statusCode
		case "unauthorized", "rejectedidentifier":
			return "authorization_failed", statusCode
		case "badcsr":
			return "bad_csr", statusCode
		case "badnonce":
			return "bad_nonce", statusCode
		case "caa":
			return "caa_error", statusCode
		case "accountdoesnotexist":
			return "account_error", statusCode
		case "useractionrequired", "externalaccountrequired":
			return "account_action_required", statusCode
		case "incorrectresponse":
			return "challenge_failed", statusCode
		case "connection":
			return "connection_error", statusCode
		case "tls":
			return "tls_error", statusCode
		case "malformed":
			return "malformed_request", statusCode
		case "serverinternal":
			return "server_error", statusCode
		case "unsupportedidentifier":
			return "unsupported_identifier", statusCode
		}
	}
	switch {
	case certificateRateLimit.MatchString(reason):
		return "rate_limited", statusCode
	case certificateDNSFailure.MatchString(reason):
		return "dns_error", statusCode
	case certificateAuthFailed.MatchString(reason):
		return "authorization_failed", statusCode
	case statusCode == 408 || statusCode == 504 || certificateTimeout.MatchString(reason):
		return "timeout", statusCode
	default:
		return "unknown", statusCode
	}
}

func certificateIssuanceHTTPStatus(reason string) int {
	match := certificateHTTPStatus.FindStringSubmatch(reason)
	if len(match) != 2 {
		return 0
	}
	statusCode, err := strconv.Atoi(match[1])
	if err != nil || statusCode < 100 || statusCode > 599 {
		return 0
	}
	return statusCode
}

func diagnosticCertificateIssuanceCode(code string) string {
	switch code {
	case "rate_limited", "dns_error", "authorization_failed", "timeout",
		"bad_csr", "bad_nonce", "caa_error", "account_error",
		"account_action_required", "challenge_failed", "connection_error",
		"tls_error", "malformed_request", "server_error", "unsupported_identifier":
		return code
	default:
		return "unknown"
	}
}

func diagnosticCertificateIssuanceStatus(statusCode int) int {
	if statusCode < 100 || statusCode > 599 {
		return 0
	}
	return statusCode
}

// Error returns a credential-safe summary of the failure.
func (e CertificateIssuanceError) Error() string {
	code := diagnosticCertificateIssuanceCode(e.Code)
	statusCode := diagnosticCertificateIssuanceStatus(e.StatusCode)
	if statusCode == 0 {
		return "opentunnel: certificate issuance failed: " + code
	}
	return fmt.Sprintf("opentunnel: certificate issuance failed: %s (HTTP %d)", code, statusCode)
}

// Unwrap returns ErrCertificateIssuance for errors.Is compatibility.
func (e CertificateIssuanceError) Unwrap() error { return ErrCertificateIssuance }

// String returns a credential-safe summary of the failure.
func (e CertificateIssuanceError) String() string { return e.Error() }

// GoString returns a credential-safe summary of the failure.
func (e CertificateIssuanceError) GoString() string { return e.Error() }

// Format writes a credential-safe summary regardless of the requested verb.
func (e CertificateIssuanceError) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, e.Error())
}

// MarshalJSON emits only normalized, credential-safe fields.
func (e CertificateIssuanceError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Code       string `json:"code"`
		StatusCode int    `json:"statusCode,omitempty"`
	}{
		Code:       diagnosticCertificateIssuanceCode(e.Code),
		StatusCode: diagnosticCertificateIssuanceStatus(e.StatusCode),
	})
}

// LogValue returns only normalized, credential-safe fields.
func (e CertificateIssuanceError) LogValue() slog.Value {
	code := diagnosticCertificateIssuanceCode(e.Code)
	statusCode := diagnosticCertificateIssuanceStatus(e.StatusCode)
	if statusCode == 0 {
		return slog.GroupValue(slog.String("code", code))
	}
	return slog.GroupValue(slog.String("code", code), slog.Int("status_code", statusCode))
}
