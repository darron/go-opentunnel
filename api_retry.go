package opentunnel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const apiMaxRetries = 6

type apiRetryPolicy uint8

const (
	apiRequestOnce apiRetryPolicy = iota
	apiRequestRepeatable
)

// Mark transport failures so Connect only falls back after a transient outage.
// Unwrap preserves callers' errors.Is/errors.As checks on the original error.
type apiTransientError struct{ err error }

func (e *apiTransientError) Error() string { return e.err.Error() }
func (e *apiTransientError) Unwrap() error { return e.err }
func transientAPIError(err error) bool {
	var remote *APIError
	if errors.As(err, &remote) {
		return retryAPIStatus(remote.StatusCode, true)
	}
	var network *apiTransientError
	return errors.As(err, &network)
}
func retryAPIStatus(status int, repeatable bool) bool {
	if repeatable {
		return status == 429 || status >= 500 && status <= 599
	}
	switch status {
	case 429, 503, 521, 522, 523, 525:
		return true
	default:
		return false
	}
}
func retryAPINetwork(err error, repeatable bool) bool {
	if errors.Is(err, ErrInvalid) || errors.Is(err, context.Canceled) {
		return false
	}
	var verification *tls.CertificateVerificationError
	var unknown x509.UnknownAuthorityError
	var invalid x509.CertificateInvalidError
	var hostname x509.HostnameError
	if errors.As(err, &verification) || errors.As(err, &unknown) || errors.As(err, &invalid) || errors.As(err, &hostname) {
		return false
	}
	var operation *net.OpError
	if errors.As(err, &operation) {
		return repeatable || operation.Op == "dial"
	}
	// Unwrap url.Error first: it implements net.Error even for policy failures.
	var request *url.Error
	if errors.As(err, &request) {
		err = request.Err
	}
	var network net.Error
	if repeatable && errors.As(err, &network) && network.Timeout() {
		return true
	}
	return repeatable && (errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, net.ErrClosed))
}
func apiRetryDelay(attempt int, retryAfter string) time.Duration {
	const maximum = 8 * time.Second
	text := strings.TrimSpace(retryAfter)
	numeric := text != ""
	for _, c := range text {
		if c < '0' || c > '9' {
			numeric = false
			break
		}
	}
	if numeric {
		seconds, err := strconv.ParseUint(text, 10, 64)
		if errors.Is(err, strconv.ErrRange) || seconds >= 8 {
			return maximum
		}
		if err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	attempt = max(0, min(attempt, 5))
	ceiling := (250 * time.Millisecond) << attempt
	// #nosec G404 -- Scheduling jitter is not a security-sensitive random value.
	return ceiling/2 + time.Duration(rand.Int64N(int64(ceiling/2)+1))
}
func waitAPIRetry(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return ctx.Err()
	}
}
func apiStatusMessage(status int) string {
	switch status {
	case 520:
		return "Cloudflare 520: the server returned an unknown error"
	case 521:
		return "Cloudflare 521: the server refused the connection"
	case 522:
		return "Cloudflare 522: the connection to the server timed out"
	case 523:
		return "Cloudflare 523: the server is unreachable"
	case 524:
		return "Cloudflare 524: the server did not answer in time"
	case 525:
		return "Cloudflare 525: the SSL handshake with the server failed"
	case 526:
		return "Cloudflare 526: the server's certificate is invalid"
	case 527:
		return "Cloudflare 527: the connection to the server failed"
	default:
		return fmt.Sprintf("HTTP %d: request rejected", status)
	}
}
