package opentunnel

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"

	"golang.org/x/net/http/httpproxy"
)

// proxyError reports only locally chosen text and numeric HTTP status codes.
// Keep the underlying cause for errors.Is/As, never for diagnostic formatting.
type proxyError struct {
	message   string
	cause     error
	permanent bool
}

func (e *proxyError) Error() string { return "opentunnel: outbound proxy: " + e.message }
func (e *proxyError) Unwrap() error { return e.cause }

// Snapshot the environment per transport, without changing process globals.
// Use the maintained Go matcher for NO_PROXY, including IDNA, ports and CIDRs.
//
//nolint:nilnil // net/http uses nil, nil for a direct connection.
func environmentProxy(getenv func(string) string) func(*http.Request) (*url.URL, error) {
	read := func(upper, lower string) (string, string) {
		if value := getenv(upper); value != "" {
			return value, upper
		}
		return getenv(lower), lower
	}
	all, allSource := read("ALL_PROXY", "all_proxy")
	httpValue, httpSource := read("HTTP_PROXY", "http_proxy")
	httpsValue, httpsSource := read("HTTPS_PROXY", "https_proxy")
	cgi := getenv("REQUEST_METHOD") != "" && httpValue != ""
	if httpValue == "" {
		httpValue, httpSource = all, allSource
	}
	if httpsValue == "" {
		httpsValue, httpsSource = all, allSource
	}
	noProxy, _ := read("NO_PROXY", "no_proxy")
	// A fixed valid proxy makes the matcher independent of malformed configured
	// URLs; a selected invalid proxy must fail closed rather than go direct.
	bypass := (&httpproxy.Config{HTTPProxy: "http://proxy.invalid", HTTPSProxy: "http://proxy.invalid", NoProxy: noProxy}).ProxyFunc()
	httpURL, httpErr := parseEnvironmentProxy(httpValue, httpSource)
	httpsURL, httpsErr := parseEnvironmentProxy(httpsValue, httpsSource)
	return func(req *http.Request) (*url.URL, error) {
		selected, err := httpsURL, httpsErr
		switch req.URL.Scheme {
		case "http":
			if cgi {
				return nil, &proxyError{message: "refusing HTTP_PROXY in a CGI environment", cause: ErrInvalid, permanent: true}
			}
			selected, err = httpURL, httpErr
		case "https":
		default:
			return nil, nil
		}
		match, _ := bypass(req.URL)
		if match == nil {
			return nil, nil
		}
		return selected, err
	}
}

//nolint:nilnil // An unset proxy selects a direct connection.
func parseEnvironmentProxy(value, source string) (*url.URL, error) {
	if value == "" {
		return nil, nil
	}
	invalid := func() (*url.URL, error) {
		return nil, &proxyError{message: source + " is invalid; use an http, https, socks5 or socks5h proxy URL", cause: ErrInvalid, permanent: true}
	}
	if !strings.Contains(value, "://") {
		value = "http://" + value
	}
	u, err := url.Parse(value)
	if err != nil || u.Hostname() == "" || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return invalid()
	}
	switch u.Scheme {
	case "http", "https", "socks5", "socks5h":
	default:
		return invalid()
	}
	if port := u.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return invalid()
		}
	}
	return u, nil
}

func configureProxyDiagnostics(transport *http.Transport) {
	original := transport.OnProxyConnectResponse
	transport.OnProxyConnectResponse = func(ctx context.Context, p *url.URL, req *http.Request, res *http.Response) error {
		if original != nil {
			if err := original(ctx, p, req, res); err != nil {
				return err
			}
		}
		if res.StatusCode != http.StatusOK {
			message := fmt.Sprintf("CONNECT rejected: HTTP %d %s", res.StatusCode, http.StatusText(res.StatusCode))
			switch res.StatusCode {
			case http.StatusProxyAuthRequired:
				message += "; check proxy credentials"
			case http.StatusForbidden:
				message += "; proxy policy denied the destination"
			}
			return &proxyError{message: message, permanent: res.StatusCode == http.StatusProxyAuthRequired || res.StatusCode == http.StatusForbidden}
		}
		return nil
	}
}

// Only clone transports we own. An explicitly supplied transport is a trusted
// override, including a nil Proxy function that deliberately connects directly.
func defaultProxyClient(client *http.Client) (*http.Client, bool) {
	if client == nil {
		client = &http.Client{}
	}
	if client.Transport != nil {
		return client, false
	}
	base, ok := http.DefaultTransport.(*http.Transport)
	if !ok || base == nil {
		return client, false
	}
	clone := *client
	transport := base.Clone()
	choose := environmentProxy(os.Getenv)
	transport.Proxy = func(req *http.Request) (*url.URL, error) {
		proxy, err := choose(req)
		if selected, ok := req.Context().Value(proxySelectionKey{}).(*atomic.Bool); ok && proxy != nil {
			selected.Store(true)
		}
		return proxy, err
	}
	configureProxyDiagnostics(transport)
	clone.Transport = transport
	return &clone, true
}

func safeProxyError(err error) error {
	var proxy *proxyError
	if errors.As(err, &proxy) {
		return proxy
	}
	var operation *net.OpError
	if errors.As(err, &operation) && operation.Op == "proxyconnect" {
		return &proxyError{message: "connection failed; check proxy reachability and TLS trust", cause: err}
	}
	return err
}

// net/http can return a malformed CONNECT response or a SOCKS error before the
// response hook runs. Track selection without calling a caller's Proxy callback
// twice, and redact those errors too. The underlying error remains inspectable.
type proxySelectionKey struct{}
type proxyDiagnosticTransport struct{ base http.RoundTripper }

func (t *proxyDiagnosticTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	var selected atomic.Bool
	req = req.WithContext(context.WithValue(req.Context(), proxySelectionKey{}, &selected))
	response, err := t.base.RoundTrip(req)
	if err != nil && selected.Load() {
		var proxy *proxyError
		if errors.As(err, &proxy) {
			return response, proxy
		}
		return response, &proxyError{message: "request failed; check proxy reachability, protocol and TLS trust", cause: err}
	}
	return response, err
}
func (t *proxyDiagnosticTransport) CloseIdleConnections() {
	if closer, ok := t.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}
