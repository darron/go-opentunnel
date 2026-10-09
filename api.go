package opentunnel

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const maxAPIResponse = 1 << 20

// API performs authenticated requests to the OpenTunnel control API.
type API struct {
	base    *url.URL
	client  *http.Client
	timeout time.Duration
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (r *cancelReadCloser) Close() error {
	err := r.ReadCloser.Close()
	r.cancel()
	return err
}

// NewAPI creates an API client for base. HTTPS bases may use any host; HTTP is
// limited to localhost or a literal loopback IP so bearer credentials are never
// sent across a network in cleartext. Redirects must remain at the initial
// origin. The supplied client is cloned before its redirect policy is hardened;
// its Transport, Jar, and redirect hook remain trusted with API credentials.
func NewAPI(base string, client *http.Client, timeout time.Duration) (*API, error) {
	if timeout < 0 {
		return nil, fmt.Errorf("%w: negative request timeout", ErrInvalid)
	}
	u, err := url.Parse(base)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme == "http" && !isLoopbackHTTPHost(u.Hostname())) {
		return nil, fmt.Errorf("%w: invalid API base URL", ErrInvalid)
	}
	if client == nil {
		client = &http.Client{}
	}
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &API{base: u, client: hardenedAPIClient(client, canonicalOrigin(u)), timeout: timeout}, nil
}

func isLoopbackHTTPHost(host string) bool {
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || (ip != nil && ip.IsLoopback())
}

type apiOrigin struct {
	scheme string
	host   string
	port   string
}

func canonicalOrigin(u *url.URL) apiOrigin {
	scheme := strings.ToLower(u.Scheme)
	port := u.Port()
	if port == "" {
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
	}
	return apiOrigin{scheme: scheme, host: strings.ToLower(u.Hostname()), port: port}
}

func (o apiOrigin) matches(u *url.URL) bool {
	return o == canonicalOrigin(u)
}

func validateAPIRedirect(initial apiOrigin, req *http.Request) error {
	if !initial.matches(req.URL) {
		return fmt.Errorf("%w: API redirect changed origin", ErrInvalid)
	}
	if req.URL.Scheme == "http" {
		if !isLoopbackHTTPHost(req.URL.Hostname()) {
			return fmt.Errorf("%w: HTTP API redirect is not loopback", ErrInvalid)
		}
	}
	return nil
}

func hardenedAPIClient(client *http.Client, initial apiOrigin) *http.Client {
	clone := *client
	original := client.CheckRedirect
	clone.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := validateAPIRedirect(initial, req); err != nil {
			return err
		}
		if original != nil {
			err := original(req, via)
			if validationErr := validateAPIRedirect(initial, req); validationErr != nil {
				return validationErr
			}
			return err
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	return &clone
}

func (a *API) endpointURL(id, suffix string) *url.URL {
	u := *a.base
	u.Path = strings.TrimRight(a.base.Path, "/") + "/api/tunnel"
	u.RawPath = strings.TrimRight(a.base.EscapedPath(), "/") + "/api/tunnel"
	if id != "" {
		u.Path += "/" + id + suffix
		u.RawPath += "/" + url.PathEscape(id) + suffix
	}
	return &u
}

func (a *API) request(ctx context.Context, method, id, suffix, token string, body []byte) (*http.Response, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: nil context", ErrInvalid)
	}
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	req, err := http.NewRequestWithContext(ctx, method, a.endpointURL(id, suffix).String(), bytes.NewReader(body))
	if err != nil {
		cancel()
		return nil, err
	}
	req.Header.Set("User-Agent", "opentunnel/"+Version)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		cancel()
		return nil, err
	}
	resp.Body = &cancelReadCloser{ReadCloser: resp.Body, cancel: cancel}
	return resp, nil
}
func (a *API) response(resp *http.Response, expected int, out any) error {
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxAPIResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxAPIResponse {
		return fmt.Errorf("%w: API response exceeds limit", ErrInvalid)
	}
	if resp.StatusCode != expected {
		var remote struct {
			Tag string `json:"_tag"`
		}
		_ = json.Unmarshal(data, &remote)
		if remote.Tag == "" {
			remote.Tag = "HttpError"
		}
		return &APIError{StatusCode: resp.StatusCode, Tag: remote.Tag, Message: "request rejected"}
	}
	if out == nil {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("%w: malformed API response", ErrInvalid)
	}
	return nil
}

// Create creates a new tunnel and returns its credentials.
func (a *API) Create(ctx context.Context) (CreateTunnelResponse, error) {
	var out CreateTunnelResponse
	resp, err := a.request(ctx, http.MethodPost, "", "", "", []byte("{}"))
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := a.response(resp, http.StatusCreated, &out); err != nil {
		return out, err
	}
	if out.Tunnel.ID == "" || out.Tunnel.Hostname == "" || out.Token == "" || (out.Tunnel.State != "online" && out.Tunnel.State != "offline") {
		return out, fmt.Errorf("%w: malformed create response", ErrInvalid)
	}
	return out, nil
}

// Get returns the current state of tunnel id using token.
func (a *API) Get(ctx context.Context, id, token string) (TunnelInfo, error) {
	var out TunnelInfo
	resp, err := a.request(ctx, http.MethodGet, id, "", token, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := a.response(resp, http.StatusOK, &out); err != nil {
		return out, err
	}
	if out.ID == "" || out.Hostname == "" || (out.State != "online" && out.State != "offline") {
		return out, fmt.Errorf("%w: malformed tunnel response", ErrInvalid)
	}
	return out, nil
}

// BindCertificate submits csr for tunnel id using token.
func (a *API) BindCertificate(ctx context.Context, id, token, csr string) (CertificateInfo, error) {
	var out CertificateInfo
	body, _ := json.Marshal(struct {
		CSR string `json:"csr"`
	}{csr})
	resp, err := a.request(ctx, http.MethodPost, id, "/certificate", token, body)
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := a.response(resp, http.StatusAccepted, &out); err != nil {
		return out, err
	}
	return validateCertificateInfo(out)
}

// Certificate returns the certificate status for tunnel id using token.
func (a *API) Certificate(ctx context.Context, id, token string) (CertificateInfo, error) {
	var out CertificateInfo
	resp, err := a.request(ctx, http.MethodGet, id, "/certificate", token, nil)
	if err != nil {
		return out, err
	}
	defer func() { _ = resp.Body.Close() }()
	if err := a.response(resp, http.StatusOK, &out); err != nil {
		return out, err
	}
	return validateCertificateInfo(out)
}

// Remove permanently removes tunnel id using token.
func (a *API) Remove(ctx context.Context, id, token string) error {
	resp, err := a.request(ctx, http.MethodDelete, id, "", token, nil)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	return a.response(resp, http.StatusNoContent, nil)
}
func validateCertificateInfo(info CertificateInfo) (CertificateInfo, error) {
	if info.ID == "" {
		return info, fmt.Errorf("%w: malformed certificate response", ErrInvalid)
	}
	switch info.State.Type {
	case "challenge":
		if info.State.Token == "" || info.State.Key == "" {
			return info, ErrInvalid
		}
	case "issuing":
	case "ready":
		if info.State.Certificate == "" || info.State.Chain == "" || info.State.Expiry.IsZero() {
			return info, ErrInvalid
		}
	case "failed":
		if info.State.Reason == "" {
			return info, ErrInvalid
		}
	default:
		return info, ErrInvalid
	}
	return info, nil
}
