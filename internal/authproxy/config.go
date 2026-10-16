// Package authproxy implements otgo's private HTTP authentication boundary.
package authproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const maxFileBytes = 64 << 10

type Paths struct{ AuthConfig, TokenFile, TunnelRoot string }
type Binding struct {
	TunnelID  string `json:"tunnel_id"`
	Hostname  string `json:"hostname"`
	APIOrigin string `json:"api_origin"`
}
type PasswordVerifier struct {
	Version    int    `json:"version"`
	Salt       string `json:"salt"`
	Iterations int    `json:"iterations"`
	Digest     string `json:"digest"`
}
type GitHubAccount struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}
type GitHubConfig struct {
	ClientID     string          `json:"client_id"`
	ClientSecret string          `json:"client_secret"`
	Users        []GitHubAccount `json:"users"`
	AppURL       string          `json:"app_url,omitempty"`
}
type Config struct {
	CACertFile    string           `json:"ca_cert,omitempty"`
	MetricsListen string           `json:"metrics_listen,omitempty"`
	Version       int              `json:"version"`
	Binding       Binding          `json:"binding"`
	Upstream      string           `json:"upstream"`
	Mode          string           `json:"mode"`
	Password      PasswordVerifier `json:"password"`
	GitHub        GitHubConfig     `json:"github"`
}
type diskPassword PasswordVerifier
type diskGitHub GitHubConfig
type diskConfig struct {
	CACertFile    string       `json:"ca_cert,omitempty"`
	MetricsListen string       `json:"metrics_listen,omitempty"`
	Version       int          `json:"version"`
	Binding       Binding      `json:"binding"`
	Upstream      string       `json:"upstream"`
	Mode          string       `json:"mode"`
	Password      diskPassword `json:"password"`
	GitHub        diskGitHub   `json:"github"`
}

func toDisk(c Config) diskConfig {
	return diskConfig{c.CACertFile, c.MetricsListen, c.Version, c.Binding, c.Upstream, c.Mode, diskPassword(c.Password), diskGitHub(c.GitHub)}
}
func fromDisk(c diskConfig) Config {
	return Config{c.CACertFile, c.MetricsListen, c.Version, c.Binding, c.Upstream, c.Mode, PasswordVerifier(c.Password), GitHubConfig(c.GitHub)}
}
func (g GitHubConfig) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		ClientID string          `json:"client_id"`
		Users    []GitHubAccount `json:"users"`
		AppURL   string          `json:"app_url,omitempty"`
	}{g.ClientID, g.Users, g.AppURL})
}
func (p PasswordVerifier) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Version    int `json:"version"`
		Iterations int `json:"iterations"`
	}{p.Version, p.Iterations})
}

func (c Config) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		CACertFile    string  `json:"ca_cert,omitempty"`
		MetricsListen string  `json:"metrics_listen,omitempty"`
		Version       int     `json:"version"`
		Binding       Binding `json:"binding"`
		Upstream      string  `json:"upstream"`
		Mode          string  `json:"mode"`
	}{c.CACertFile, c.MetricsListen, c.Version, c.Binding, c.Upstream, c.Mode})
}
func (c Config) Format(f fmt.State, _ rune) { b, _ := c.MarshalJSON(); _, _ = f.Write(b) }
func (g GitHubConfig) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "GitHubConfig{credentials:[REDACTED]}")
}
func (p PasswordVerifier) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprint(f, "PasswordVerifier{[REDACTED]}")
}

func ValidProfile(s string) bool {
	if len(s) == 0 || len(s) > 63 || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	for _, c := range s {
		allowed := c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
		if !allowed {
			return false
		}
	}
	return true
}
func ResolvePaths(profile, tunnelRoot, authConfig, tokenFile string) (Paths, error) {
	if profile == "" {
		profile = "default"
	}
	if !ValidProfile(profile) {
		return Paths{}, errors.New("invalid profile name")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return Paths{}, errors.New("cannot resolve home directory")
	}
	configHome := xdgHome("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	dataHome := xdgHome("XDG_DATA_HOME", filepath.Join(home, ".local", "share"))
	if tunnelRoot == "" {
		tunnelRoot = filepath.Join(dataHome, "opentunnel")
	}
	if authConfig == "" {
		authConfig = filepath.Join(configHome, "otgo", profile, "auth.json")
	}
	if tokenFile == "" {
		tokenFile = filepath.Join(dataHome, "otgo", profile, "tokens.json")
	}
	roots := []*string{&tunnelRoot, &authConfig, &tokenFile}
	for _, p := range roots {
		v, e := filepath.Abs(*p)
		if e != nil {
			return Paths{}, errors.New("cannot resolve storage path")
		}
		*p = v
	}
	if authConfig == tokenFile {
		return Paths{}, errors.New("auth config and token registry must be separate files")
	}
	return Paths{authConfig, tokenFile, tunnelRoot}, nil
}
func xdgHome(key, fallback string) string {
	v := os.Getenv(key)
	if !filepath.IsAbs(v) {
		return fallback
	}
	return v
}

func APIOrigin(raw string) (string, error) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return "", errors.New("invalid API origin")
	}
	if u.Scheme == "http" && !loopback(u.Hostname()) {
		return "", errors.New("API origin requires HTTPS or loopback")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "443" && u.Scheme == "https" || port == "80" && u.Scheme == "http" {
		port = ""
	}
	if port != "" {
		host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return u.Scheme + "://" + host, nil
}
func loopback(host string) bool {
	ip := net.ParseIP(host)
	return strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
}
func upstreamURL(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.User != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.RawPath != "" || (u.Scheme != "http" && u.Scheme != "https") || (u.Scheme == "http" && !loopback(u.Hostname())) {
		return nil, errors.New("upstream must be an HTTPS origin or loopback HTTP origin")
	}
	return u, nil
}
func ValidateBinding(c Config, b Binding) error {
	if c.Binding != b {
		return errors.New("saved auth configuration does not match tunnel identity or API; run explicit auth setup")
	}
	return nil
}
func validateConfig(c Config) error {
	if c.CACertFile != "" && (!filepath.IsAbs(c.CACertFile) || strings.ContainsRune(c.CACertFile, 0)) {
		return errors.New("ca_cert must be an absolute PEM file path")
	}
	if _, e := MetricsListenAddress(c.MetricsListen); e != nil {
		return e
	}
	if c.Version != 0 && c.Version != 1 {
		return errors.New("unsupported auth config version")
	}
	if c.Binding.TunnelID == "" || len(c.Binding.TunnelID) > 256 || c.Binding.Hostname == "" || len(c.Binding.Hostname) > 253 || strings.ContainsAny(c.Binding.Hostname, "/:\\@ \t\r\n") {
		return errors.New("invalid auth identity binding")
	}
	origin, e := APIOrigin(c.Binding.APIOrigin)
	if e != nil || origin != c.Binding.APIOrigin {
		return errors.New("invalid auth API binding")
	}
	if _, e = upstreamURL(c.Upstream); e != nil {
		return e
	}
	if c.Mode != "password" && c.Mode != "github" {
		return errors.New("auth mode must be password or github")
	}
	if c.Mode == "password" && !validVerifier(c.Password) {
		return errors.New("password verifier is missing or invalid")
	}
	if c.Mode == "github" {
		if c.GitHub.ClientID == "" || len(c.GitHub.ClientID) > 256 || c.GitHub.ClientSecret == "" || len(c.GitHub.ClientSecret) > 4096 || len(c.GitHub.Users) == 0 || len(c.GitHub.Users) > 256 {
			return errors.New("GitHub credentials and allowlist are required")
		}
		seen := make(map[int64]bool)
		for _, u := range c.GitHub.Users {
			if u.ID <= 0 || seen[u.ID] {
				return errors.New("invalid GitHub allowlist")
			}
			seen[u.ID] = true
		}
	}
	return nil
}
func LoadConfig(path string) (Config, error) {
	b, e := readPrivate(path)
	if e != nil {
		return Config{}, e
	}
	var c diskConfig
	if e = decodeStrict(b, &c); e != nil {
		return Config{}, errors.New("invalid auth configuration JSON")
	}
	cfg := fromDisk(c)
	if e = validateConfig(cfg); e != nil {
		return Config{}, e
	}
	return cfg, nil
}
func SaveConfig(path string, c Config) error {
	if e := validateConfig(c); e != nil {
		return e
	}
	c.Version = 1
	b, e := json.MarshalIndent(toDisk(c), "", "  ")
	if e != nil {
		return errors.New("cannot encode auth configuration")
	}
	return withFileLock(path, func() error { return writePrivate(path, append(b, '\n')) })
}

func ValidateUpstream(raw string) error { _, e := upstreamURL(raw); return e }

// MetricsListenAddress validates and normalizes the private metrics bind address.
// Arbitrary names are rejected without DNS resolution; localhost binds IPv4.
func MetricsListenAddress(address string) (string, error) {
	if address == "" {
		return "", nil
	}
	host, port, e := net.SplitHostPort(address)
	if e != nil {
		return "", errors.New("metrics-listen requires a loopback host:port")
	}
	n, e := strconv.Atoi(port)
	if e != nil || n < 0 || n > 65535 {
		return "", errors.New("metrics-listen port must be between 0 and 65535")
	}
	if host == "localhost" {
		host = "127.0.0.1"
	} else {
		ip, e := netip.ParseAddr(host)
		if e != nil || !ip.IsLoopback() || ip.Zone() != "" {
			return "", errors.New("metrics-listen host must be a loopback IP or localhost")
		}
	}
	return net.JoinHostPort(host, strconv.Itoa(n)), nil
}
