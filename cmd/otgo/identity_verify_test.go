package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/darron/go-opentunnel/internal/authproxy"
	"github.com/golang-jwt/jwt/v5"
)

// These cases catch a CLI that skips cryptographic/request checks, trusts
// decoded claims, ignores captured headers, or changes a profile to verify it.
func TestAuthVerify(t *testing.T) {
	flags, paths := authFixture(t)
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	key, err := authproxy.EnsureIdentityKey(paths, cfg)
	if err != nil {
		t.Fatal(err)
	}
	configBefore, err := os.ReadFile(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	keyBefore, err := os.ReadFile(authproxy.IdentityKeyPath(paths))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	hash := sha256.Sum256([]byte("/a%23b?q=one%20two&x=1"))
	claims := func() jwt.MapClaims {
		return jwt.MapClaims{
			"iss": "https://test.opentunnel.test", "aud": "http://127.0.0.1:57732", "sub": "5176", "github_login": "darron",
			"method": "GET", "request_uri_sha256": base64.RawURLEncoding.EncodeToString(hash[:]),
			"iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": "test-assertion",
		}
	}
	sign := func(c jwt.MapClaims, signingKey ed25519.PrivateKey) string {
		t.Helper()
		token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, c)
		token.Header["typ"] = "otgo-identity+jwt"
		encoded, err := token.SignedString(signingKey)
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                               string
		change                             func(jwt.MapClaims)
		extra                              []string
		input                              string
		wrongKey, wantOK, checked, expired bool
	}{
		{name: "valid assertion", wantOK: true},
		{name: "matching captured headers", extra: []string{"--github-user", "darron", "--github-id", "5176"}, wantOK: true, checked: true},
		{name: "forged username", extra: []string{"--github-user", "attacker", "--github-id", "5176"}},
		{name: "forged id", extra: []string{"--github-user", "darron", "--github-id", "1"}},
		{name: "unpaired header", extra: []string{"--github-user", "darron"}},
		{name: "wrong key", wrongKey: true},
		{name: "wrong issuer", change: func(c jwt.MapClaims) { c["iss"] = "https://attacker.test" }},
		{name: "wrong audience", change: func(c jwt.MapClaims) { c["aud"] = "http://127.0.0.1:9000" }},
		{name: "expired", wantOK: true, expired: true, change: func(c jwt.MapClaims) {
			c["iat"] = now.Add(-time.Minute).Unix()
			c["exp"] = now.Add(-30 * time.Second).Unix()
		}},
		{name: "expired strict", extra: []string{"--require-current"}, change: func(c jwt.MapClaims) {
			c["iat"] = now.Add(-time.Minute).Unix()
			c["exp"] = now.Add(-30 * time.Second).Unix()
		}},
		{name: "expired wrong key", wrongKey: true, change: func(c jwt.MapClaims) {
			c["iat"] = now.Add(-time.Minute).Unix()
			c["exp"] = now.Add(-30 * time.Second).Unix()
		}},
		{name: "expired wrong path", extra: []string{"--request-uri", "/different"}, change: func(c jwt.MapClaims) {
			c["iat"] = now.Add(-time.Minute).Unix()
			c["exp"] = now.Add(-30 * time.Second).Unix()
		}},
		{name: "future", change: func(c jwt.MapClaims) {
			c["iat"] = now.Add(time.Minute).Unix()
			c["exp"] = now.Add(90 * time.Second).Unix()
		}},
		{name: "too long lifetime", change: func(c jwt.MapClaims) { c["exp"] = now.Add(time.Minute).Unix() }},
		{name: "wrong method", extra: []string{"--method", "POST"}},
		{name: "wrong query", extra: []string{"--request-uri", "/a%23b?x=1&q=one%20two"}},
		{name: "raw target alias", extra: []string{"--request-uri", "/a#b?q=one%20two&x=1"}},
		{name: "absolute target", extra: []string{"--request-uri", "http://127.0.0.1:57732/a%23b?q=one%20two&x=1"}},
		{name: "missing target", extra: []string{"--request-uri", ""}},
		{name: "invalid method", extra: []string{"--method", "GET\r\nInjected: yes"}},
		{name: "empty method", extra: []string{"--method", ""}},
		{name: "missing stdin flag", extra: []string{"--assertion-stdin=false"}},
		{name: "malformed", input: "not-a-jwt"},
		{name: "empty", input: "\n"},
		{name: "oversized", input: strings.Repeat("a", 4097)},
		{name: "multiline", input: "a.b.c\na.b.c"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := claims()
			if tc.change != nil {
				tc.change(c)
			}
			signingKey := key
			if tc.wrongKey {
				signingKey = other
			}
			encoded := sign(c, signingKey)
			input := encoded + "\n"
			if tc.input != "" {
				input = tc.input
			}
			args := append([]string{"auth", "verify"}, flags...)
			args = append(args, "--assertion-stdin", "--method", "GET", "--request-uri", "/a%23b?q=one%20two&x=1", "--json")
			args = append(args, tc.extra...)
			var out, errout bytes.Buffer
			err := run(t.Context(), args, strings.NewReader(input), &out, &errout)
			if (err == nil) != tc.wantOK {
				t.Fatalf("success=%v want=%v err=%v output=%s", err == nil, tc.wantOK, err, out.String())
			}
			if tc.name == "expired strict" && (err == nil || !strings.Contains(err.Error(), "--require-current")) {
				t.Fatalf("strict expiry failed for the wrong reason: %v", err)
			}
			if !tc.wantOK && out.Len() != 0 {
				t.Fatal("verification failure wrote success output")
			}
			if tc.wantOK {
				var result struct {
					Verified             bool
					ValidNow             bool
					Identity             struct{ ID, Login string }
					GitHubHeadersChecked bool
					Issuer, Audience     string
				}
				if err := json.Unmarshal(out.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.ValidNow == tc.expired || !result.Verified || result.Identity.ID != "5176" || result.Identity.Login != "darron" || result.GitHubHeadersChecked != tc.checked || result.Issuer != "https://test.opentunnel.test" || result.Audience != "http://127.0.0.1:57732" {
					t.Fatalf("wrong verification result: %+v", result)
				}
			}
			rendered := out.String() + errout.String()
			if err != nil {
				rendered += err.Error()
			}
			if strings.Contains(rendered, encoded) || strings.Contains(rendered, "do-not-print") {
				t.Fatal("assertion or profile secret leaked")
			}
		})
	}
	for path, want := range map[string][]byte{paths.AuthConfig: configBefore, authproxy.IdentityKeyPath(paths): keyBefore} {
		got, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("verification changed profile: %v", err)
		}
	}
}

func TestAuthVerifyDoesNotCreateKey(t *testing.T) {
	flags, paths := authFixture(t)
	before, err := os.ReadFile(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	args := append([]string{"auth", "verify"}, flags...)
	args = append(args, "--assertion-stdin", "--request-uri", "/")
	if err := run(t.Context(), args, strings.NewReader("a.b.c"), &out, io.Discard); err == nil {
		t.Fatal("verified without a pinned key")
	}
	if _, err := os.Lstat(authproxy.IdentityKeyPath(paths)); !os.IsNotExist(err) {
		t.Fatalf("created signing key: %v", err)
	}
	after, err := os.ReadFile(paths.AuthConfig)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("modified unpinned configuration")
	}
}

type identityFailReader struct{}

func (identityFailReader) Read([]byte) (int, error) { return 0, errors.New("fixture read failure") }

func TestAuthVerifyInputFailure(t *testing.T) {
	flags, _ := authFixture(t)
	args := append([]string{"auth", "verify"}, flags...)
	args = append(args, "--assertion-stdin", "--request-uri", "/")
	var out bytes.Buffer
	if err := run(t.Context(), args, identityFailReader{}, &out, io.Discard); err == nil || out.Len() != 0 {
		t.Fatalf("read error accepted: %v", err)
	}
}

func TestAuthVerifyRejectsUnusablePinnedKeys(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "unsafe", "wrong fingerprint", "changed backend", "foreign tunnel"} {
		t.Run(mode, func(t *testing.T) {
			flags, paths := authFixture(t)
			cfg, err := authproxy.LoadConfig(paths.AuthConfig)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := authproxy.EnsureIdentityKey(paths, cfg); err != nil {
				t.Fatal(err)
			}
			cfg, err = authproxy.LoadConfig(paths.AuthConfig)
			if err != nil {
				t.Fatal(err)
			}
			switch mode {
			case "missing":
				err = os.Remove(authproxy.IdentityKeyPath(paths))
			case "corrupt":
				err = os.WriteFile(authproxy.IdentityKeyPath(paths), []byte("broken"), 0600)
			case "unsafe":
				// #nosec G302 -- Deliberately unsafe fixture that verification must reject.
				err = os.Chmod(authproxy.IdentityKeyPath(paths), 0644)
			case "wrong fingerprint":
				cfg.IdentityKeyID = strings.Repeat("0", 64)
				err = authproxy.SaveConfig(paths.AuthConfig, cfg)
			case "changed backend":
				cfg.Upstream = "http://127.0.0.1:9000"
				err = authproxy.SaveConfig(paths.AuthConfig, cfg)
			case "foreign tunnel":
				cfg.Binding.TunnelID = "different"
				err = authproxy.SaveConfig(paths.AuthConfig, cfg)
			}
			if err != nil {
				t.Fatal(err)
			}
			args := append([]string{"auth", "verify"}, flags...)
			args = append(args, "--assertion-stdin", "--request-uri", "/")
			var out bytes.Buffer
			err = run(t.Context(), args, strings.NewReader("a.b.c"), &out, io.Discard)
			if err == nil || out.Len() != 0 {
				t.Fatalf("accepted unusable key: %v", err)
			}
			if strings.Contains(err.Error(), "malformed identity assertion") {
				t.Fatal("did not validate stored key before parsing claims")
			}
		})
	}
}

func TestAuthVerifyHTTPSAndText(t *testing.T) {
	flags, paths := authFixture(t)
	cfg, err := authproxy.LoadConfig(paths.AuthConfig)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Upstream = "https://backend.example:8443"
	if err := authproxy.SaveConfig(paths.AuthConfig, cfg); err != nil {
		t.Fatal(err)
	}
	key, err := authproxy.EnsureIdentityKey(paths, cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	hash := sha256.Sum256([]byte("/"))
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, jwt.MapClaims{
		"iss": "https://test.opentunnel.test", "aud": "https://backend.example:8443", "sub": "5176", "github_login": "darron",
		"method": "GET", "request_uri_sha256": base64.RawURLEncoding.EncodeToString(hash[:]), "iat": now.Unix(), "exp": now.Add(30 * time.Second).Unix(), "jti": "https-check",
	})
	token.Header["typ"] = "otgo-identity+jwt"
	encoded, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, expired := range []bool{false, true} {
		expires := now.Add(30 * time.Second)
		if expired {
			expires = now.Add(-30 * time.Second)
		}
		if expired {
			claims, ok := token.Claims.(jwt.MapClaims)
			if !ok {
				t.Fatal("fixture claims type")
			}
			claims["iat"] = now.Add(-time.Minute).Unix()
			claims["exp"] = expires.Unix()
			claims["nbf"] = now.Add(-40 * time.Second).Unix()
			encoded, err = token.SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
		}
		for _, checked := range []bool{false, true} {
			args := append([]string{"auth", "verify"}, flags...)
			args = append(args, "--assertion-stdin", "--request-uri", "/")
			if checked {
				args = append(args, "--github-user", "darron", "--github-id", "5176")
			}
			var out bytes.Buffer
			if err := run(t.Context(), args, strings.NewReader(encoded), &out, io.Discard); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out.String(), "Verified GitHub user: darron (ID 5176)") || !strings.Contains(out.String(), "Offline check") {
				t.Fatalf("missing diagnostic result: %s", out.String())
			}
			if !checked && !strings.Contains(out.String(), "headers were not supplied") {
				t.Fatal("claimed to check absent headers")
			}
			if checked && !strings.Contains(out.String(), "headers match") {
				t.Fatal("did not report checked headers")
			}
			if expired && (!strings.Contains(out.String(), "EXPIRED; not valid for backend access") || strings.Contains(out.String(), "currently valid") || !strings.Contains(out.String(), expires.UTC().Format("2006-01-02T15:04:05Z"))) {
				t.Fatalf("expired text misreported signed validity: %s", out.String())
			}
			if expired && (!strings.Contains(out.String(), "Issued at: "+now.Add(-time.Minute).UTC().Format("2006-01-02T15:04:05Z")) || strings.Contains(out.String(), "Valid from:")) {
				t.Fatalf("issued-at mislabeled as validity start despite later not-before: %s", out.String())
			}
			if !expired && !strings.Contains(out.String(), "currently valid") {
				t.Fatal("current assertion not reported as valid")
			}
		}
	}
}
