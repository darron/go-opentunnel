package main

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"strings"
	"testing"

	"github.com/darron/go-opentunnel/identity"
	"github.com/darron/go-opentunnel/internal/authproxy"
)

func TestAuthPublicKeyOfflineStableAndReset(t *testing.T) {
	flags, paths := authFixture(t)
	var out, errout bytes.Buffer
	invoke := func(extra ...string) error {
		out.Reset()
		return run(t.Context(), append(append([]string{"auth", "public-key"}, flags...), extra...), strings.NewReader(""), &out, &errout)
	}
	if err := invoke(); err != nil {
		t.Fatal(err)
	}
	exported := append([]byte(nil), out.Bytes()...)
	public, err := identity.ParsePublicKey(exported)
	if err != nil {
		t.Fatal(err)
	}
	if err := invoke(); err != nil || !bytes.Equal(exported, out.Bytes()) {
		t.Fatalf("key changed: %v", err)
	}
	if err := invoke("--json"); err != nil {
		t.Fatal(err)
	}
	var result struct{ PublicKey, KeyID, Issuer, Audience string }
	if err := json.Unmarshal(out.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.PublicKey != string(exported) || len(result.KeyID) != 64 || result.Issuer != "https://test.opentunnel.test" || result.Audience != "http://127.0.0.1:57732" {
		t.Fatalf("export metadata: %+v", result)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(exported)
	if block.Type != "PUBLIC KEY" || !bytes.Equal(der, block.Bytes) || strings.Contains(out.String(), "do-not-print") {
		t.Fatal("private material exported")
	}
	if err := run(t.Context(), append([]string{"auth", "reset"}, flags...), strings.NewReader(""), &out, &errout); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(authproxy.IdentityKeyPath(paths)); !os.IsNotExist(err) {
		t.Fatalf("key survived reset: %v", err)
	}
}
