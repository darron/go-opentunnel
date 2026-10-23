package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/darron/go-opentunnel"
)

func TestCommandConflictFailReachesRelay(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	expiry := time.Now().Add(time.Hour).Truncate(time.Second)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"demo.test", "*.demo.test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: expiry}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	id := opentunnel.Identity{ID: "demo", Hostname: "demo.test", Token: "fixture-token", PrivateKey: string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})), Certificate: cert, Chain: cert, CertificateExpiry: expiry}
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tunnel/demo/certificate":
			_ = json.NewEncoder(w).Encode(opentunnel.CertificateInfo{ID: "cert", State: opentunnel.CertificateState{Type: "ready", Certificate: cert, Chain: cert, Expiry: expiry}})
		case "/api/tunnel/demo/connect":
			ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"opentunnel"}})
			if err != nil {
				return
			}
			defer func() { _ = ws.CloseNow() }()
			ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
			defer cancel()
			_, data, err := ws.Read(ctx)
			if err != nil {
				return
			}
			var attach struct {
				Type   string   `json:"type"`
				Token  string   `json:"token"`
				Routes []string `json:"routes"`
			}
			if json.Unmarshal(data, &attach) != nil || attach.Type != "attach" || attach.Token != id.Token || len(attach.Routes) != 1 || attach.Routes[0] != "@" {
				t.Error("CLI did not send expected attachment")
				return
			}
			_ = ws.Write(ctx, websocket.MessageText, []byte(`{"type":"attach_error","code":"route_conflict"}`))
		default:
			t.Errorf("unexpected API operation: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer api.Close()
	for _, command := range []string{"connect", "listen"} {
		t.Run(command, func(t *testing.T) {
			dir := t.TempDir()
			if err := opentunnel.NewFileStorage(dir).Save(t.Context(), "unit", id); err != nil {
				t.Fatal(err)
			}
			route := "@"
			if command == "connect" {
				route += "=127.0.0.1:9"
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			var out, errout bytes.Buffer
			err := run(ctx, []string{command, "--api", api.URL, "--data-dir", dir, "--profile", "unit", "--route", route, "--on-route-conflict=fail"}, strings.NewReader(""), &out, &errout)
			var attach *opentunnel.AttachError
			if !errors.As(err, &attach) || attach.Code != "route_conflict" {
				t.Fatalf("CLI lost fail policy: %v", err)
			}
		})
	}
}
