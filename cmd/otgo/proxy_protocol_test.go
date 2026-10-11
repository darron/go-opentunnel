package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/darron/go-opentunnel"
)

func TestConnectProxyProtocolFlags(t *testing.T) {
	for _, flags := range [][]string{
		{"--proxy-protocol", "@=v3"}, {"--proxy-protocol", "missing=v1"},
		{"--proxy-protocol", "@=v1", "--proxy-protocol", "@=v2"}, {"--proxy-protocol", "@"},
	} {
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		var out, errout bytes.Buffer
		args := append([]string{"connect", "--data-dir", t.TempDir(), "--route", "@=127.0.0.1:8080"}, flags...)
		err := run(ctx, args, strings.NewReader(""), &out, &errout)
		if err == nil || errors.Is(err, context.Canceled) || strings.Contains(err.Error(), "flag provided but not defined") {
			t.Fatalf("bad options accepted or flag missing: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var out, errout bytes.Buffer
	err := run(ctx, []string{"connect", "--data-dir", t.TempDir(), "--route", "@=127.0.0.1:8080", "--proxy-protocol", "@=v2"}, strings.NewReader(""), &out, &errout)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("valid options rejected: %v", err)
	}
}

type proxyInteractiveFixture struct {
	interactiveConnectionFixture
	options map[string]opentunnel.RouteOptions
}

func (c *proxyInteractiveFixture) Status() opentunnel.Status {
	return opentunnel.Status{Routes: opentunnel.Routes{"@": "127.0.0.1:8080"}, RouteOptions: c.options}
}
func (c *proxyInteractiveFixture) SetRoutesWithOptions(r opentunnel.Routes, o map[string]opentunnel.RouteOptions) error {
	c.options = o
	return c.SetRoutes(r)
}

func TestInteractiveProxyProtocol(t *testing.T) {
	c := &proxyInteractiveFixture{}
	if err := interactiveCommand(c, "proxy-protocol @=v2", true, io.Discard); err != nil {
		t.Fatal(err)
	}
	if c.options["@"].ProxyProtocol != opentunnel.ProxyProtocolV2 {
		t.Fatal("options not updated")
	}
	for _, command := range []string{"proxy-protocol @=v3", "proxy-protocol absent=v1", "proxy-protocol @=v1 @=v2"} {
		var out, errout bytes.Buffer
		quit, err := processInteractiveCommand(c, command, true, &out, &errout)
		if quit || err != nil || errout.Len() == 0 || out.Len() != 0 || c.options["@"].ProxyProtocol != opentunnel.ProxyProtocolV2 {
			t.Fatalf("bad input altered tunnel: %s: %v", command, err)
		}
	}
	if err := interactiveCommand(c, "proxy-protocol", true, io.Discard); err != nil {
		t.Fatal(err)
	}
	if len(c.options) != 0 {
		t.Fatal("empty command did not clear options")
	}
}
