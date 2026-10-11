package opentunnel

import (
	"bytes"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestProxyProtocolUpstreamVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors/proxy.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Peers []struct {
			Peer    string
			Address *string
			Port    *uint16
		}
		Headers []struct {
			Version           ProxyProtocol
			Peer, SNI, Header string
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, v := range vectors.Peers {
		t.Run("peer/"+v.Peer, func(t *testing.T) {
			addr, port := parseProxyPeer(v.Peer)
			if v.Address == nil {
				if addr.IsValid() {
					t.Fatalf("accepted invalid peer %q", v.Peer)
				}
				return
			}
			if addr.String() != *v.Address || port != *v.Port {
				t.Fatalf("got %s:%d, want %s:%d", addr, port, *v.Address, *v.Port)
			}
		})
	}
	for _, v := range vectors.Headers {
		t.Run("header/"+string(v.Version)+"/"+v.Peer+"/"+v.SNI, func(t *testing.T) {
			want, err := hex.DecodeString(v.Header)
			if err != nil {
				t.Fatal(err)
			}
			got := proxyHeader(v.Version, v.Peer, v.SNI)
			if !bytes.Equal(got, want) {
				t.Fatalf("got %x, want %x", got, want)
			}
		})
	}
}

func TestProxyProtocolBounds(t *testing.T) {
	for _, peer := range []string{"[127.0.0.1]:80", "::1%lo0", "1.2.3.4:000001", "1.2.3.4:80\r\nINJECT", strings.Repeat("a", 10000)} {
		if addr, _ := parseProxyPeer(peer); addr.IsValid() {
			t.Errorf("accepted %q", peer)
		}
		if got := string(proxyHeader(ProxyProtocolV1, peer, "")); got != "PROXY UNKNOWN\r\n" {
			t.Errorf("unsafe header %q", got)
		}
	}
	for _, n := range []int{0, 255, 256, 10000} {
		b := proxyHeader(ProxyProtocolV2, "unknown", strings.Repeat("x", n))
		want := 16
		if n > 0 && n <= 255 {
			want += 3 + n
		}
		if len(b) != want {
			t.Errorf("authority length %d: got header %d, want %d", n, len(b), want)
		}
	}
}

func TestRouteOptionsRejectedBeforeProvisioning(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	for _, options := range []map[string]RouteOptions{
		{"@": {ProxyProtocol: "v3"}}, {"absent": {ProxyProtocol: ProxyProtocolV1}},
	} {
		_, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"@": "127.0.0.1:8080"}, RouteOptions: options})
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("got %v", err)
		}
	}
	if f.api.creates.Load() != 0 {
		t.Fatal("invalid options provisioned a remote tunnel")
	}
}

func TestTunnelProxyHeadersAndRouteUpdates(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{})
	routes := Routes{"@": echoTarget(t), "plain": echoTarget(t)}
	options := map[string]RouteOptions{"@": {ProxyProtocol: ProxyProtocolV1}}
	x, err := c.Connect(t.Context(), ConnectOptions{Routes: routes, RouteOptions: options})
	if err != nil {
		t.Fatal(err)
	}
	s := f.next(t)
	hostname := x.Identity().Hostname
	options["@"] = RouteOptions{ProxyProtocol: "invalid"}
	status := x.Status()
	status.RouteOptions["@"] = RouteOptions{}
	if x.Status().RouteOptions["@"].ProxyProtocol != ProxyProtocolV1 {
		t.Fatal("options were not copied")
	}
	exchange := func(id uint32, sni string, header []byte) {
		t.Helper()
		visitor := s.public(t, id, sni)
		payload := []byte("GET /secret HTTP/1.1\r\n\r\n")
		if _, err := visitor.Write(payload); err != nil {
			t.Fatal(err)
		}
		want := append(append([]byte(nil), header...), payload...)
		got := make([]byte, len(want))
		if _, err := io.ReadFull(visitor, got); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("backend bytes %q, want %q", got, want)
		}
		_ = visitor.Close()
	}
	exchange(1, hostname, []byte("PROXY TCP4 127.0.0.1 0.0.0.0 0 443\r\n"))
	exchange(2, "plain."+hostname, nil)
	updated := map[string]RouteOptions{"@": {ProxyProtocol: ProxyProtocolV2}}
	if err := x.SetRoutesWithOptions(routes, updated); err != nil {
		t.Fatal(err)
	}
	updated["@"] = RouteOptions{}
	v2, err := hex.DecodeString("0d0a0d0a000d0a515549540a211100187f00000100000000000001bb02000964656d6f2e74657374")
	if err != nil {
		t.Fatal(err)
	}
	if hostname != "demo.test" {
		t.Fatal("update literal PROXY vector for fixture hostname")
	}
	exchange(3, hostname, v2)
	if err := x.SetRoutesWithOptions(routes, map[string]RouteOptions{"@": {ProxyProtocol: "invalid"}}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("invalid update: %v", err)
	}
	if x.Status().RouteOptions["@"].ProxyProtocol != ProxyProtocolV2 {
		t.Fatal("failed update changed options")
	}
	if err := x.SetRoutes(routes); err != nil {
		t.Fatal(err)
	}
	exchange(4, hostname, nil)
	if len(x.Status().RouteOptions) != 0 {
		t.Fatal("plain route update retained options")
	}
}

func TestProxyHeaderWriteDeadlineAndPartialWrites(t *testing.T) {
	writer, reader := net.Pipe()
	defer func() { _ = writer.Close(); _ = reader.Close() }()
	start := time.Now()
	err := writeProxyHeader(writer, []byte("PROXY UNKNOWN\r\n"), 30*time.Millisecond)
	var timeout net.Error
	if !errors.As(err, &timeout) || !timeout.Timeout() || time.Since(start) > time.Second {
		t.Fatalf("unbounded header write: %v", err)
	}
	want := []byte("PROXY UNKNOWN\r\n")
	got := make([]byte, len(want))
	result := make(chan error, 1)
	go func() { _, err := io.ReadFull(reader, got); result <- err }()
	if err := writeProxyHeader(shortProxyWriter{Conn: writer}, want, time.Second); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("partial preamble %q", got)
	}
	// A successful preamble must clear its deadline for subsequent payloads.
	time.Sleep(40 * time.Millisecond)
	go func() { _, err := reader.Read(make([]byte, 1)); result <- err }()
	if _, err := writer.Write([]byte("x")); err != nil {
		t.Fatalf("header deadline leaked into payload: %v", err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}

type shortProxyWriter struct{ net.Conn }

func (c shortProxyWriter) Write(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return c.Conn.Write(p)
}

func TestProxyProtocolDoesNotDialMismatchedRoute(t *testing.T) {
	for _, version := range []ProxyProtocol{ProxyProtocolV1, ProxyProtocolV2} {
		t.Run(string(version), func(t *testing.T) {
			backend, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = backend.Close() }()
			tcp, ok := backend.(*net.TCPListener)
			if !ok {
				t.Fatal("non-TCP backend")
			}
			f := newRelay(t)
			c := tunnelClient(t, f, TransportOptions{})
			x, err := c.Connect(t.Context(), ConnectOptions{Routes: Routes{"@": backend.Addr().String(), "admin": backend.Addr().String()}, RouteOptions: map[string]RouteOptions{"admin": {ProxyProtocol: version}}})
			if err != nil {
				t.Fatal(err)
			}
			s := f.next(t)
			visitor := tls.Client(s.publicRaw(t, 1, "admin."+x.Identity().Hostname), &tls.Config{RootCAs: f.api.authority.roots, ServerName: x.Identity().Hostname, MinVersion: tls.VersionTLS12})
			defer func() { _ = visitor.Close() }()
			_ = visitor.SetDeadline(time.Now().Add(time.Second))
			if err := visitor.HandshakeContext(t.Context()); err == nil {
				t.Fatal("accepted relay/TLS route mismatch")
			}
			waitStatus(t, x, func(s Status) bool { return s.Connections == 0 })
			if err := tcp.SetDeadline(time.Now().Add(30 * time.Millisecond)); err != nil {
				t.Fatal(err)
			}
			conn, err := tcp.Accept()
			if conn != nil {
				_ = conn.Close()
				t.Fatal("unauthenticated route reached backend")
			}
			var timeout net.Error
			if !errors.As(err, &timeout) || !timeout.Timeout() {
				t.Fatalf("unexpected accept error: %v", err)
			}
		})
	}
}

func FuzzProxyPeer(f *testing.F) {
	for _, peer := range []string{"203.0.113.9:443", "[::ffff:203.0.113.9]:123", "[::1]:65536", "example.com:80", "\r\n"} {
		f.Add(peer)
	}
	f.Fuzz(func(t *testing.T, peer string) {
		header := proxyHeader(ProxyProtocolV1, peer, "")
		if !bytes.HasSuffix(header, []byte("\r\n")) || bytes.Count(header, []byte("\r\n")) != 1 || len(header) > 107 {
			t.Fatalf("unsafe v1 header %q", header)
		}
		binaryHeader := proxyHeader(ProxyProtocolV2, peer, "api.demo.test")
		if len(binaryHeader) > 16+36+3+255 {
			t.Fatal("unbounded v2 header")
		}
	})
}
