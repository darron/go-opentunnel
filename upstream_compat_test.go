package opentunnel

import (
	"bytes"
	"context"
	"crypto/sha1" // #nosec G505 -- RFC 6455 handshake; not used for certificate verification.
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// The optional runner downloads and checksums the actual upstream Rust codec.
// Ordinary tests stay Go-only; this test does not substitute a second Go codec.
func TestUpstreamWebSocketCodec(t *testing.T) {
	executable := os.Getenv("OTGO_UPSTREAM_WEBSOCKET_FIXTURE")
	if executable == "" {
		t.Skip("run python3 scripts/upstream_compat.py (requires Rust)")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("missing hijacker")
			return
		}
		connection, buffer, err := hijacker.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer func() { _ = connection.Close() }()
		// #nosec G401 -- SHA-1 is mandated by the WebSocket upgrade protocol.
		digest := sha1.Sum([]byte(r.Header.Get("Sec-WebSocket-Key") + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
		_, err = fmt.Fprintf(buffer, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nSec-WebSocket-Protocol: opentunnel\r\n\r\n", base64.StdEncoding.EncodeToString(digest[:]))
		if err != nil {
			t.Error(err)
			return
		}
		if err = buffer.Flush(); err != nil {
			t.Error(err)
			return
		}
		// #nosec G204 G702 -- Explicit opt-in test runner supplies a test-only codec executable.
		command := exec.CommandContext(ctx, executable)
		command.Stdin, command.Stdout = buffer.Reader, connection
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if err := command.Run(); err != nil && ctx.Err() == nil {
			t.Errorf("upstream codec: %v: %s", err, stderr.String())
		}
	}))
	defer server.Close()
	for _, size := range []int{0, 1, 125, 126, 32772, 65535, 65536, 1 << 20} {
		t.Run(strconv.Itoa(size), func(t *testing.T) {
			ws, response, err := websocket.Dial(ctx, strings.Replace(server.URL, "http:", "ws:", 1), &websocket.DialOptions{Subprotocols: []string{"opentunnel"}})
			if response != nil && response.Body != nil {
				_ = response.Body.Close()
			}
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = ws.CloseNow() }()
			ws.SetReadLimit(1 << 20)
			for _, kind := range []websocket.MessageType{websocket.MessageText, websocket.MessageBinary} {
				payload := bytes.Repeat([]byte("x"), size)
				if kind == websocket.MessageBinary && size >= 4 {
					copy(payload, []byte{0, 0, 0, 42})
				}
				result := make(chan error, 1)
				go func() {
					gotKind, data, err := ws.Read(ctx)
					if err == nil && (gotKind != kind || !bytes.Equal(data, payload)) {
						err = fmt.Errorf("echo mismatch: kind %v size %d", gotKind, len(data))
					}
					result <- err
				}()
				writer, err := ws.Writer(ctx, kind)
				if err != nil {
					t.Fatal(err)
				}
				// Large messages fragment across writes; a ping crosses the partial message.
				first := len(payload) / 2
				if _, err := writer.Write(payload[:first]); err != nil {
					t.Fatal(err)
				}
				if err := ws.Ping(ctx); err != nil {
					t.Fatal(err)
				}
				if _, err := writer.Write(payload[first:]); err != nil {
					t.Fatal(err)
				}
				if err := writer.Close(); err != nil {
					t.Fatal(err)
				}
				if err := <-result; err != nil {
					t.Fatal(err)
				}
			}
			if err := ws.Close(websocket.StatusNormalClosure, "done"); err != nil && !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
		})
	}
}
