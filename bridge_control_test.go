package opentunnel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestAttachMessageLimitAndRecovery(t *testing.T) {
	for _, size := range []int{64 * 1024, 64*1024 + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			f := newRelay(t)
			var attempts atomic.Int32
			result := make(chan error, 1)
			f.api.bridge = func(w http.ResponseWriter, r *http.Request) {
				if attempts.Add(1) > 1 {
					f.accept(w, r)
					return
				}
				ws, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"opentunnel"}})
				if err != nil {
					result <- err
					return
				}
				defer func() { _ = ws.CloseNow() }()
				ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
				defer cancel()
				if _, _, err := ws.Read(ctx); err != nil {
					result <- err
					return
				}
				// An ignored JSON field pads a valid attached response to the exact boundary.
				prefix := `{"type":"attached","session":"boundary","routes":["@"],"heartbeat_ms":15000,"idle_timeout_ms":45000,"padding":"`
				body := prefix + strings.Repeat("x", size-len(prefix)-2) + `"}`
				if err := ws.Write(ctx, websocket.MessageText, []byte(body)); err != nil {
					result <- err
					return
				}
				if size > 64*1024 {
					_, _, err = ws.Read(ctx)
					if websocket.CloseStatus(err) != websocket.StatusMessageTooBig {
						result <- fmt.Errorf("oversized attach close: %w", err)
						return
					}
				} else {
					if err := ws.Write(ctx, websocket.MessageText, []byte(`{"type":"ping","time_sent":73}`)); err != nil {
						result <- err
						return
					}
					_, data, err := ws.Read(ctx)
					if err != nil {
						result <- fmt.Errorf("boundary attachment ping: %w", err)
						return
					}
					m, ok := decodeControl(data)
					if !ok || m.Type != "pong" || m.TimeSent != 73 {
						result <- fmt.Errorf("boundary attachment did not answer ping: %q", data)
						return
					}
				}
				result <- nil
				<-ctx.Done()
			}
			c := tunnelClient(t, f, TransportOptions{BackoffMin: time.Millisecond, BackoffMax: 5 * time.Millisecond})
			_ = listenTest(t, c, ListenOptions{Routes: []string{"@"}})
			select {
			case err := <-result:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("attachment boundary was not checked")
			}
			if size > 64*1024 {
				_ = f.next(t)
				if got := attempts.Load(); got != 2 {
					t.Fatalf("oversized attachment attempts = %d, want 2", got)
				}
			} else if got := attempts.Load(); got != 1 {
				t.Fatalf("boundary attachment attempts = %d, want 1", got)
			}
		})
	}
}

func TestReaderControlOverflowNeverBlocksBridge(t *testing.T) {
	for _, operation := range []string{"pong", "rejected open"} {
		t.Run(operation, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			s := &session{
				ctx: ctx, cancel: cancel,
				owner:    &Connection{identity: Identity{Hostname: "demo.test"}},
				controls: make(chan outbound, 1), readerControls: make(chan outbound, 1),
			}
			s.readerControls <- outbound{ctx: ctx}
			s.enqueueControl(controlMessage{Type: "reset", Conn: 7, Code: "client_io_error"})
			select {
			case queued := <-s.controls:
				m, ok := decodeControl(queued.data)
				if !ok || m.Type != "reset" || m.Conn != 7 {
					t.Fatalf("reserved teardown control corrupted: %q", queued.data)
				}
			default:
				t.Fatal("reader queue consumed reserved teardown capacity")
			}
			done := make(chan struct{})
			t.Cleanup(func() {
				cancel()
				select {
				case <-done:
				case <-time.After(time.Second):
					t.Error("reader control worker did not stop")
				}
			})
			go func() {
				defer close(done)
				if operation == "pong" {
					s.replyToPing(42)
				} else {
					s.open(controlMessage{Type: "open", Conn: 1, SNI: "missing.demo.test"})
				}
			}()
			select {
			case <-done:
			case <-time.After(200 * time.Millisecond):
				t.Fatal("full control queue blocked the bridge reader")
			}
			if ctx.Err() == nil {
				t.Fatal("control overflow silently dropped a required reply instead of closing the session")
			}
		})
	}
}

func TestWriterPrioritizesReaderControlsBeforeQueuedData(t *testing.T) {
	accepted := make(chan *websocket.Conn, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ws, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		accepted <- ws
		<-t.Context().Done()
	}))
	t.Cleanup(server.Close)
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	client, response, err := websocket.Dial(ctx, server.URL, nil)
	if response != nil && response.Body != nil {
		defer func() { _ = response.Body.Close() }()
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.CloseNow() })
	peer := <-accepted
	t.Cleanup(func() { _ = peer.CloseNow() })
	s := &session{
		ctx: ctx, cancel: cancel, ws: client,
		owner: &Connection{client: &Client{options: TransportOptions{WriteTimeout: time.Second}}},
		queue: make(chan outbound, 32), controls: make(chan outbound, 1), readerControls: make(chan outbound, 32),
	}
	for i := range 32 {
		s.queue <- outbound{ctx: ctx, kind: websocket.MessageBinary, data: encodeFrame(1, []byte("data"))}
		s.replyToPing(int64(i))
	}
	done := make(chan struct{})
	go func() { defer close(done); s.writer() }()
	t.Cleanup(func() { cancel(); <-done })
	for i := range 32 {
		kind, data, err := peer.Read(ctx)
		if err != nil {
			t.Fatal(err)
		}
		m, ok := decodeControl(data)
		if kind != websocket.MessageText || !ok || m.Type != "pong" || m.TimeSent != int64(i) {
			t.Fatalf("message %d: data overtook pending pong: kind=%v body=%q", i, kind, data)
		}
	}
	kind, data, err := peer.Read(ctx)
	if err != nil || kind != websocket.MessageBinary {
		t.Fatalf("queued application data was lost: %v %v", kind, err)
	}
	id, payload, ok := decodeFrame(data)
	if !ok || id != 1 || string(payload) != "data" {
		t.Fatalf("application frame corrupted: %q", data)
	}
}

func TestBridgeMessageLimitAndRecovery(t *testing.T) {
	f := newRelay(t)
	c := tunnelClient(t, f, TransportOptions{BackoffMin: time.Millisecond, BackoffMax: 5 * time.Millisecond})
	_ = listenTest(t, c, ListenOptions{Routes: []string{"@"}})
	s := f.next(t)
	// A maximum-sized frame on an unknown channel is ignored without closing the bridge.
	if err := s.ws.Write(s.ctx, websocket.MessageBinary, encodeFrame(99, make([]byte, 32*1024))); err != nil {
		t.Fatal(err)
	}
	if err := s.control(controlMessage{Type: "ping", TimeSent: 71}); err != nil {
		t.Fatal(err)
	}
	if pong := s.nextControl(t, "pong"); pong.TimeSent != 71 {
		t.Fatalf("boundary frame disrupted the bridge: %+v", pong)
	}
	// One extra byte must close this session; normal attachment then recovers.
	_ = s.ws.Write(s.ctx, websocket.MessageBinary, encodeFrame(99, make([]byte, 32*1024+1)))
	next := f.next(t)
	if err := next.control(controlMessage{Type: "ping", TimeSent: 72}); err != nil {
		t.Fatal(err)
	}
	if pong := next.nextControl(t, "pong"); pong.TimeSent != 72 {
		t.Fatalf("bridge did not recover: %+v", pong)
	}
}
