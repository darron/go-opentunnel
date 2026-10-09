package opentunnel

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coder/websocket"
)

type outbound struct {
	ctx    context.Context
	kind   websocket.MessageType
	data   []byte
	result chan error
}
type session struct {
	owner         *Connection
	routes        Routes
	ctx           context.Context
	cancel        context.CancelFunc
	ws            *websocket.Conn
	queue         chan outbound
	controls      chan outbound
	mu            sync.Mutex
	channels      map[uint32]*channel
	wg            sync.WaitGroup
	workers       sync.WaitGroup
	attachedAt    time.Time
	attached      atomic.Bool
	routesChanged atomic.Bool
	lastReceived  atomic.Int64
}

func newSession(x *Connection, r Routes) *session {
	ctx, cancel := context.WithCancel(x.ctx)
	return &session{owner: x, routes: r, ctx: ctx, cancel: cancel, channels: make(map[uint32]*channel), queue: make(chan outbound, 32), controls: make(chan outbound, 32)}
}

func (s *session) run() error {
	defer s.cancel()
	id := s.owner.Identity()
	u := *s.owner.client.api.endpointURL(id.ID, "/connect")
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	attachCtx, cancel := context.WithTimeout(s.ctx, s.owner.client.options.AttachTimeout)
	defer cancel()
	ws, response, err := websocket.Dial(attachCtx, u.String(), &websocket.DialOptions{HTTPClient: s.owner.client.api.client, Subprotocols: []string{"opentunnel"}, HTTPHeader: http.Header{"User-Agent": []string{"go-opentunnel/" + Version}}})
	if err != nil {
		if response != nil && response.Body != nil {
			_ = response.Body.Close()
		}
		if s.ctx.Err() != nil {
			return s.ctx.Err()
		}
		return errors.New("opentunnel: bridge handshake failed")
	}
	s.ws = ws
	defer func() {
		s.cancel()
		_ = ws.CloseNow()
		s.mu.Lock()
		for _, ch := range s.channels {
			ch.raw.abort(errors.New("bridge disconnected"))
		}
		s.mu.Unlock()
		s.wg.Wait()
		s.workers.Wait()
	}()
	ws.SetReadLimit(1024 * 1024)
	if ws.Subprotocol() != "opentunnel" {
		return errors.New("opentunnel: server did not negotiate opentunnel protocol")
	}
	attach := controlMessage{Type: "attach", Token: id.Token, Transport: "ws", Routes: routeNames(s.routes), Client: &clientInfo{Version: Version, MaxConns: s.owner.client.options.MaxConnections}}
	data, err := json.Marshal(attach)
	if err != nil {
		return err
	}
	if err = ws.Write(attachCtx, websocket.MessageText, data); err != nil {
		return errors.New("opentunnel: attach write failed")
	}
	var reply controlMessage
	for {
		kind, b, e := ws.Read(attachCtx)
		if e != nil {
			if s.ctx.Err() != nil {
				return s.ctx.Err()
			}
			return errors.New("opentunnel: bridge attach timed out or closed")
		}
		if kind != websocket.MessageText {
			continue
		}
		m, ok := decodeControl(b)
		if !ok {
			continue
		}
		if m.Type == "attach_error" {
			return &AttachError{Code: diagnosticAttachCode(m.Code)}
		}
		if m.Type == "attached" {
			reply = m
			break
		}
	}
	cancel()
	s.attachedAt = time.Now()
	s.attached.Store(true)
	s.lastReceived.Store(time.Now().UnixNano())
	s.owner.mu.Lock()
	s.owner.status.State = "connected"
	s.owner.status.Session = reply.Session
	s.owner.status.LastError = ""
	s.owner.status.ConnectedAt = time.Now()
	s.owner.mu.Unlock()
	s.owner.emit(Event{Type: "connected", Session: reply.Session, Routes: append([]string(nil), reply.Routes...)})
	s.owner.markReady()
	s.workers.Add(2)
	go func() { defer s.workers.Done(); s.writer() }()
	go func() { defer s.workers.Done(); s.heartbeat(reply.HeartbeatMS, reply.IdleTimeoutMS) }()
	for {
		kind, b, e := ws.Read(s.ctx)
		if e != nil {
			if s.ctx.Err() != nil {
				return s.ctx.Err()
			}
			return errors.New("opentunnel: bridge closed")
		}
		s.lastReceived.Store(time.Now().UnixNano())
		if kind == websocket.MessageBinary {
			id, payload, ok := decodeFrame(b)
			if !ok {
				continue
			}
			s.mu.Lock()
			ch := s.channels[id]
			s.mu.Unlock()
			if ch != nil && !ch.raw.push(payload) {
				ch.abort(ErrInboundLimit)
			}
			continue
		}
		m, ok := decodeControl(b)
		if !ok {
			continue
		}
		switch m.Type {
		case "open":
			s.open(m)
		case "ping":
			if e := s.control(controlMessage{Type: "pong", TimeSent: m.TimeSent}); e != nil {
				return e
			}
		case "end", "reset":
			s.mu.Lock()
			ch := s.channels[m.Conn]
			s.mu.Unlock()
			if ch != nil {
				if m.Type == "end" {
					ch.raw.endInbound()
				} else {
					ch.remoteReset.Store(true)
					ch.abort(errors.New("remote reset"))
				}
			}
		case "drain":
			return errors.New("opentunnel: server draining")
		}
	}
}
func (s *session) writer() {
	for {
		var msg outbound
		// Cleanup has a separate bounded queue so a blocked data producer cannot
		// retain a channel slot while waiting to send its reset.
		select {
		case msg = <-s.controls:
		default:
			select {
			case <-s.ctx.Done():
				return
			case msg = <-s.controls:
			case msg = <-s.queue:
			}
		}
		if e := msg.ctx.Err(); e != nil {
			if msg.result != nil {
				msg.result <- e
			}
			continue
		}
		// A logical send may finish on channel cancellation. Once a physical
		// write starts, only the session or transport timeout may interrupt it:
		// coder/websocket closes the shared socket on write cancellation.
		ctx, cancel := context.WithTimeout(s.ctx, s.owner.client.options.WriteTimeout)
		e := s.ws.Write(ctx, msg.kind, msg.data)
		cancel()
		if msg.result != nil {
			msg.result <- e
		}
		if e != nil {
			s.cancel()
			return
		}
	}
}
func (s *session) send(kind websocket.MessageType, data []byte) error {
	return s.sendContext(s.ctx, kind, data)
}
func (s *session) sendContext(ctx context.Context, kind websocket.MessageType, data []byte) error {
	ctx, cancel := context.WithTimeout(ctx, s.owner.client.options.WriteTimeout)
	defer cancel()
	msg := outbound{ctx: ctx, kind: kind, data: data, result: make(chan error, 1)}
	select {
	case s.queue <- msg:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case e := <-msg.result:
		return e
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (s *session) control(m controlMessage) error {
	return s.controlContext(s.ctx, m)
}
func (s *session) controlContext(ctx context.Context, m controlMessage) error {
	b, e := json.Marshal(m)
	if e != nil {
		return e
	}
	return s.sendContext(ctx, websocket.MessageText, b)
}

// enqueueControl never blocks channel teardown. Exhausting its fixed capacity
// closes the session rather than dropping resets and leaving relay channels open.
func (s *session) enqueueControl(m controlMessage) {
	b, err := json.Marshal(m)
	if err != nil {
		s.cancel()
		return
	}
	select {
	case <-s.ctx.Done():
	case s.controls <- outbound{ctx: s.ctx, kind: websocket.MessageText, data: b}:
	default:
		s.cancel()
	}
}
func (s *session) heartbeat(heartbeatMS, idleMS int) {
	interval := time.Duration(heartbeatMS) * time.Millisecond
	if interval < time.Second {
		interval = time.Second
	}
	idle := time.Duration(idleMS) * time.Millisecond
	if idle < 5*time.Second {
		idle = 5 * time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, s.lastReceived.Load())) > idle {
				s.cancel()
				return
			}
			if s.control(controlMessage{Type: "ping", TimeSent: time.Now().UnixMilli()}) != nil {
				return
			}
		}
	}
}
func (s *session) open(m controlMessage) {
	x := s.owner
	x.mu.Lock()
	route, ok := RouteForSNI(m.SNI, x.identity.Hostname)
	target := x.routes[route]
	cert := x.cert
	x.mu.Unlock()
	if !ok || target == "" {
		_ = s.control(controlMessage{Type: "reset", Conn: m.Conn, Code: "unknown_route"})
		return
	}
	s.mu.Lock()
	if old := s.channels[m.Conn]; old != nil {
		s.mu.Unlock()
		old.abort(errors.New("duplicate connection ID"))
		return
	}
	if len(s.channels) >= x.client.options.MaxConnections {
		s.mu.Unlock()
		_ = s.control(controlMessage{Type: "reset", Conn: m.Conn, Code: "too_many_connections"})
		return
	}
	channelCtx, channelCancel := context.WithCancel(s.ctx)
	ch := &channel{ctx: channelCtx, cancel: channelCancel, id: m.Conn, route: route, target: target, session: s, cert: cert}
	ch.raw = newBridgeConn(s, m.Conn, m.Peer, x.client.options.MaxInboundBytes)
	s.channels[m.Conn] = ch
	s.wg.Add(1)
	x.mu.Lock()
	x.status.Connections = len(s.channels)
	x.mu.Unlock()
	s.mu.Unlock()
	x.emit(Event{Type: "connection-opened", Conn: m.Conn, Route: route, Peer: m.Peer})
	go func() { defer s.wg.Done(); ch.forward() }()
}
func (s *session) finished(ch *channel, err error) {
	s.mu.Lock()
	if s.channels[ch.id] != ch {
		s.mu.Unlock()
		return
	}
	delete(s.channels, ch.id)
	s.owner.mu.Lock()
	s.owner.status.Connections = len(s.channels)
	s.owner.mu.Unlock()
	s.mu.Unlock()
	event := Event{Type: "connection-closed", Conn: ch.id, Route: ch.route}
	if err != nil {
		event.Error = err.Error()
	}
	s.owner.emit(event)
}

// Terminate visitor TLS locally. ECDSA keys restrict TLS 1.2 to forward-secret
// ECDHE suites; TLS 1.3 uses ephemeral key exchange.
func channelTLS(cert *tls.Certificate) *tls.Config {
	return &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*cert}, NextProtos: []string{"http/1.1"}}
}
