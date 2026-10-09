package opentunnel

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

var dnsLabel = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
var targetLabel = regexp.MustCompile(`^[A-Za-z0-9-]+$`)

func validRoute(value string) bool   { return value == "@" || dnsLabel.MatchString(value) }
func validProfile(value string) bool { return dnsLabel.MatchString(value) }

func ValidateRoutes(routes Routes) error {
	for name, target := range routes {
		if !validRoute(name) || !validTarget(target) {
			return ErrInvalid
		}
	}
	return nil
}

func validTarget(value string) bool {
	host, port, err := net.SplitHostPort(value)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, "/\\?@#") {
		return false
	}
	if strings.Contains(host, ":") && net.ParseIP(host) == nil {
		return false
	}
	if net.ParseIP(host) == nil {
		for _, label := range strings.Split(host, ".") {
			if label == "" || len(label) > 63 || !targetLabel.MatchString(label) {
				return false
			}
		}
	}
	if len(port) > 5 {
		return false
	}
	for _, ch := range port {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	p, err := strconv.Atoi(port)
	return err == nil && p >= 1 && p <= 65535
}

func RouteForSNI(sni, hostname string) (string, bool) {
	sni, hostname = strings.ToLower(sni), strings.ToLower(hostname)
	if sni == hostname {
		return "@", true
	}
	suffix := "." + hostname
	if !strings.HasSuffix(sni, suffix) {
		return "", false
	}
	route := strings.TrimSuffix(sni, suffix)
	return route, validRoute(route) && route != "@"
}

func routeNames(routes Routes) []string {
	names := make([]string, 0, len(routes))
	for name := range routes {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func encodeFrame(conn uint32, payload []byte) []byte {
	frame := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(frame, conn)
	copy(frame[4:], payload)
	return frame
}
func decodeFrame(frame []byte) (uint32, []byte, bool) {
	if len(frame) < 4 {
		return 0, nil, false
	}
	return binary.BigEndian.Uint32(frame), frame[4:], true
}

type clientInfo struct {
	Version  string `json:"version"`
	MaxConns int    `json:"max_conns"`
}
type controlMessage struct {
	Type          string      `json:"type"`
	Token         string      `json:"token,omitempty"`
	Transport     string      `json:"transport,omitempty"`
	Client        *clientInfo `json:"client,omitempty"`
	Routes        []string    `json:"routes,omitempty"`
	Session       string      `json:"session,omitempty"`
	HeartbeatMS   int         `json:"heartbeat_ms,omitempty"`
	IdleTimeoutMS int         `json:"idle_timeout_ms,omitempty"`
	Code          string      `json:"code,omitempty"`
	Conn          uint32      `json:"conn,omitempty"`
	Peer          string      `json:"peer,omitempty"`
	SNI           string      `json:"sni,omitempty"`
	ALPN          string      `json:"alpn,omitempty"`
	TimeSent      int64       `json:"time_sent,omitempty"`
	Reason        string      `json:"reason,omitempty"`
}

// MarshalJSON writes each message's schema fields, including required zero values
// such as conn=0 and open.alpn="".
func (m controlMessage) MarshalJSON() ([]byte, error) {
	routes := m.Routes
	if routes == nil {
		routes = []string{}
	}
	switch m.Type {
	case "attach":
		return json.Marshal(struct {
			Type      string      `json:"type"`
			Token     string      `json:"token"`
			Transport string      `json:"transport"`
			Client    *clientInfo `json:"client"`
			Routes    []string    `json:"routes"`
		}{m.Type, m.Token, m.Transport, m.Client, routes})
	case "attached":
		return json.Marshal(struct {
			Type          string   `json:"type"`
			Session       string   `json:"session"`
			Routes        []string `json:"routes"`
			HeartbeatMS   int      `json:"heartbeat_ms"`
			IdleTimeoutMS int      `json:"idle_timeout_ms"`
		}{m.Type, m.Session, routes, m.HeartbeatMS, m.IdleTimeoutMS})
	case "attach_error":
		return json.Marshal(struct {
			Type string `json:"type"`
			Code string `json:"code"`
		}{m.Type, m.Code})
	case "ping", "pong":
		return json.Marshal(struct {
			Type     string `json:"type"`
			TimeSent int64  `json:"time_sent"`
		}{m.Type, m.TimeSent})
	case "drain":
		return json.Marshal(struct {
			Type   string `json:"type"`
			Reason string `json:"reason"`
		}{m.Type, m.Reason})
	case "open":
		return json.Marshal(struct {
			Type string `json:"type"`
			Conn uint32 `json:"conn"`
			Peer string `json:"peer"`
			SNI  string `json:"sni"`
			ALPN string `json:"alpn"`
		}{m.Type, m.Conn, m.Peer, m.SNI, m.ALPN})
	case "end":
		return json.Marshal(struct {
			Type string `json:"type"`
			Conn uint32 `json:"conn"`
		}{m.Type, m.Conn})
	case "reset":
		return json.Marshal(struct {
			Type string `json:"type"`
			Conn uint32 `json:"conn"`
			Code string `json:"code"`
		}{m.Type, m.Conn, m.Code})
	default:
		return json.Marshal(struct {
			Type string `json:"type"`
		}{m.Type})
	}
}

func decodeControl(data []byte) (controlMessage, bool) {
	var raw map[string]json.RawMessage
	if json.Unmarshal(data, &raw) != nil {
		return controlMessage{}, false
	}
	var msg controlMessage
	if err := json.Unmarshal(data, &msg); err != nil {
		return controlMessage{}, false
	}
	need := func(names ...string) bool {
		for _, name := range names {
			if value, ok := raw[name]; !ok || string(value) == "null" {
				return false
			}
		}
		return true
	}
	stringField := func(name string) bool {
		var value string
		return need(name) && json.Unmarshal(raw[name], &value) == nil
	}
	arrayField := func(name string) bool {
		var value []string
		return need(name) && json.Unmarshal(raw[name], &value) == nil
	}
	integerField := func(name string) bool { var value int64; return need(name) && json.Unmarshal(raw[name], &value) == nil }
	connField := func() bool { var value uint32; return need("conn") && json.Unmarshal(raw["conn"], &value) == nil }
	valid := false
	switch msg.Type {
	case "attach":
		if msg.Client != nil {
			var clientFields map[string]json.RawMessage
			_ = json.Unmarshal(raw["client"], &clientFields)
			var version string
			var maxConns int
			valid = stringField("token") && stringField("transport") && arrayField("routes") && msg.Transport == "ws" && need("client") && json.Unmarshal(clientFields["version"], &version) == nil && string(clientFields["version"]) != "null" && json.Unmarshal(clientFields["max_conns"], &maxConns) == nil && string(clientFields["max_conns"]) != "null"
		}
	case "attached":
		const maximumTimingMS = 24 * 60 * 60 * 1000
		valid = stringField("session") && arrayField("routes") && integerField("heartbeat_ms") && integerField("idle_timeout_ms") && msg.HeartbeatMS > 0 && msg.IdleTimeoutMS > 0 && msg.HeartbeatMS <= maximumTimingMS && msg.IdleTimeoutMS <= maximumTimingMS
	case "attach_error":
		valid = stringField("code") && safeControlCode(msg.Code)
	case "ping", "pong":
		valid = integerField("time_sent")
	case "drain":
		valid = stringField("reason")
	case "open":
		valid = connField() && stringField("peer") && stringField("sni") && stringField("alpn")
	case "end":
		valid = connField()
	case "reset":
		valid = connField() && stringField("code")
	}
	return msg, valid
}

func safeControlCode(code string) bool {
	// Accept future codes within the diagnostic size limit. AttachError.Error
	// quotes them for safe rendering.
	if len(code) > 256 {
		return false
	}
	for _, ch := range code {
		if ch < 32 || ch == 127 {
			return false
		}
	}
	return true
}
