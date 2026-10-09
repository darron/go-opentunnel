package opentunnel

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestSharedProtocolVectors(t *testing.T) {
	var frames []struct {
		Conn           uint32 `json:"conn"`
		Payload, Frame string
	}
	loadVector(t, "frames.json", &frames)
	for _, v := range frames {
		payload, _ := hex.DecodeString(v.Payload)
		want, _ := hex.DecodeString(v.Frame)
		if got := encodeFrame(v.Conn, payload); string(got) != string(want) {
			t.Fatalf("frame %d: %x", v.Conn, got)
		}
		conn, got, ok := decodeFrame(want)
		if !ok || conn != v.Conn || string(got) != string(payload) {
			t.Fatalf("decode %x", want)
		}
	}
	if _, _, ok := decodeFrame([]byte{1, 2, 3}); ok {
		t.Fatal("short frame accepted")
	}

	var names struct {
		Route []struct {
			Value string
			Valid bool
		}
		Profile []struct {
			Value string
			Valid bool
		}
		Target []struct {
			Value string
			Valid bool
		}
	}
	loadVector(t, "names.json", &names)
	for _, v := range names.Route {
		if validRoute(v.Value) != v.Valid {
			t.Fatalf("route %q", v.Value)
		}
	}
	for _, v := range names.Profile {
		if validProfile(v.Value) != v.Valid {
			t.Fatalf("profile %q", v.Value)
		}
	}
	for _, v := range names.Target {
		if (ValidateRoutes(Routes{"@": v.Value}) == nil) != v.Valid {
			t.Fatalf("target %q", v.Value)
		}
	}
	if err := ValidateRoutes(Routes{}); err != nil {
		t.Fatalf("empty route update: %v", err)
	}
	for _, target := range []string{"localhost:http", "localhost:-1", "localhost:+1", "localhost:000001", "localhost:65536"} {
		if err := ValidateRoutes(Routes{"@": target}); err == nil {
			t.Fatalf("accepted invalid target %q", target)
		}
	}

	var routes []struct {
		Hostname, SNI string
		Route         *string
	}
	loadVector(t, "routes.json", &routes)
	for _, v := range routes {
		got, ok := RouteForSNI(v.SNI, v.Hostname)
		if (v.Route != nil) != ok || ok && got != *v.Route {
			t.Fatalf("SNI %#v => %q %v", v, got, ok)
		}
	}
}

func TestControlRejectsOverflowTiming(t *testing.T) {
	for _, field := range []string{"heartbeat_ms", "idle_timeout_ms"} {
		frame := `{"type":"attached","session":"s","routes":[],"heartbeat_ms":15000,"idle_timeout_ms":45000,"` + field + `":9223372036855}`
		if _, ok := decodeControl([]byte(frame)); ok {
			t.Fatalf("accepted overflowing %s", field)
		}
	}
}

func TestControlVectorsAndInvalidControls(t *testing.T) {
	var vectors struct{ Client, Server, Ignored, Invalid []json.RawMessage }
	loadVector(t, "control.json", &vectors)
	for _, group := range [][]json.RawMessage{vectors.Client, vectors.Server} {
		for _, raw := range group {
			message, ok := decodeControl(raw)
			if !ok {
				t.Fatalf("valid control rejected: %s", raw)
			}
			encoded, err := json.Marshal(message)
			if err != nil {
				t.Fatal(err)
			}
			var want, got any
			if err := json.Unmarshal(raw, &want); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &got); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("control changed after marshal: got %s want %s", encoded, raw)
			}
		}
	}
	for _, group := range [][]json.RawMessage{vectors.Ignored, vectors.Invalid} {
		for _, raw := range group {
			if _, ok := decodeControl(raw); ok {
				t.Fatalf("invalid control accepted: %s", raw)
			}
		}
	}
	if _, ok := decodeControl([]byte(`{"type":"attach","token":"t","transport":"ws","routes":[],"client":{}}`)); ok {
		t.Fatal("attach without client mandatory fields accepted")
	}
	for _, raw := range []string{
		`{"type":"end","conn":null}`,
		`{"type":"attached","session":null,"routes":[],"heartbeat_ms":1,"idle_timeout_ms":1}`,
		`{"type":"attached","session":"s","routes":null,"heartbeat_ms":1,"idle_timeout_ms":1}`,
		`{"type":"attached","session":"s","routes":[],"heartbeat_ms":0,"idle_timeout_ms":1}`,
		`{"type":"attach_error","code":"bad\nsecret"}`,
	} {
		if _, ok := decodeControl([]byte(raw)); ok {
			t.Fatalf("accepted invalid control %s", raw)
		}
	}
}

func TestControlMarshalPreservesRequiredZeroAndEmptyFields(t *testing.T) {
	for _, message := range []controlMessage{
		{Type: "open", Conn: 0, Peer: "peer", SNI: "demo.opentunnel.xyz", ALPN: ""},
		{Type: "end", Conn: 0},
		{Type: "reset", Conn: 0, Code: "unknown_route"},
		{Type: "attach", Token: "token", Transport: "ws", Client: &clientInfo{Version: Version, MaxConns: 1}},
		{Type: "attached", Session: "session", HeartbeatMS: 1, IdleTimeoutMS: 2},
	} {
		encoded, err := json.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		var raw map[string]json.RawMessage
		if err := json.Unmarshal(encoded, &raw); err != nil {
			t.Fatal(err)
		}
		switch message.Type {
		case "open", "end", "reset":
			if string(raw["conn"]) != "0" {
				t.Fatalf("%s omitted zero conn: %s", message.Type, encoded)
			}
		case "attach", "attached":
			if string(raw["routes"]) != "[]" {
				t.Fatalf("%s routes = %s", message.Type, encoded)
			}
		}
		if message.Type == "open" && string(raw["alpn"]) != `""` {
			t.Fatalf("open omitted ALPN: %s", encoded)
		}
	}
}

func loadVector(t *testing.T, name string, dst any) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, dst); err != nil {
		t.Fatal(err)
	}
}

func TestControlAcceptsUnknownAttachCode(t *testing.T) {
	if _, ok := decodeControl([]byte(`{"type":"attach_error","code":"future/code v2"}`)); !ok {
		t.Fatal("unfamiliar attach code ignored")
	}
}

func FuzzDecodeFrame(f *testing.F) {
	f.Add([]byte{0, 0, 0, 1, 2, 3})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		id, p, ok := decodeFrame(b)
		if ok {
			round := encodeFrame(id, p)
			if string(round) != string(b) {
				t.Fatal("frame roundtrip")
			}
		}
	})
}
func FuzzDecodeControl(f *testing.F) {
	f.Add([]byte(`{"type":"end","conn":0}`))
	f.Add([]byte(`{"type":"future","field":1}`))
	f.Add([]byte(`null`))
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 1024*1024 {
			return
		}
		m, ok := decodeControl(b)
		if !ok {
			return
		}
		data, e := json.Marshal(m)
		if e != nil {
			t.Fatal(e)
		}
		if _, ok := decodeControl(data); !ok {
			t.Fatal("valid control failed roundtrip")
		}
	})
}
func FuzzRouteForSNI(f *testing.F) {
	f.Add("api.demo.test", "demo.test")
	f.Add("", "demo.test")
	f.Fuzz(func(t *testing.T, sni, host string) {
		route, ok := RouteForSNI(sni, host)
		if ok && !validRoute(route) {
			t.Fatal("invalid resolved route")
		}
		if ok && route != "@" && !strings.HasSuffix(strings.ToLower(sni), "."+strings.ToLower(host)) {
			t.Fatal("foreign hostname resolved")
		}
	})
}
