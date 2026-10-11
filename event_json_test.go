package opentunnel

import (
	"encoding/json"
	"testing"
)

func TestEventJSONPreservesZeroVisitorID(t *testing.T) {
	for _, kind := range []string{"connection-opened", "connection-closed"} {
		for _, id := range []uint32{0, 1, ^uint32(0)} {
			data, err := json.Marshal(Event{Type: kind, Conn: id, Route: "@"})
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			if _, ok := fields["conn"]; !ok {
				t.Fatalf("%s omitted visitor ID %d: %s", kind, id, data)
			}
			var got uint32
			if err := json.Unmarshal(fields["conn"], &got); err != nil || got != id {
				t.Fatalf("%s visitor ID = %s, want %d", kind, fields["conn"], id)
			}
			if _, ok := fields["expiry"]; ok {
				t.Fatal("channel event included an unset certificate expiry")
			}
		}
	}
	data, err := json.Marshal(Event{Type: "connected", Session: "session"})
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["conn"]; ok {
		t.Fatal("non-channel event included an unused connection ID")
	}
}
