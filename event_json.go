package opentunnel

import "encoding/json"

// MarshalJSON includes Conn for visitor lifecycle events even when its ID is
// zero. Other events omit an unused connection ID.
func (e Event) MarshalJSON() ([]byte, error) {
	type plain Event
	var conn *uint32
	if e.Type == "connection-opened" || e.Type == "connection-closed" || e.Conn != 0 {
		conn = &e.Conn
	}
	return json.Marshal(struct {
		plain
		Conn *uint32 `json:"conn,omitempty"`
	}{plain(e), conn})
}
