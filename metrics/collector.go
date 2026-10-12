// Package metrics adapts OpenTunnel statistics to the official Prometheus
// collector interface. It starts no server and registers no global collectors.
// Applications choose their own registry, HTTP handler and access policy.
package metrics

import (
	opentunnel "github.com/darron/go-opentunnel"
	"github.com/prometheus/client_golang/prometheus"
)

type sample struct {
	desc  *prometheus.Desc
	kind  prometheus.ValueType
	value func(opentunnel.Stats) float64
}
type collector struct {
	source   interface{ Stats() opentunnel.Stats }
	samples  []sample
	duration *prometheus.Desc
}

// NewCollector returns a collector for a Client, Connection or API. Each scrape
// uses one copied Stats snapshot. Metric names always start with
// opentunnel_client_, regardless of source scope, and have no labels. Register
// collectors with different scopes in separate registries or wrap them with
// application-controlled constant labels to avoid duplicate metric names.
// API request duration is a summary with count and sum only, without quantiles.
// source must be non-nil and support concurrent Stats calls.
func NewCollector(source interface{ Stats() opentunnel.Stats }) prometheus.Collector {
	c := &collector{source: source, duration: desc("api_request_duration_seconds", "Total duration of completed API requests including body read and validation, in seconds.")}
	c.samples = []sample{
		{desc("api_requests_total", "Completed HTTP API requests, including failures."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.APIRequests) }},
		{desc("api_errors_total", "Completed API requests ending in transport, body, decoding, validation or HTTP status errors."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.APIErrors) }},
		{desc("bridge_attempts_total", "Relay bridge attachment attempts, including unsuccessful attempts."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.BridgeAttempts) }},
		{desc("bridge_attachments_total", "Successfully attached relay bridges."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.BridgeAttachments) }},
		{desc("bridge_failures_total", "Unsuccessful relay bridge attachment attempts; established bridge teardown is excluded."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.BridgeFailures) }},
		{desc("reconnects_total", "Relay bridge attachment attempts after the first attempt on each connection."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.Reconnects) }},
		{desc("connections_opened_total", "Admitted relay visitor connections, including TLS handshakes and pending listener visitors."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.ConnectionsOpened) }},
		{desc("connections_closed_total", "Admitted relay visitor connections that have finished teardown."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.ConnectionsClosed) }},
		{desc("connections_rejected_total", "Relay visitor admissions rejected for route, duplicate identifier or capacity limits."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.ConnectionsRejected) }},
		{desc("bytes_received_total", "TLS record payload bytes read from the relay transport, excluding relay headers and WebSocket framing/control traffic."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.BytesReceived) }},
		{desc("bytes_sent_total", "TLS record payload bytes successfully written to the relay transport, including successful chunks before failure, excluding relay headers and WebSocket framing/control traffic."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.BytesSent) }},
		{desc("dropped_events_total", "Lifecycle events omitted from bounded event channels, retained after connection removal."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.DroppedEvents) }},
		{desc("active_bridges", "Currently attached relay bridges."), prometheus.GaugeValue, func(s opentunnel.Stats) float64 { return float64(s.ActiveBridges) }},
		{desc("active_connections", "Currently admitted relay visitors, including TLS handshakes and visitors waiting for listener Accept."), prometheus.GaugeValue, func(s opentunnel.Stats) float64 { return float64(s.ActiveConnections) }},
		{desc("inbound_buffered_bytes", "Relay payload bytes currently buffered for admitted visitor connections."), prometheus.GaugeValue, func(s opentunnel.Stats) float64 { return float64(s.InboundBufferedBytes) }},
	}
	return c
}
func desc(name, help string) *prometheus.Desc {
	return prometheus.NewDesc("opentunnel_client_"+name, help, nil, nil)
}
func (c *collector) Describe(ch chan<- *prometheus.Desc) {
	for _, s := range c.samples {
		ch <- s.desc
	}
	ch <- c.duration
}
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.source.Stats()
	for _, s := range c.samples {
		ch <- prometheus.MustNewConstMetric(s.desc, s.kind, s.value(snapshot))
	}
	ch <- prometheus.MustNewConstSummary(c.duration, snapshot.APIRequests, snapshot.APIDuration.Seconds(), nil)
}
