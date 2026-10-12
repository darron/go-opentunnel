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
type labeledValue struct {
	label string
	value func(opentunnel.Stats) float64
}
type labeledFamily struct {
	desc   *prometheus.Desc
	values []labeledValue
}
type collector struct {
	source              interface{ Stats() opentunnel.Stats }
	samples             []sample
	duration            *prometheus.Desc
	certificateFailures *prometheus.Desc
	families            []labeledFamily
}

// NewCollector returns a collector for a Client, Connection or API. Each scrape
// uses one copied Stats snapshot. Metric names always start with
// opentunnel_client_, regardless of source scope. Labeled counters use only
// fixed direction, result, outcome or class labels matching the upstream
// vocabulary; class is selected from eleven diagnostic causes. Register
// collectors with different scopes in separate registries or wrap them with
// application-controlled constant labels to avoid duplicate metric names.
// API request duration is a summary with count and sum only, without quantiles.
// source must be non-nil and support concurrent Stats calls.
func NewCollector(source interface{ Stats() opentunnel.Stats }) prometheus.Collector {
	c := &collector{source: source, duration: desc("api_request_duration_seconds", "Total duration of completed API requests including body read and validation, in seconds.")}
	c.certificateFailures = prometheus.NewDesc("opentunnel_client_certificate_failures_total", "Validated terminal failed certificate API responses by diagnostic cause; repeated polling can count the same failed state again, not remote jobs or attempts.", []string{"class"}, nil)
	c.samples = []sample{
		{desc("api_requests_total", "Completed HTTP API requests, including failures."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.APIRequests) }},
		{desc("api_errors_total", "Completed API requests ending in transport, body, decoding, validation or HTTP status errors."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.APIErrors) }},
		{desc("bridge_attempts_total", "Relay bridge attachment attempts, including unsuccessful attempts."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.BridgeAttempts) }},
		{desc("reconnects_total", "Relay bridge attachment attempts after the first attempt on each connection."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.Reconnects) }},
		{desc("visitor_connections_closed_total", "Admitted relay visitor connections that have finished teardown."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.ConnectionsClosed) }},
		{desc("dropped_events_total", "Lifecycle events omitted from bounded event channels, retained after connection removal."), prometheus.CounterValue, func(s opentunnel.Stats) float64 { return float64(s.DroppedEvents) }},
		{desc("bridges_attached", "Currently attached relay bridges."), prometheus.GaugeValue, func(s opentunnel.Stats) float64 { return float64(s.ActiveBridges) }},
		{desc("visitor_connections_open", "Currently admitted relay visitors, including TLS handshakes and visitors waiting for listener Accept."), prometheus.GaugeValue, func(s opentunnel.Stats) float64 { return float64(s.ActiveConnections) }},
		{desc("inbound_buffered_bytes", "Relay payload bytes currently buffered for admitted visitor connections."), prometheus.GaugeValue, func(s opentunnel.Stats) float64 { return float64(s.InboundBufferedBytes) }},
	}
	c.families = []labeledFamily{
		{prometheus.NewDesc("opentunnel_client_bridge_attaches_total", "Completed relay bridge attachment attempts by result.", []string{"result"}, nil), []labeledValue{
			{"ok", func(s opentunnel.Stats) float64 { return float64(s.BridgeAttachments) }},
			{"error", func(s opentunnel.Stats) float64 { return float64(s.BridgeFailures) }},
		}},
		{prometheus.NewDesc("opentunnel_client_visitor_connections_total", "Relay visitor admissions by outcome, including handshakes and pending listener visitors.", []string{"outcome"}, nil), []labeledValue{
			{"accepted", func(s opentunnel.Stats) float64 { return float64(s.ConnectionsOpened) }},
			{"rejected", func(s opentunnel.Stats) float64 { return float64(s.ConnectionsRejected) }},
		}},
		{prometheus.NewDesc("opentunnel_client_visitor_bytes_total", "Relay data-frame payload bytes received or successfully sent, including TLS headers and handshakes, excluding relay headers and WebSocket framing/control traffic.", []string{"direction"}, nil), []labeledValue{
			{"in", func(s opentunnel.Stats) float64 { return float64(s.BytesReceived) }},
			{"out", func(s opentunnel.Stats) float64 { return float64(s.BytesSent) }},
		}},
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
	for _, family := range c.families {
		ch <- family.desc
	}
	ch <- c.duration
	ch <- c.certificateFailures
}
func (c *collector) Collect(ch chan<- prometheus.Metric) {
	snapshot := c.source.Stats()
	for _, s := range c.samples {
		ch <- prometheus.MustNewConstMetric(s.desc, s.kind, s.value(snapshot))
	}
	for _, family := range c.families {
		for _, value := range family.values {
			ch <- prometheus.MustNewConstMetric(family.desc, prometheus.CounterValue, value.value(snapshot), value.label)
		}
	}
	// Never iterate user-provided map keys: every exposed label is fixed here.
	for _, class := range [...]opentunnel.CertificateFailureClass{
		opentunnel.CertificateFailureNetwork, opentunnel.CertificateFailureTimeout,
		opentunnel.CertificateFailureHTTP5xx, opentunnel.CertificateFailureHTTP429,
		opentunnel.CertificateFailureBadBody, opentunnel.CertificateFailureNonce,
		opentunnel.CertificateFailureBadNonce, opentunnel.CertificateFailureAuthorizationPending,
		opentunnel.CertificateFailureDNS, opentunnel.CertificateFailureRejected, opentunnel.CertificateFailureOther,
	} {
		ch <- prometheus.MustNewConstMetric(c.certificateFailures, prometheus.CounterValue, float64(snapshot.CertificateFailures[class]), string(class))
	}
	ch <- prometheus.MustNewConstSummary(c.duration, snapshot.APIRequests, snapshot.APIDuration.Seconds(), nil)
}
