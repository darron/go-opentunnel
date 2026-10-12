package metrics

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	opentunnel "github.com/darron/go-opentunnel"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	dto "github.com/prometheus/client_model/go"
)

type fixedSource struct{ value opentunnel.Stats }

func (s fixedSource) Stats() opentunnel.Stats { return s.value }

// These checks catch omitted fields, wrong metric types, duration units,
// accidental metadata labels and a collector coupled to global registration.
func TestCollectorExactFamilies(t *testing.T) {
	source := fixedSource{opentunnel.Stats{APIRequests: 20, APIErrors: 2, APIDuration: 1500 * time.Millisecond, BridgeAttempts: 3, BridgeAttachments: 4, BridgeFailures: 5, Reconnects: 6, ConnectionsOpened: 7, ConnectionsClosed: 8, ConnectionsRejected: 9, BytesReceived: 10, BytesSent: 11, DroppedEvents: 12, ActiveBridges: 13, ActiveConnections: 14, InboundBufferedBytes: 15}}
	before, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	collector := NewCollector(source)
	registry := prometheus.NewPedanticRegistry()
	if err = registry.Register(collector); err != nil {
		t.Fatal(err)
	}
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]struct {
		typ   dto.MetricType
		value float64
	}{
		"api_requests_total": {dto.MetricType_COUNTER, 20}, "api_errors_total": {dto.MetricType_COUNTER, 2},
		"bridge_attempts_total": {dto.MetricType_COUNTER, 3}, "bridge_attachments_total": {dto.MetricType_COUNTER, 4}, "bridge_failures_total": {dto.MetricType_COUNTER, 5}, "reconnects_total": {dto.MetricType_COUNTER, 6},
		"connections_opened_total": {dto.MetricType_COUNTER, 7}, "connections_closed_total": {dto.MetricType_COUNTER, 8}, "connections_rejected_total": {dto.MetricType_COUNTER, 9}, "bytes_received_total": {dto.MetricType_COUNTER, 10}, "bytes_sent_total": {dto.MetricType_COUNTER, 11}, "dropped_events_total": {dto.MetricType_COUNTER, 12},
		"active_bridges": {dto.MetricType_GAUGE, 13}, "active_connections": {dto.MetricType_GAUGE, 14}, "inbound_buffered_bytes": {dto.MetricType_GAUGE, 15},
		"api_request_duration_seconds": {dto.MetricType_SUMMARY, 1.5},
	}
	if len(families) != len(want) {
		t.Fatalf("families=%d want=%d", len(families), len(want))
	}
	for _, f := range families {
		name := strings.TrimPrefix(f.GetName(), "opentunnel_client_")
		expected, ok := want[name]
		if !ok || f.GetName() != "opentunnel_client_"+name {
			t.Fatalf("unexpected family %q", f.GetName())
		}
		if f.GetType() != expected.typ || f.GetHelp() == "" || len(f.Metric) != 1 {
			t.Fatalf("invalid family %v", f)
		}
		m := f.Metric[0]
		if len(m.Label) != 0 {
			t.Fatalf("metadata labels=%v", m.Label)
		}
		var value float64
		switch expected.typ {
		case dto.MetricType_COUNTER:
			value = m.GetCounter().GetValue()
		case dto.MetricType_GAUGE:
			value = m.GetGauge().GetValue()
		case dto.MetricType_SUMMARY:
			value = m.GetSummary().GetSampleSum()
			if m.GetSummary().GetSampleCount() != 20 || len(m.GetSummary().Quantile) != 0 {
				t.Fatalf("summary=%v", m.GetSummary())
			}
		}
		if value != expected.value {
			t.Fatalf("%s=%v want=%v", name, value, expected.value)
		}
	}
	after, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(before) != len(after) {
		t.Fatal("collector registered globally")
	}
	const expected = `# HELP opentunnel_client_api_request_duration_seconds Total duration of completed API requests including body read and validation, in seconds.
# TYPE opentunnel_client_api_request_duration_seconds summary
opentunnel_client_api_request_duration_seconds_sum 1.5
opentunnel_client_api_request_duration_seconds_count 20
# HELP opentunnel_client_api_requests_total Completed HTTP API requests, including failures.
# TYPE opentunnel_client_api_requests_total counter
opentunnel_client_api_requests_total 20
`
	names := []string{"opentunnel_client_api_request_duration_seconds", "opentunnel_client_api_requests_total"}
	if err := testutil.GatherAndCompare(registry, strings.NewReader(expected), names...); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	defer server.Close()
	if err := testutil.ScrapeAndCompare(server.URL, strings.NewReader(expected), names...); err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 || !strings.Contains(string(body), "opentunnel_client_bytes_received_total 10") {
		t.Fatalf("scrape=%d %s", resp.StatusCode, body)
	}
	for _, forbidden := range []string{"token=", "hostname=", "route=", "session=", "peer=", "profile=", "go_goroutines", "process_"} {
		if strings.Contains(string(body), forbidden) {
			t.Fatalf("prohibited metadata %q", forbidden)
		}
	}
}

func TestCollectorConcurrentAPIRequestsAndScrapes(t *testing.T) {
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"id":"demo","hostname":"demo.test","state":"online"}`)
	}))
	defer apiServer.Close()
	client, err := opentunnel.NewClient(opentunnel.ClientOptions{API: apiServer.URL, Storage: opentunnel.NewMemoryStorage()})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = client.Close() }()
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewCollector(client))
	apiRegistry := prometheus.NewPedanticRegistry()
	apiRegistry.MustRegister(NewCollector(client.API()))
	server := httptest.NewServer(promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
	defer server.Close()
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				if _, e := client.API().Get(t.Context(), "demo", "token"); e != nil {
					t.Error(e)
				}
				_ = client.Stats()
				if _, e := registry.Gather(); e != nil {
					t.Error(e)
				}
				if _, e := apiRegistry.Gather(); e != nil {
					t.Error(e)
				}
				req, e := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL, nil)
				if e != nil {
					t.Error(e)
					return
				}
				resp, e := http.DefaultClient.Do(req)
				if e != nil {
					t.Error(e)
					return
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				_ = resp.Body.Close()
				if resp.StatusCode != 200 {
					t.Errorf("scrape status=%d", resp.StatusCode)
				}
			}
		}()
	}
	wg.Wait()
	if client.Stats().APIRequests != 80 || client.Stats().APIErrors != 0 {
		t.Fatalf("final stats=%+v", client.Stats())
	}
}
