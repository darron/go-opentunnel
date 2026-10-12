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
		typ    dto.MetricType
		labels map[string]float64
	}{
		"api_requests_total":               {dto.MetricType_COUNTER, map[string]float64{"": 20}},
		"api_errors_total":                 {dto.MetricType_COUNTER, map[string]float64{"": 2}},
		"bridge_attempts_total":            {dto.MetricType_COUNTER, map[string]float64{"": 3}},
		"bridge_attaches_total":            {dto.MetricType_COUNTER, map[string]float64{"result=ok": 4, "result=error": 5}},
		"reconnects_total":                 {dto.MetricType_COUNTER, map[string]float64{"": 6}},
		"visitor_connections_total":        {dto.MetricType_COUNTER, map[string]float64{"outcome=accepted": 7, "outcome=rejected": 9}},
		"visitor_connections_closed_total": {dto.MetricType_COUNTER, map[string]float64{"": 8}},
		"visitor_bytes_total":              {dto.MetricType_COUNTER, map[string]float64{"direction=in": 10, "direction=out": 11}},
		"dropped_events_total":             {dto.MetricType_COUNTER, map[string]float64{"": 12}},
		"bridges_attached":                 {dto.MetricType_GAUGE, map[string]float64{"": 13}},
		"visitor_connections_open":         {dto.MetricType_GAUGE, map[string]float64{"": 14}},
		"inbound_buffered_bytes":           {dto.MetricType_GAUGE, map[string]float64{"": 15}},
		"api_request_duration_seconds":     {dto.MetricType_SUMMARY, map[string]float64{"": 1.5}},
		"certificate_failures_total": {dto.MetricType_COUNTER, map[string]float64{
			"class=network": 0, "class=timeout": 0, "class=http_5xx": 0, "class=http_429": 0,
			"class=bad_body": 0, "class=nonce": 0, "class=bad_nonce": 0, "class=authz_pending": 0,
			"class=dns": 0, "class=rejected": 0, "class=other": 0,
		}},
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
		if f.GetType() != expected.typ || f.GetHelp() == "" || len(f.Metric) != len(expected.labels) {
			t.Fatalf("invalid family %v", f)
		}
		seen := make(map[string]bool)
		for _, m := range f.Metric {
			label := ""
			if len(m.Label) == 1 {
				label = m.Label[0].GetName() + "=" + m.Label[0].GetValue()
			} else if len(m.Label) > 1 {
				t.Fatalf("unexpected labels: %v", m.Label)
			}
			wantValue, ok := expected.labels[label]
			if !ok || seen[label] {
				t.Fatalf("unexpected/duplicate label %s in %s", label, name)
			}
			seen[label] = true
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
			if value != wantValue {
				t.Fatalf("%s{%s}=%v want=%v", name, label, value, wantValue)
			}
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
	if resp.StatusCode != 200 || !strings.Contains(string(body), `opentunnel_client_visitor_bytes_total{direction="in"} 10`) {
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

func TestCollectorCertificateFailureCausesAreBounded(t *testing.T) {
	source := fixedSource{opentunnel.Stats{CertificateFailures: map[opentunnel.CertificateFailureClass]uint64{opentunnel.CertificateFailureNonce: 7, "credential-label-injection": 90}}}
	registry := prometheus.NewPedanticRegistry()
	registry.MustRegister(NewCollector(source))
	families, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range families {
		if family.GetName() != "opentunnel_client_certificate_failures_total" {
			continue
		}
		if family.GetType() != dto.MetricType_COUNTER || len(family.Metric) != 11 {
			t.Fatalf("invalid bounded family: %v", family)
		}
		for _, m := range family.Metric {
			if len(m.Label) != 1 || m.Label[0].GetName() != "class" || m.Label[0].GetValue() == "credential-label-injection" {
				t.Fatalf("unsafe labels: %v", m)
			}
			want := float64(0)
			if m.Label[0].GetValue() == "nonce" {
				want = 7
			}
			if m.GetCounter().GetValue() != want {
				t.Fatalf("cause count: %v", m)
			}
		}
		return
	}
	t.Fatal("certificate failure cause family absent")
}
