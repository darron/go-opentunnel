package metrics_test

import (
	"fmt"

	opentunnel "github.com/darron/go-opentunnel"
	"github.com/darron/go-opentunnel/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func ExampleNewCollector() {
	client, err := opentunnel.NewClient(opentunnel.ClientOptions{Storage: opentunnel.NewMemoryStorage()})
	if err != nil {
		panic(err)
	}
	defer func() { _ = client.Close() }()
	registry := prometheus.NewRegistry()
	registry.MustRegister(metrics.NewCollector(client))
	handler := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	// Serve handler on an administrative HTTP server with your own access policy.
	fmt.Println(handler != nil, client.Stats().APIRequests)
	// Output: true 0
}
