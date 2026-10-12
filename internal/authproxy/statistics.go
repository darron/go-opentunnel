package authproxy

import (
	"github.com/prometheus/client_golang/prometheus"
	"sync/atomic"
)

var requestOutcomes = [...]string{"admitted", "auth_denied", "origin_denied", "protocol_denied", "public_denied", "unavailable", "owned"}
var responseClasses = [...]string{"1xx", "2xx", "3xx", "4xx", "5xx", "other"}
var loginModes = [...]string{"password", "github"}
var loginOutcomes = [...]string{"success", "failure"}

type statistics struct {
	requests      [len(requestOutcomes)]atomic.Uint64
	responses     [len(responseClasses)]atomic.Uint64
	backendErrors atomic.Uint64
	logins        [len(loginModes)][len(loginOutcomes)]atomic.Uint64
}

// Stats is a copied snapshot of local proxy decisions and response headers.
// A response count does not imply that a streamed body completed successfully.
type Stats struct {
	Requests         map[string]uint64
	BackendResponses map[string]uint64
	BackendErrors    uint64
	Logins           map[string]map[string]uint64
}

func (h *Handler) Stats() Stats {
	s := Stats{Requests: make(map[string]uint64, len(requestOutcomes)), BackendResponses: make(map[string]uint64, len(responseClasses)), BackendErrors: h.stats.backendErrors.Load(), Logins: make(map[string]map[string]uint64, len(loginModes))}
	for i, v := range requestOutcomes {
		s.Requests[v] = h.stats.requests[i].Load()
	}
	for i, v := range responseClasses {
		s.BackendResponses[v] = h.stats.responses[i].Load()
	}
	for i, m := range loginModes {
		s.Logins[m] = make(map[string]uint64, len(loginOutcomes))
		for j, o := range loginOutcomes {
			s.Logins[m][o] = h.stats.logins[i][j].Load()
		}
	}
	return s
}
func (s *statistics) request(outcome string) {
	for i, v := range requestOutcomes {
		if v == outcome {
			s.requests[i].Add(1)
			return
		}
	}
}
func (s *statistics) response(code int) {
	i := 5
	if code >= 100 && code < 600 {
		i = code/100 - 1
	}
	s.responses[i].Add(1)
}
func (s *statistics) login(mode int, success bool) {
	outcome := 1
	if success {
		outcome = 0
	}
	s.logins[mode][outcome].Add(1)
}

type proxyCollector struct {
	h                                   *Handler
	requests, responses, errors, logins *prometheus.Desc
}

// Collector returns a collector for this handler. Register it in a private registry.
func (h *Handler) Collector() prometheus.Collector {
	return &proxyCollector{h: h,
		requests:  prometheus.NewDesc("opentunnel_proxy_requests_total", "Local proxy routing and admission decisions.", []string{"outcome"}, nil),
		responses: prometheus.NewDesc("opentunnel_proxy_backend_responses_total", "Backend response headers received, including protocol upgrades.", []string{"class"}, nil),
		errors:    prometheus.NewDesc("opentunnel_proxy_backend_errors_total", "Reverse proxy failures handled locally.", nil, nil),
		logins:    prometheus.NewDesc("opentunnel_proxy_logins_total", "Terminal browser login attempts, recorded at trusted authentication points.", []string{"mode", "outcome"}, nil),
	}
}
func (c *proxyCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.requests
	ch <- c.responses
	ch <- c.errors
	ch <- c.logins
}
func (c *proxyCollector) Collect(ch chan<- prometheus.Metric) {
	s := c.h.Stats()
	for _, o := range requestOutcomes {
		ch <- prometheus.MustNewConstMetric(c.requests, prometheus.CounterValue, float64(s.Requests[o]), o)
	}
	for _, v := range responseClasses {
		ch <- prometheus.MustNewConstMetric(c.responses, prometheus.CounterValue, float64(s.BackendResponses[v]), v)
	}
	ch <- prometheus.MustNewConstMetric(c.errors, prometheus.CounterValue, float64(s.BackendErrors))
	for _, m := range loginModes {
		for _, o := range loginOutcomes {
			ch <- prometheus.MustNewConstMetric(c.logins, prometheus.CounterValue, float64(s.Logins[m][o]), m, o)
		}
	}
}
