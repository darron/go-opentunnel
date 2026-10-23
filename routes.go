package opentunnel

import (
	"fmt"
	"strings"
)

// RootRoute selects the tunnel's root hostname instead of a subdomain.
const RootRoute = "@"

// RouteLabelPattern matches a lowercase DNS label, excluding RootRoute.
const RouteLabelPattern = `^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`

// IsValidRouteName reports whether route is RootRoute or a lowercase DNS label.
func IsValidRouteName(route string) bool { return route == RootRoute || dnsLabel.MatchString(route) }

// PublicURL returns the HTTPS URL for route on hostname. Hostname must be a DNS
// name without a scheme, port, trailing dot, or path. Invalid input or a combined
// hostname longer than 253 bytes returns ErrInvalid. This does not check DNS or
// whether a route is attached.
func PublicURL(route, hostname string) (string, error) {
	if !IsValidRouteName(route) || hostname == "" {
		return "", fmt.Errorf("%w: invalid route or hostname", ErrInvalid)
	}
	for _, b := range []byte(hostname) {
		if b > 127 {
			return "", fmt.Errorf("%w: hostname must use ASCII DNS labels", ErrInvalid)
		}
	}
	for _, label := range strings.Split(strings.ToLower(hostname), ".") {
		if !dnsLabel.MatchString(label) {
			return "", fmt.Errorf("%w: invalid hostname", ErrInvalid)
		}
	}
	if route != RootRoute {
		hostname = route + "." + hostname
	}
	if len(hostname) > 253 {
		return "", fmt.Errorf("%w: hostname exceeds 253 bytes", ErrInvalid)
	}
	return "https://" + hostname, nil
}
