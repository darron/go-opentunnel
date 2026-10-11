package opentunnel

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// ProxyProtocol selects a PROXY protocol preamble on a forwarded TCP connection.
// The empty value forwards application bytes without a preamble.
type ProxyProtocol string

const (
	// ProxyProtocolV1 selects the text PROXY protocol header.
	ProxyProtocolV1 ProxyProtocol = "v1"
	// ProxyProtocolV2 selects the binary header, including an authority TLV for SNI.
	ProxyProtocolV2 ProxyProtocol = "v2"
)

// RouteOptions configures local forwarding. The backend must accept the selected
// PROXY protocol; ordinary HTTP servers generally do not. These options do not
// authenticate visitors or change the bridge protocol.
type RouteOptions struct {
	// ProxyProtocol is empty, ProxyProtocolV1 or ProxyProtocolV2. Peer addresses
	// originate at the relay and must not be treated as verified identities.
	ProxyProtocol ProxyProtocol `json:"proxyProtocol,omitempty"`
}

func validateRouteOptions(routes Routes, options map[string]RouteOptions) error {
	for name, option := range options {
		if _, exists := routes[name]; !exists {
			return fmt.Errorf("%w: options require a configured route", ErrInvalid)
		}
		switch option.ProxyProtocol {
		case "", ProxyProtocolV1, ProxyProtocolV2:
		default:
			return fmt.Errorf("%w: PROXY protocol must be v1, v2 or empty", ErrInvalid)
		}
	}
	return nil
}

func copyRouteOptions(options map[string]RouteOptions) map[string]RouteOptions {
	if len(options) == 0 {
		return nil
	}
	result := make(map[string]RouteOptions, len(options))
	for name, option := range options {
		result[name] = option
	}
	return result
}

func parseProxyPeer(peer string) (netip.Addr, uint16) {
	if len(peer) > 256 || strings.Contains(peer, "%") {
		return netip.Addr{}, 0
	}
	if addr, err := netip.ParseAddr(peer); err == nil {
		return addr.Unmap(), 0
	}
	host, port, found := strings.Cut(peer, ":")
	ipv6 := strings.HasPrefix(peer, "[")
	if ipv6 {
		host, port, found = strings.Cut(peer, "]:")
		host = strings.TrimPrefix(host, "[")
	}
	if !found || len(port) == 0 || len(port) > 5 {
		return netip.Addr{}, 0
	}
	for _, digit := range port {
		if digit < '0' || digit > '9' {
			return netip.Addr{}, 0
		}
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || (ipv6 && !addr.Is6()) || (!ipv6 && !addr.Is4()) {
		return netip.Addr{}, 0
	}
	number, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return netip.Addr{}, 0
	}
	return addr.Unmap(), uint16(number)
}

func proxyHeader(version ProxyProtocol, peer, sni string) []byte {
	addr, port := parseProxyPeer(peer)
	if version == ProxyProtocolV1 {
		if !addr.IsValid() {
			return []byte("PROXY UNKNOWN\r\n")
		}
		family, destination := "TCP6", "::"
		if addr.Is4() {
			family, destination = "TCP4", "0.0.0.0"
		}
		return fmt.Appendf(nil, "PROXY %s %s %s %d 443\r\n", family, addr, destination, port)
	}
	if version != ProxyProtocolV2 {
		return nil
	}
	header := []byte{13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10, 0x20, 0, 0, 0}
	if addr.IsValid() {
		header[12] = 0x21
		if addr.Is4() {
			header[13] = 0x11
			source := addr.As4()
			header = append(header, source[:]...)
			header = append(header, make([]byte, 4)...)
		} else {
			header[13] = 0x21
			source := addr.As16()
			header = append(header, source[:]...)
			header = append(header, make([]byte, 16)...)
		}
		header = binary.BigEndian.AppendUint16(header, port)
		header = binary.BigEndian.AppendUint16(header, 443)
	}
	if len(sni) > 0 && len(sni) <= 255 {
		header = append(header, 0x02)
		// #nosec G115 -- Authority length is explicitly bounded to 255 bytes above.
		header = binary.BigEndian.AppendUint16(header, uint16(len(sni)))
		header = append(header, sni...)
	}
	// #nosec G115 -- Payload is at most 36 address bytes plus a 258-byte authority TLV.
	binary.BigEndian.PutUint16(header[14:16], uint16(len(header)-16))
	return header
}
