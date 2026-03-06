package session

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/net"
)

// DNSFlowClass describes DNS/control-plane classification for a request.
type DNSFlowClass uint8

const (
	DNSFlowClassUnset DNSFlowClass = iota
	DNSFlowClassNonDNS
	DNSFlowClassTCPControl
	DNSFlowClassUDPControl
)

func (c DNSFlowClass) String() string {
	switch c {
	case DNSFlowClassTCPControl:
		return "dns_tcp_control"
	case DNSFlowClassUDPControl:
		return "dns_udp_control"
	case DNSFlowClassNonDNS:
		return "non_dns"
	default:
		return "unset"
	}
}

// DNSPlane marks which DNS handling plane processed this request.
type DNSPlane string

const (
	DNSPlaneUnknown     DNSPlane = "unknown"
	DNSPlaneVisionGuard DNSPlane = "vision_dns_guard"
	DNSPlaneXHTTPSplit  DNSPlane = "xhttp_splitconn"
	DNSPlaneMuxXUDP     DNSPlane = "mux_xudp"
	DNSPlaneOther       DNSPlane = "other"
)

// ClassifyDNSFlow classifies DNS/control-plane based on destination network+port.
func ClassifyDNSFlow(dest net.Destination) DNSFlowClass {
	if dest.Port != net.Port(53) && dest.Port != net.Port(853) {
		return DNSFlowClassNonDNS
	}
	switch dest.Network {
	case net.Network_TCP:
		return DNSFlowClassTCPControl
	case net.Network_UDP:
		return DNSFlowClassUDPControl
	default:
		return DNSFlowClassNonDNS
	}
}

// ResolveDNSFlowClass resolves DNS flow class from context, falling back to
// outbound metadata when no explicit class was propagated.
func ResolveDNSFlowClass(ctx context.Context) DNSFlowClass {
	if class := DNSFlowClassFromContext(ctx); class != DNSFlowClassUnset {
		return class
	}
	outbounds := OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return DNSFlowClassUnset
	}
	return ClassifyDNSFlow(outbounds[len(outbounds)-1].Target)
}

// IsDNSControlPlaneClass reports whether class represents DNS control-plane.
func IsDNSControlPlaneClass(class DNSFlowClass) bool {
	return class == DNSFlowClassTCPControl || class == DNSFlowClassUDPControl
}

// IsDNSControlPlaneDestination reports whether destination is DNS control-plane.
func IsDNSControlPlaneDestination(dest net.Destination) bool {
	return IsDNSControlPlaneClass(ClassifyDNSFlow(dest))
}

// IsLoopbackAddress reports whether address is loopback-like.
func IsLoopbackAddress(addr net.Address) bool {
	if addr == nil {
		return false
	}
	switch addr.Family() {
	case net.AddressFamilyIPv4, net.AddressFamilyIPv6:
		ip := addr.IP()
		return ip != nil && ip.IsLoopback()
	case net.AddressFamilyDomain:
		return strings.EqualFold(strings.TrimSpace(addr.Domain()), "localhost")
	default:
		return false
	}
}

// IsLoopbackIngress reports whether inbound arrived on a loopback-bound
// listener. This is semantic loopback detection and does not depend on a
// specific deployment port.
func IsLoopbackIngress(inbound *Inbound) bool {
	if inbound == nil || !inbound.Local.IsValid() {
		return false
	}
	return IsLoopbackAddress(inbound.Local.Address)
}

// IsControlPlaneLoopbackIngress reports whether inbound came through loopback
// ingress and should use deterministic control-plane handling.
func IsControlPlaneLoopbackIngress(inbound *Inbound) bool {
	return IsLoopbackIngress(inbound)
}

// ShouldBypassVisionDetach reports whether Vision should keep userspace TLS
// instead of detach/zero-copy for deterministic control-plane behavior.
func ShouldBypassVisionDetach(ctx context.Context) bool {
	class := ResolveDNSFlowClass(ctx)
	if class != DNSFlowClassTCPControl && class != DNSFlowClassUDPControl {
		return false
	}
	inbound := InboundFromContext(ctx)
	// DNS control-plane bypass is restricted to control-plane loopback ingress.
	return IsControlPlaneLoopbackIngress(inbound)
}

// ShouldDowngradeVisionFlow reports whether loopback TCP DNS control traffic
// should avoid the Vision flow entirely and use plain VLESS semantics instead.
func ShouldDowngradeVisionFlow(ctx context.Context, dest net.Destination) bool {
	if ClassifyDNSFlow(dest) != DNSFlowClassTCPControl {
		return false
	}
	return IsControlPlaneLoopbackIngress(InboundFromContext(ctx))
}
