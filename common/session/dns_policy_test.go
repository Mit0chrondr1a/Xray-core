package session

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestClassifyDNSFlow(t *testing.T) {
	tests := []struct {
		name string
		dest net.Destination
		want DNSFlowClass
	}{
		{
			name: "tcp 53 is dns control",
			dest: net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			want: DNSFlowClassTCPControl,
		},
		{
			name: "udp 853 is dns control",
			dest: net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(853)),
			want: DNSFlowClassUDPControl,
		},
		{
			name: "tcp 443 is non-dns",
			dest: net.TCPDestination(net.DomainAddress("example.com"), net.Port(443)),
			want: DNSFlowClassNonDNS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := ClassifyDNSFlow(tc.dest); got != tc.want {
				t.Fatalf("ClassifyDNSFlow()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestResolveDNSFlowClass(t *testing.T) {
	ctx := context.Background()
	if got := ResolveDNSFlowClass(ctx); got != DNSFlowClassUnset {
		t.Fatalf("ResolveDNSFlowClass(empty)=%v, want %v", got, DNSFlowClassUnset)
	}

	ctx = ContextWithDNSFlowClass(ctx, DNSFlowClassUDPControl)
	if got := ResolveDNSFlowClass(ctx); got != DNSFlowClassUDPControl {
		t.Fatalf("ResolveDNSFlowClass(context)=%v, want %v", got, DNSFlowClassUDPControl)
	}

	ctx = context.Background()
	ctx = ContextWithOutbounds(ctx, []*Outbound{{
		Target: net.TCPDestination(net.IPAddress([]byte{8, 8, 8, 8}), net.Port(53)),
	}})
	if got := ResolveDNSFlowClass(ctx); got != DNSFlowClassTCPControl {
		t.Fatalf("ResolveDNSFlowClass(outbound)=%v, want %v", got, DNSFlowClassTCPControl)
	}
}

func TestIsControlPlaneLoopbackIngress(t *testing.T) {
	inbound := &Inbound{
		Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100)),
	}
	if !IsControlPlaneLoopbackIngress(inbound) {
		t.Fatal("loopback ingress should be detected")
	}

	inbound.Local = net.TCPDestination(net.IPAddress([]byte{10, 0, 0, 1}), net.Port(9100))
	if IsControlPlaneLoopbackIngress(inbound) {
		t.Fatal("non-loopback ingress must not be detected as control-plane loopback")
	}
}

func TestShouldBypassVisionDetach(t *testing.T) {
	tests := []struct {
		name     string
		inbound  *Inbound
		allowed  net.Network
		outbound net.Destination
		want     bool
	}{
		{
			name:     "tcp dns bypassed on loopback ingress",
			inbound:  &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100))},
			outbound: net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			want:     true,
		},
		{
			name:    "tcp dns not bypassed without loopback ingress",
			inbound: &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{10, 0, 0, 1}), net.Port(9100))},
			outbound: net.TCPDestination(
				net.IPAddress([]byte{1, 1, 1, 1}),
				net.Port(53),
			),
			want: false,
		},
		{
			name:    "udp dns bypassed on loopback ingress",
			inbound: &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100))},
			outbound: net.UDPDestination(
				net.IPAddress([]byte{1, 1, 1, 1}),
				net.Port(853),
			),
			want: true,
		},
		{
			name:    "loopback non dns udp not bypassed",
			inbound: &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100))},
			outbound: net.UDPDestination(
				net.IPAddress([]byte{9, 9, 9, 9}),
				net.Port(12345),
			),
			want: false,
		},
		{
			name:    "loopback mux udp outer tcp not bypassed",
			inbound: &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100))},
			allowed: net.Network_UDP,
			outbound: net.TCPDestination(
				net.DomainAddress("v1.mux.cool"),
				net.Port(666),
			),
			want: false,
		},
		{
			name:    "udp dns not bypassed without loopback ingress",
			inbound: &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{10, 0, 0, 1}), net.Port(9100))},
			outbound: net.UDPDestination(
				net.IPAddress([]byte{1, 1, 1, 1}),
				net.Port(853),
			),
			want: false,
		},
		{
			name:     "non dns no loopback not bypassed",
			outbound: net.TCPDestination(net.DomainAddress("example.com"), net.Port(443)),
			want:     false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.inbound != nil {
				ctx = ContextWithInbound(ctx, tc.inbound)
			}
			if tc.allowed != net.Network_Unknown {
				ctx = ContextWithAllowedNetwork(ctx, tc.allowed)
			}
			ctx = ContextWithOutbounds(ctx, []*Outbound{{Target: tc.outbound}})
			if got := ShouldBypassVisionDetach(ctx); got != tc.want {
				t.Fatalf("ShouldBypassVisionDetach()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestShouldDowngradeVisionFlow(t *testing.T) {
	tests := []struct {
		name    string
		inbound *Inbound
		dest    net.Destination
		want    bool
	}{
		{
			name:    "loopback tcp dns downgrades",
			inbound: &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100))},
			dest:    net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			want:    true,
		},
		{
			name:    "loopback udp dns stays on vision-compatible path",
			inbound: &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100))},
			dest:    net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(853)),
			want:    false,
		},
		{
			name:    "non-loopback tcp dns does not downgrade",
			inbound: &Inbound{Local: net.TCPDestination(net.IPAddress([]byte{10, 0, 0, 1}), net.Port(9100))},
			dest:    net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			want:    false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			if tc.inbound != nil {
				ctx = ContextWithInbound(ctx, tc.inbound)
			}
			if got := ShouldDowngradeVisionFlow(ctx, tc.dest); got != tc.want {
				t.Fatalf("ShouldDowngradeVisionFlow()=%v, want %v", got, tc.want)
			}
		})
	}
}
