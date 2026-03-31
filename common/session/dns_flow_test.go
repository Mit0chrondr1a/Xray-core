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
