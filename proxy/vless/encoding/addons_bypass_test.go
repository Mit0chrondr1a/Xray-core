package encoding

import (
	"context"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func loopbackIngressContext() context.Context {
	return session.ContextWithInbound(context.Background(), &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	})
}

func TestShouldBypassVisionDNS(t *testing.T) {
	dest := xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53))
	if !ShouldBypassVisionDNS(loopbackIngressContext(), dest) {
		t.Fatal("expected loopback DNS control traffic to bypass Vision payload framing")
	}

	nonLoopback := session.ContextWithInbound(context.Background(), &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{10, 0, 0, 1}), xnet.Port(2036)),
	})
	if ShouldBypassVisionDNS(nonLoopback, dest) {
		t.Fatal("non-loopback ingress must not bypass Vision DNS framing")
	}
}

func TestShouldBypassVisionLoopbackUDP(t *testing.T) {
	loopbackCtx := loopbackIngressContext()

	if ShouldBypassVisionLoopbackUDP(loopbackCtx, xnet.UDPDestination(xnet.IPAddress([]byte{9, 9, 9, 9}), xnet.Port(12345))) {
		t.Fatal("non-DNS loopback UDP must not bypass Vision payload framing")
	}

	if !ShouldBypassVisionLoopbackUDP(loopbackCtx, xnet.UDPDestination(xnet.IPAddress([]byte{9, 9, 9, 9}), xnet.Port(853))) {
		t.Fatal("expected loopback DNS-over-UDP traffic to bypass Vision payload framing")
	}

	muxOuter := xnet.TCPDestination(xnet.DomainAddress("v1.mux.cool"), xnet.Port(666))
	allowedUDPCtx := session.ContextWithAllowedNetwork(loopbackCtx, xnet.Network_UDP)
	if ShouldBypassVisionLoopbackUDP(allowedUDPCtx, muxOuter) {
		t.Fatal("mux outer TCP flow must not bypass Vision payload framing")
	}

	if ShouldBypassVisionLoopbackUDP(loopbackCtx, muxOuter) {
		t.Fatal("mux outer TCP flow must not bypass")
	}
}
