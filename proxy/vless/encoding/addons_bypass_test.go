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

func TestShouldHonorInboundVisionPayloadBypass(t *testing.T) {
	dest := xnet.TCPDestination(xnet.IPAddress([]byte{1, 0, 0, 1}), xnet.Port(53))
	addons := &Addons{BypassVisionPayload: true}

	if !ShouldHonorInboundVisionPayloadBypass(addons, loopbackIngressContext(), dest) {
		t.Fatal("expected explicit bypass signal to be honored on loopback DNS ingress")
	}

	nonLoopback := session.ContextWithInbound(context.Background(), &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{10, 0, 0, 1}), xnet.Port(2036)),
	})
	if ShouldHonorInboundVisionPayloadBypass(addons, nonLoopback, dest) {
		t.Fatal("non-loopback ingress must not honor explicit bypass signal")
	}

	if ShouldHonorInboundVisionPayloadBypass(&Addons{}, loopbackIngressContext(), dest) {
		t.Fatal("missing explicit bypass signal must not be honored")
	}
}

func TestShouldHonorResponseVisionPayloadBypass(t *testing.T) {
	dest := xnet.TCPDestination(xnet.IPAddress([]byte{1, 0, 0, 1}), xnet.Port(53))
	if !ShouldHonorResponseVisionPayloadBypass(&Addons{BypassVisionPayload: true}, dest) {
		t.Fatal("expected response bypass signal for DNS control-plane destination")
	}

	nonDNS := xnet.TCPDestination(xnet.IPAddress([]byte{8, 8, 8, 8}), xnet.Port(443))
	if ShouldHonorResponseVisionPayloadBypass(&Addons{BypassVisionPayload: true}, nonDNS) {
		t.Fatal("non-DNS destination must not honor response bypass signal")
	}
}
