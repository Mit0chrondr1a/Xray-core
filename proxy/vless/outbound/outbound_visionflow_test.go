package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless"
)

func TestApplyVisionFlow(t *testing.T) {
	tests := []struct {
		name       string
		flow       string
		dest       net.Destination
		wantVision bool
		wantClass  session.DNSFlowClass
	}{
		{
			name:       "vision dns keeps vision flow marker",
			flow:       vless.XRV,
			dest:       net.UDPDestination(net.IPAddress([]byte{8, 8, 8, 8}), net.Port(53)),
			wantVision: true,
			wantClass:  session.DNSFlowClassUDPControl,
		},
		{
			name:       "vision normal",
			flow:       vless.XRV,
			dest:       net.TCPDestination(net.DomainAddress("example.com"), net.Port(443)),
			wantVision: true,
			wantClass:  session.DNSFlowClassNonDNS,
		},
		{
			name:       "non vision flow",
			flow:       "xtls-rprx-direct",
			dest:       net.TCPDestination(net.DomainAddress("example.com"), net.Port(443)),
			wantVision: false,
			wantClass:  session.DNSFlowClassNonDNS,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := applyVisionFlow(session.ContextWithVisionFlow(context.Background(), false), tc.flow, tc.dest)
			if got := session.VisionFlowFromContext(ctx); got != tc.wantVision {
				t.Fatalf("VisionFlowFromContext() = %v, want %v", got, tc.wantVision)
			}
			if got := session.DNSFlowClassFromContext(ctx); got != tc.wantClass {
				t.Fatalf("DNSFlowClassFromContext() = %v, want %v", got, tc.wantClass)
			}
		})
	}
}

func TestShouldRewriteUDPToMux(t *testing.T) {
	tests := []struct {
		name string
		cmd  protocol.RequestCommand
		flow string
		cone bool
		port net.Port
		want bool
	}{
		{
			name: "vision udp dns still rewrites to mux",
			cmd:  protocol.RequestCommandUDP,
			flow: vless.XRV,
			port: net.Port(53),
			want: true,
		},
		{
			name: "vision udp 443 rewrites to mux",
			cmd:  protocol.RequestCommandUDP,
			flow: vless.XRV,
			port: net.Port(443),
			want: true,
		},
		{
			name: "cone udp non-dns rewrites to mux",
			cmd:  protocol.RequestCommandUDP,
			flow: "",
			cone: true,
			port: net.Port(1234),
			want: true,
		},
		{
			name: "cone udp dns does not rewrite",
			cmd:  protocol.RequestCommandUDP,
			flow: "",
			cone: true,
			port: net.Port(53),
			want: false,
		},
		{
			name: "tcp never rewrites",
			cmd:  protocol.RequestCommandTCP,
			flow: vless.XRV,
			port: net.Port(443),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := shouldRewriteUDPToMux(tc.cmd, tc.flow, tc.cone, tc.port)
			if got != tc.want {
				t.Fatalf("shouldRewriteUDPToMux() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEffectiveRequestFlow(t *testing.T) {
	loopbackCtx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100)),
	})
	nonLoopbackCtx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Local: net.TCPDestination(net.IPAddress([]byte{10, 0, 0, 1}), net.Port(9100)),
	})

	tests := []struct {
		name        string
		ctx         context.Context
		accountFlow string
		dest        net.Destination
		want        string
	}{
		{
			name:        "loopback tcp dns downgrades vision",
			ctx:         loopbackCtx,
			accountFlow: vless.XRV,
			dest:        net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			want:        "",
		},
		{
			name:        "loopback udp dns keeps vision for mux path",
			ctx:         loopbackCtx,
			accountFlow: vless.XRV,
			dest:        net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(853)),
			want:        vless.XRV,
		},
		{
			name:        "non-loopback tcp dns keeps configured flow",
			ctx:         nonLoopbackCtx,
			accountFlow: vless.XRV,
			dest:        net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			want:        vless.XRV,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectiveRequestFlow(tc.ctx, tc.accountFlow, tc.dest); got != tc.want {
				t.Fatalf("effectiveRequestFlow() = %q, want %q", got, tc.want)
			}
		})
	}
}
