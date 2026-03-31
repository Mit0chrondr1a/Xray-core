package outbound

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/proxy/vless"
)

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
			name: "cone udp doq rewrites like main",
			cmd:  protocol.RequestCommandUDP,
			flow: "",
			cone: true,
			port: net.Port(853),
			want: true,
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

func TestIsVisionSharedParentCommand(t *testing.T) {
	tests := []struct {
		name string
		cmd  protocol.RequestCommand
		want bool
	}{
		{name: "mux", cmd: protocol.RequestCommandMux, want: true},
		{name: "reverse", cmd: protocol.RequestCommandRvs, want: true},
		{name: "tcp", cmd: protocol.RequestCommandTCP, want: false},
		{name: "udp", cmd: protocol.RequestCommandUDP, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isVisionSharedParentCommand(tc.cmd); got != tc.want {
				t.Fatalf("isVisionSharedParentCommand()=%v, want %v", got, tc.want)
			}
		})
	}
}
