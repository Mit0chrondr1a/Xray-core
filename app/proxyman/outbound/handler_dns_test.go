package outbound

import (
	"context"
	"testing"

	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestShouldBypassMuxForLoopbackControl(t *testing.T) {
	loopbackCtx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(9100)),
	})
	nonLoopbackCtx := session.ContextWithInbound(context.Background(), &session.Inbound{
		Local: net.TCPDestination(net.IPAddress([]byte{10, 0, 0, 1}), net.Port(9100)),
	})

	tests := []struct {
		name string
		ctx  context.Context
		dest net.Destination
		want bool
	}{
		{
			name: "loopback tcp dns bypasses mux",
			ctx:  loopbackCtx,
			dest: net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			want: true,
		},
		{
			name: "loopback udp dns stays eligible for xudp",
			ctx:  loopbackCtx,
			dest: net.UDPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(853)),
			want: false,
		},
		{
			name: "non-loopback tcp dns does not bypass mux",
			ctx:  nonLoopbackCtx,
			dest: net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldBypassMuxForLoopbackControl(tc.ctx, tc.dest); got != tc.want {
				t.Fatalf("shouldBypassMuxForLoopbackControl()=%v, want %v", got, tc.want)
			}
		})
	}
}
