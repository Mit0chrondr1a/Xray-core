package inbound

import (
	"net"
	"testing"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/proxy/vless"
)

type splitStub struct{ net.Conn }

func (splitStub) IsSplitConn() bool { return true }

func TestFlowEmptyGateSplitConn(t *testing.T) {
	c1, _ := net.Pipe()
	t.Cleanup(func() { _ = c1.Close() })

	state, reason := flowEmptyGate(splitStub{Conn: c1})
	if state != session.CopyGateNotApplicable {
		t.Fatalf("state=%v, want %v", state, session.CopyGateNotApplicable)
	}
	if reason != session.CopyGateReasonTransportNonRawSplitConn {
		t.Fatalf("reason=%v, want %v", reason, session.CopyGateReasonTransportNonRawSplitConn)
	}
}

func TestFlowEmptyGateDefault(t *testing.T) {
	c1, _ := net.Pipe()
	t.Cleanup(func() { _ = c1.Close() })

	state, reason := flowEmptyGate(c1)
	if state != session.CopyGateForcedUserspace {
		t.Fatalf("state=%v, want %v", state, session.CopyGateForcedUserspace)
	}
	if reason != session.CopyGateReasonFlowNonVisionPolicy {
		t.Fatalf("reason=%v, want %v", reason, session.CopyGateReasonFlowNonVisionPolicy)
	}
}

func TestAllowVisionFlowDowngrade(t *testing.T) {
	loopbackInbound := &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(9100)),
	}
	nonLoopbackInbound := &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{10, 0, 0, 1}), xnet.Port(9100)),
	}

	tests := []struct {
		name        string
		inbound     *session.Inbound
		accountFlow string
		dest        xnet.Destination
		want        bool
	}{
		{
			name:        "loopback tcp dns allows downgrade",
			inbound:     loopbackInbound,
			accountFlow: vless.XRV,
			dest:        xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
			want:        true,
		},
		{
			name:        "loopback udp dns does not downgrade",
			inbound:     loopbackInbound,
			accountFlow: vless.XRV,
			dest:        xnet.UDPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(853)),
			want:        false,
		},
		{
			name:        "non-loopback tcp dns does not downgrade",
			inbound:     nonLoopbackInbound,
			accountFlow: vless.XRV,
			dest:        xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
			want:        false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := allowVisionFlowDowngrade(tc.inbound, tc.accountFlow, tc.dest); got != tc.want {
				t.Fatalf("allowVisionFlowDowngrade()=%v, want %v", got, tc.want)
			}
		})
	}
}
