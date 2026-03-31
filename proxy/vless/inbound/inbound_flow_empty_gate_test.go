package inbound

import (
	"context"
	"net"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
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

func TestShouldSkipKTLSPromotionForParentRequest(t *testing.T) {
	t.Run("mux parent", func(t *testing.T) {
		req := &protocol.RequestHeader{Command: protocol.RequestCommandMux}
		if !shouldSkipKTLSPromotionForParentRequest(req) {
			t.Fatal("mux parent should skip kTLS promotion")
		}
	})

	t.Run("reverse parent", func(t *testing.T) {
		req := &protocol.RequestHeader{Command: protocol.RequestCommandRvs}
		if !shouldSkipKTLSPromotionForParentRequest(req) {
			t.Fatal("reverse parent should skip kTLS promotion")
		}
	})

	t.Run("direct tcp flow", func(t *testing.T) {
		req := &protocol.RequestHeader{Command: protocol.RequestCommandTCP}
		if shouldSkipKTLSPromotionForParentRequest(req) {
			t.Fatal("direct TCP flow should not skip kTLS promotion")
		}
	})
}

func TestIsSharedParentRequest(t *testing.T) {
	tests := []struct {
		name string
		req  *protocol.RequestHeader
		want bool
	}{
		{name: "nil", req: nil, want: false},
		{name: "mux", req: &protocol.RequestHeader{Command: protocol.RequestCommandMux}, want: true},
		{name: "reverse", req: &protocol.RequestHeader{Command: protocol.RequestCommandRvs}, want: true},
		{name: "tcp", req: &protocol.RequestHeader{Command: protocol.RequestCommandTCP}, want: false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSharedParentRequest(tc.req); got != tc.want {
				t.Fatalf("isSharedParentRequest()=%v, want %v", got, tc.want)
			}
		})
	}
}

type testVisionParentPromoter struct {
	outcome xtls.KTLSPromotionOutcome
	err     error
	calls   int
}

func (p *testVisionParentPromoter) EnableKTLSOutcome() (xtls.KTLSPromotionOutcome, error) {
	p.calls++
	return p.outcome, p.err
}

func TestMaybeEnableVisionParentKTLS(t *testing.T) {
	t.Run("mux parent uses compatibility path", func(t *testing.T) {
		promoter := &testVisionParentPromoter{
			outcome: xtls.KTLSPromotionOutcome{Status: xtls.KTLSPromotionEnabled},
		}
		promoted, err := maybeEnableVisionParentKTLS(context.Background(), &protocol.RequestHeader{Command: protocol.RequestCommandMux}, promoter)
		if err != nil {
			t.Fatalf("maybeEnableVisionParentKTLS() error = %v", err)
		}
		if promoted {
			t.Fatal("maybeEnableVisionParentKTLS() promoted = true, want false")
		}
		if promoter.calls != 0 {
			t.Fatalf("EnableKTLSOutcome calls=%d, want 0", promoter.calls)
		}
	})

	t.Run("enabled for reverse parent", func(t *testing.T) {
		promoter := &testVisionParentPromoter{
			outcome: xtls.KTLSPromotionOutcome{Status: xtls.KTLSPromotionEnabled},
		}
		promoted, err := maybeEnableVisionParentKTLS(context.Background(), &protocol.RequestHeader{Command: protocol.RequestCommandRvs}, promoter)
		if err != nil {
			t.Fatalf("maybeEnableVisionParentKTLS() error = %v", err)
		}
		if !promoted {
			t.Fatal("maybeEnableVisionParentKTLS() promoted = false, want true")
		}
		if promoter.calls != 1 {
			t.Fatalf("EnableKTLSOutcome calls=%d, want 1", promoter.calls)
		}
	})

	t.Run("unsupported for reverse parent", func(t *testing.T) {
		promoter := &testVisionParentPromoter{
			outcome: xtls.KTLSPromotionOutcome{Status: xtls.KTLSPromotionUnsupported},
		}
		promoted, err := maybeEnableVisionParentKTLS(context.Background(), &protocol.RequestHeader{Command: protocol.RequestCommandRvs}, promoter)
		if err != nil {
			t.Fatalf("maybeEnableVisionParentKTLS() error = %v", err)
		}
		if promoted {
			t.Fatal("maybeEnableVisionParentKTLS() promoted = true, want false")
		}
		if promoter.calls != 1 {
			t.Fatalf("EnableKTLSOutcome calls=%d, want 1", promoter.calls)
		}
	})

	t.Run("direct tcp skips promotion", func(t *testing.T) {
		promoter := &testVisionParentPromoter{
			outcome: xtls.KTLSPromotionOutcome{Status: xtls.KTLSPromotionEnabled},
		}
		promoted, err := maybeEnableVisionParentKTLS(context.Background(), &protocol.RequestHeader{Command: protocol.RequestCommandTCP}, promoter)
		if err != nil {
			t.Fatalf("maybeEnableVisionParentKTLS() error = %v", err)
		}
		if promoted {
			t.Fatal("maybeEnableVisionParentKTLS() promoted = true, want false")
		}
		if promoter.calls != 0 {
			t.Fatalf("EnableKTLSOutcome calls=%d, want 0", promoter.calls)
		}
	})
}

func TestIsMuxAndNotXUDP(t *testing.T) {
	t.Run("plain mux stream", func(t *testing.T) {
		req := &protocol.RequestHeader{Command: protocol.RequestCommandMux}
		first := buf.FromBytes([]byte{0, 0, 0, 1, 0, 0, 1})
		if !isMuxAndNotXUDP(req, first) {
			t.Fatal("stream mux should not be classified as XUDP")
		}
	})

	t.Run("xudp sentinel", func(t *testing.T) {
		req := &protocol.RequestHeader{Command: protocol.RequestCommandMux}
		first := buf.FromBytes([]byte{0, 0, 0, 0, 0, 0, 2})
		if isMuxAndNotXUDP(req, first) {
			t.Fatal("XUDP mux frame should not be treated as non-XUDP mux")
		}
	})
}
