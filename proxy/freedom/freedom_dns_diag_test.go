package freedom

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

func TestNewDNSUplinkDiagnosticGuardedDNS(t *testing.T) {
	outbound := &session.Outbound{
		Target: net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
	}
	inbound := &session.Inbound{
		Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(2036)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
	diag := newDNSUplinkDiagnostic(ctx, outbound.Target)
	if diag == nil {
		t.Fatal("newDNSUplinkDiagnostic() returned nil for guarded DNS flow")
	}
	if diag.flowClass != session.DNSFlowClassTCPControl {
		t.Fatalf("flowClass=%v, want %v", diag.flowClass, session.DNSFlowClassTCPControl)
	}
}

func TestNewDNSUplinkDiagnosticNonDNS(t *testing.T) {
	outbound := &session.Outbound{
		Target: net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(443)),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{outbound})
	diag := newDNSUplinkDiagnostic(ctx, outbound.Target)
	if diag != nil {
		t.Fatal("newDNSUplinkDiagnostic() should be nil for non-DNS destination")
	}
}

func TestDNSUplinkDiagnosticWriterObserveWrite(t *testing.T) {
	diag := &dnsUplinkDiagnostic{
		startedAt: time.Now().Add(-2 * time.Millisecond),
	}
	writer := &dnsUplinkDiagnosticWriter{
		Writer: buf.Discard,
		diag:   diag,
	}
	mb := buf.MultiBuffer{buf.FromBytes([]byte("abc"))}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}
	if diag.totalBytes != 3 {
		t.Fatalf("totalBytes=%d, want 3", diag.totalBytes)
	}
	if diag.firstWriteNs <= 0 {
		t.Fatalf("firstWriteNs=%d, want >0", diag.firstWriteNs)
	}
}

func TestClassifyDNSUplinkErr(t *testing.T) {
	if got := classifyDNSUplinkErr(nil); got != "none" {
		t.Fatalf("classifyDNSUplinkErr(nil)=%q, want %q", got, "none")
	}
	if got := classifyDNSUplinkErr(context.Canceled); got != "context_canceled" {
		t.Fatalf("classifyDNSUplinkErr(context.Canceled)=%q, want %q", got, "context_canceled")
	}
}
