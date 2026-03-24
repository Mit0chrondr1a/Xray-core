package freedom

import (
	"context"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/tls"
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
		dns:    diag,
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

func TestNewVisionUplinkDiagnosticPendingDetachTCP(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	diag := newVisionUplinkDiagnostic(inbound, net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(443)))
	if diag == nil {
		t.Fatal("newVisionUplinkDiagnostic() returned nil for pending-detach TCP flow")
	}
}

func TestNewVisionUplinkDiagnosticIgnoresDNSAndNonPending(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.SetCanSpliceCopy(session.CopyGateEligible)
	if diag := newVisionUplinkDiagnostic(inbound, net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(443))); diag != nil {
		t.Fatal("newVisionUplinkDiagnostic() should be nil for non-pending flow")
	}

	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	if diag := newVisionUplinkDiagnostic(inbound, net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53))); diag != nil {
		t.Fatal("newVisionUplinkDiagnostic() should be nil for DNS flow")
	}
}

func TestVisionUplinkDiagnosticWriterObserveWrite(t *testing.T) {
	diag := &visionUplinkDiagnostic{
		startedAt: time.Now().Add(-2 * time.Millisecond),
	}
	writer := &dnsUplinkDiagnosticWriter{
		Writer: buf.Discard,
		vision: diag,
	}
	mb := buf.MultiBuffer{buf.FromBytes([]byte("abcd"))}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}
	if diag.totalBytes != 4 {
		t.Fatalf("totalBytes=%d, want 4", diag.totalBytes)
	}
	if diag.firstWriteNs <= 0 {
		t.Fatalf("firstWriteNs=%d, want >0", diag.firstWriteNs)
	}
}

func TestObserveVisionPendingDetachOnUplinkCompleteLeavesPlainNonDeferredFlowUntouched(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, 10*time.Millisecond)
	defer timer.SetTimeout(0)

	downlinkTimeout := 10 * time.Millisecond
	func() {
		defer func() {
			timer.SetTimeout(downlinkTimeout)
		}()
		observeVisionPendingDetachOnUplinkComplete(context.Background(), inbound, outbound, "copy_complete", nil)
	}()

	time.Sleep(50 * time.Millisecond)
	select {
	case <-ctx.Done():
	default:
		t.Fatal("timer should remain owned by the caller; observation must not extend it")
	}
	if downlinkTimeout != 10*time.Millisecond {
		t.Fatalf("downlinkTimeout=%v, want unchanged caller timeout", downlinkTimeout)
	}
	if got := inbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("inbound state=%v, want pending_detach", got)
	}
	if got := inbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("inbound reason=%v, want unspecified", got)
	}
	if got := outbound.GetCanSpliceCopy(); got != session.CopyGatePendingDetach {
		t.Fatalf("outbound state=%v, want pending_detach", got)
	}
	if got := outbound.CopyGateReason(); got != session.CopyGateReasonUnspecified {
		t.Fatalf("outbound reason=%v, want unspecified", got)
	}
}

func TestObserveVisionPendingDetachOnUplinkCompletePublishesLocalNoDetachOnRequestStreamClosed(t *testing.T) {
	inbound := &session.Inbound{Conn: &tls.DeferredRustConn{}}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithVisionSignal(context.Background(), visionCh)
	ctx = session.ContextWithInbound(ctx, inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	observeVisionPendingDetachOnUplinkComplete(ctx, inbound, outbound, "request_stream_closed", nil)

	if got := inbound.VisionSemanticPhase(); got != session.VisionSemanticPhaseNoDetach {
		t.Fatalf("inbound semantic=%v, want vision_no_detach", got)
	}
	if got := outbound.VisionSemanticPhase(); got != session.VisionSemanticPhaseNoDetach {
		t.Fatalf("outbound semantic=%v, want vision_no_detach", got)
	}
	if got := inbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("inbound state=%v, want forced_userspace", got)
	}
	if got := outbound.GetCanSpliceCopy(); got != session.CopyGateForcedUserspace {
		t.Fatalf("outbound state=%v, want forced_userspace", got)
	}
	select {
	case sig := <-visionCh:
		if sig.Command != 1 {
			t.Fatalf("signal command=%d, want 1", sig.Command)
		}
	default:
		t.Fatal("observeVisionPendingDetachOnUplinkComplete() did not publish local no-detach signal")
	}
}
