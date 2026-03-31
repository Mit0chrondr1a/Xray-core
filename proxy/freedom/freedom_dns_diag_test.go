package freedom

import (
	"context"
	goerrors "errors"
	"io"
	gonet "net"
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
	if diag.flowClass != "dns_tcp_control" {
		t.Fatalf("flowClass=%q, want %q", diag.flowClass, "dns_tcp_control")
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
	if got := diag.totalBytes.Load(); got != 3 {
		t.Fatalf("totalBytes=%d, want 3", got)
	}
	if got := diag.firstWriteNs.Load(); got <= 0 {
		t.Fatalf("firstWriteNs=%d, want >0", got)
	}
}

func TestDNSResponseDiagnosticWriterObserveWrite(t *testing.T) {
	diag := &dnsUplinkDiagnostic{
		startedAt: time.Now().Add(-2 * time.Millisecond),
	}
	timings := &session.FlowTimings{}
	writer := &dnsResponseDiagnosticWriter{
		Writer:  buf.Discard,
		dns:     diag,
		timings: timings,
	}
	mb := buf.MultiBuffer{buf.FromBytes([]byte("response"))}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}
	if got := diag.responseBytes.Load(); got != int64(len("response")) {
		t.Fatalf("responseBytes=%d, want %d", got, len("response"))
	}
	if got := diag.firstResponseNs.Load(); got <= 0 {
		t.Fatalf("firstResponseNs=%d, want >0", got)
	}
	if got := timings.FirstResponseUnixNano(); got == 0 {
		t.Fatal("FirstResponseUnixNano() = 0, want populated")
	}
}

func TestDNSUplinkDiagnosticLatencyBreakdown(t *testing.T) {
	diag := &dnsUplinkDiagnostic{}
	diag.firstWriteNs.Store(10)
	diag.firstResponseNs.Store(55)
	diag.lastResponseNs.Store(80)
	if got := diag.requestTTFBNs(); got != 45 {
		t.Fatalf("requestTTFBNs()=%d, want 45", got)
	}
	if got := diag.responseCompleteNs(); got != 70 {
		t.Fatalf("responseCompleteNs()=%d, want 70", got)
	}
}

func TestNewDNSUplinkDiagnosticUDPDNS(t *testing.T) {
	outbound := &session.Outbound{
		Target: net.UDPDestination(net.IPAddress([]byte{1, 0, 0, 1}), net.Port(853)),
	}
	ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{outbound})
	diag := newDNSUplinkDiagnostic(ctx, outbound.Target)
	if diag == nil {
		t.Fatal("newDNSUplinkDiagnostic() returned nil for UDP DNS flow")
	}
	if diag.flowClass != "dns_udp_control" {
		t.Fatalf("flowClass=%q, want %q", diag.flowClass, "dns_udp_control")
	}
	if diag.dnsPlane != "unknown" {
		t.Fatalf("dnsPlane=%q, want %q", diag.dnsPlane, "unknown")
	}
}

func TestClassifyDNSUplinkErr(t *testing.T) {
	if got := classifyDNSUplinkErr(nil); got != "none" {
		t.Fatalf("classifyDNSUplinkErr(nil)=%q, want %q", got, "none")
	}
	if got := classifyDNSUplinkErr(errDNSUDPFirstResponseTimeout); got != "first_response_timeout" {
		t.Fatalf("classifyDNSUplinkErr(errDNSUDPFirstResponseTimeout)=%q, want %q", got, "first_response_timeout")
	}
	if got := classifyDNSUplinkErr(context.Canceled); got != "context_canceled" {
		t.Fatalf("classifyDNSUplinkErr(context.Canceled)=%q, want %q", got, "context_canceled")
	}
}

func TestShouldFastFailDNSUDPFirstResponse(t *testing.T) {
	inbound := &session.Inbound{
		Local: net.TCPDestination(net.IPAddress([]byte{127, 0, 0, 1}), net.Port(2036)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	if !shouldFastFailDNSUDPFirstResponse(ctx, net.UDPDestination(net.IPAddress([]byte{1, 0, 0, 1}), net.Port(853))) {
		t.Fatal("shouldFastFailDNSUDPFirstResponse() = false, want true for loopback DoQ")
	}
	if shouldFastFailDNSUDPFirstResponse(ctx, net.UDPDestination(net.IPAddress([]byte{1, 0, 0, 1}), net.Port(53))) {
		t.Fatal("shouldFastFailDNSUDPFirstResponse() = true, want false for UDP/53")
	}
	if shouldFastFailDNSUDPFirstResponse(context.Background(), net.UDPDestination(net.IPAddress([]byte{1, 0, 0, 1}), net.Port(853))) {
		t.Fatal("shouldFastFailDNSUDPFirstResponse() = true, want false without loopback ingress")
	}
}

func TestUDPFirstResponseTimeoutReaderReturnsSentinelOnTimeout(t *testing.T) {
	conn := &fakeDeadlineConn{}
	reader := &stubBufReader{err: timeoutReadError{}}
	guard := newUDPFirstResponseGuard(conn, dnsUDPFirstResponseTimeout)
	guard.ObserveWrite()
	guarded := newUDPFirstResponseTimeoutReader(reader, guard)
	if guarded == nil {
		t.Fatal("newUDPFirstResponseTimeoutReader() returned nil")
	}
	mb, err := guarded.ReadMultiBuffer()
	if err == nil || !goerrors.Is(err, errDNSUDPFirstResponseTimeout) {
		t.Fatalf("ReadMultiBuffer() error = %v, want errDNSUDPFirstResponseTimeout", err)
	}
	if mb != nil {
		t.Fatalf("ReadMultiBuffer() mb = %v, want nil", mb)
	}
	if len(conn.deadlines) < 2 {
		t.Fatalf("deadline calls = %d, want at least 2", len(conn.deadlines))
	}
	if conn.deadlines[0].IsZero() {
		t.Fatal("first deadline should arm timeout")
	}
	if !conn.deadlines[len(conn.deadlines)-1].IsZero() {
		t.Fatal("final deadline should clear timeout")
	}
}

func TestUDPFirstResponseTimeoutReaderClearsDeadlineAfterFirstPacket(t *testing.T) {
	conn := &fakeDeadlineConn{}
	reader := &stubBufReader{mb: buf.MultiBuffer{buf.FromBytes([]byte("dns"))}}
	guard := newUDPFirstResponseGuard(conn, dnsUDPFirstResponseTimeout)
	guard.ObserveWrite()
	guarded := newUDPFirstResponseTimeoutReader(reader, guard)
	mb, err := guarded.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	if mb.IsEmpty() {
		t.Fatal("ReadMultiBuffer() returned empty buffer, want payload")
	}
	if len(conn.deadlines) < 2 {
		t.Fatalf("deadline calls = %d, want at least 2", len(conn.deadlines))
	}
	if conn.deadlines[0].IsZero() {
		t.Fatal("first deadline should arm timeout")
	}
	if !conn.deadlines[len(conn.deadlines)-1].IsZero() {
		t.Fatal("final deadline should clear timeout")
	}
	buf.ReleaseMulti(mb)
}

func TestUDPFirstResponseTimeoutReaderLeavesTimeoutUntouchedBeforeAnyWrite(t *testing.T) {
	conn := &fakeDeadlineConn{}
	reader := &stubBufReader{err: timeoutReadError{}}
	guard := newUDPFirstResponseGuard(conn, dnsUDPFirstResponseTimeout)
	guarded := newUDPFirstResponseTimeoutReader(reader, guard)

	_, err := guarded.ReadMultiBuffer()
	if err == nil {
		t.Fatal("ReadMultiBuffer() error = nil, want timeout")
	}
	if goerrors.Is(err, errDNSUDPFirstResponseTimeout) {
		t.Fatalf("ReadMultiBuffer() error = %v, want original timeout before any write", err)
	}
	if _, ok := err.(timeoutReadError); !ok {
		t.Fatalf("ReadMultiBuffer() error type = %T, want timeoutReadError", err)
	}
	if len(conn.deadlines) != 0 {
		t.Fatalf("deadline calls = %d, want 0 before any write", len(conn.deadlines))
	}
}

func TestUDPFirstResponseGuardRefreshesDeadlineOnEachWrite(t *testing.T) {
	conn := &fakeDeadlineConn{}
	guard := newUDPFirstResponseGuard(conn, dnsUDPFirstResponseTimeout)

	guard.ObserveWrite()
	time.Sleep(time.Millisecond)
	guard.ObserveWrite()

	if len(conn.deadlines) != 2 {
		t.Fatalf("deadline calls = %d, want 2", len(conn.deadlines))
	}
	if conn.deadlines[0].IsZero() || conn.deadlines[1].IsZero() {
		t.Fatal("write deadlines should arm the first-response guard")
	}
	if !conn.deadlines[1].After(conn.deadlines[0]) {
		t.Fatalf("second deadline = %v, want after first deadline %v", conn.deadlines[1], conn.deadlines[0])
	}
}

func TestUDPFirstResponseGuardCapsTotalWaitBudget(t *testing.T) {
	conn := &fakeDeadlineConn{}
	guard := newUDPFirstResponseGuardWithBudget(conn, 40*time.Millisecond, 60*time.Millisecond)

	guard.ObserveWrite()
	time.Sleep(30 * time.Millisecond)
	guard.ObserveWrite()

	if len(conn.deadlines) != 2 {
		t.Fatalf("deadline calls = %d, want 2", len(conn.deadlines))
	}
	if conn.deadlines[0].IsZero() || conn.deadlines[1].IsZero() {
		t.Fatal("write deadlines should arm the first-response guard")
	}
	if !conn.deadlines[1].After(conn.deadlines[0]) {
		t.Fatalf("second deadline = %v, want after first deadline %v", conn.deadlines[1], conn.deadlines[0])
	}
	if delta := conn.deadlines[1].Sub(conn.deadlines[0]); delta > 30*time.Millisecond {
		t.Fatalf("deadline extension=%v, want capped by overall budget", delta)
	}
}

func TestDNSUplinkDiagnosticWriterArmsFirstResponseGuardOnPayload(t *testing.T) {
	conn := &fakeDeadlineConn{}
	guard := newUDPFirstResponseGuard(conn, dnsUDPFirstResponseTimeout)
	writer := &dnsUplinkDiagnosticWriter{
		Writer: buf.Discard,
		guard:  guard,
	}

	if err := writer.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("dns"))}); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}
	if len(conn.deadlines) != 1 {
		t.Fatalf("deadline calls = %d, want 1", len(conn.deadlines))
	}
	if conn.deadlines[0].IsZero() {
		t.Fatal("first deadline should arm timeout after payload write")
	}
}

func TestNewVisionUplinkDiagnosticPendingDetachTCP(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	diag := newVisionUplinkDiagnostic(inbound, net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(443)), nil)
	if diag == nil {
		t.Fatal("newVisionUplinkDiagnostic() returned nil for pending-detach TCP flow")
	}
}

func TestNewVisionUplinkDiagnosticIgnoresDNSAndNonPending(t *testing.T) {
	inbound := &session.Inbound{}
	inbound.SetCanSpliceCopy(session.CopyGateEligible)
	if diag := newVisionUplinkDiagnostic(inbound, net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(443)), nil); diag != nil {
		t.Fatal("newVisionUplinkDiagnostic() should be nil for non-pending flow")
	}

	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	if diag := newVisionUplinkDiagnostic(inbound, net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)), nil); diag != nil {
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
	if diag.lastWriteNs <= 0 {
		t.Fatalf("lastWriteNs=%d, want >0", diag.lastWriteNs)
	}
}

func TestVisionUplinkDiagnosticWriterStoresSharedFlowTimings(t *testing.T) {
	timings := &session.FlowTimings{}
	timings.StoreUplinkStart(time.Now().Add(-2 * time.Millisecond).UnixNano())
	diag := &visionUplinkDiagnostic{
		startedAt: time.Now().Add(-2 * time.Millisecond),
		timings:   timings,
	}
	writer := &dnsUplinkDiagnosticWriter{
		Writer: buf.Discard,
		vision: diag,
	}
	mb := buf.MultiBuffer{buf.FromBytes([]byte("abcd"))}
	if err := writer.WriteMultiBuffer(mb); err != nil {
		t.Fatalf("WriteMultiBuffer() error = %v", err)
	}
	if got := timings.UplinkFirstWriteUnixNano(); got == 0 {
		t.Fatal("UplinkFirstWriteUnixNano() = 0, want populated")
	}
	if got := timings.UplinkLastWriteUnixNano(); got == 0 {
		t.Fatal("UplinkLastWriteUnixNano() = 0, want populated")
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

type stubBufReader struct {
	mb  buf.MultiBuffer
	err error
}

func (r *stubBufReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.err != nil {
		return nil, r.err
	}
	mb := r.mb
	r.mb = nil
	return mb, nil
}

type timeoutReadError struct{}

func (timeoutReadError) Error() string   { return "i/o timeout" }
func (timeoutReadError) Timeout() bool   { return true }
func (timeoutReadError) Temporary() bool { return true }

type fakeDeadlineConn struct {
	deadlines []time.Time
}

func (c *fakeDeadlineConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *fakeDeadlineConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fakeDeadlineConn) Close() error                { return nil }
func (c *fakeDeadlineConn) LocalAddr() gonet.Addr       { return &gonet.TCPAddr{} }
func (c *fakeDeadlineConn) RemoteAddr() gonet.Addr      { return &gonet.TCPAddr{} }
func (c *fakeDeadlineConn) SetDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return nil
}
func (c *fakeDeadlineConn) SetReadDeadline(t time.Time) error {
	c.deadlines = append(c.deadlines, t)
	return nil
}
func (c *fakeDeadlineConn) SetWriteDeadline(time.Time) error { return nil }
