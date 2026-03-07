package proxy

import (
	"bytes"
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	clog "github.com/xtls/xray-core/common/log"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/pipeline"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/ebpf"
	xreality "github.com/xtls/xray-core/transport/internet/reality"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

type testSeverityCaptureHandler struct {
	level clog.Severity
	msgs  []string
}

func (h *testSeverityCaptureHandler) Handle(msg clog.Message) {
	gm, ok := msg.(*clog.GeneralMessage)
	if !ok {
		return
	}
	if gm.Severity <= h.level {
		h.msgs = append(h.msgs, gm.String())
	}
}

type testDummyAddr string

func (a testDummyAddr) Network() string { return "tcp" }
func (a testDummyAddr) String() string  { return string(a) }

type testEOFConn struct{}

func (testEOFConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (testEOFConn) Write(b []byte) (int, error)      { return len(b), nil }
func (testEOFConn) Close() error                     { return nil }
func (testEOFConn) LocalAddr() net.Addr              { return testDummyAddr("eof-local") }
func (testEOFConn) RemoteAddr() net.Addr             { return testDummyAddr("eof-remote") }
func (testEOFConn) SetDeadline(time.Time) error      { return nil }
func (testEOFConn) SetReadDeadline(time.Time) error  { return nil }
func (testEOFConn) SetWriteDeadline(time.Time) error { return nil }

type testXHTTPFlowConn struct{ testEOFConn }

func (testXHTTPFlowConn) LocalAddr() net.Addr  { return testDummyAddr("xhttp-local") }
func (testXHTTPFlowConn) RemoteAddr() net.Addr { return testDummyAddr("xhttp-remote") }

type testTraceConn struct {
	testEOFConn
	id int
}

func TestDetermineSocketCryptoHintWithSourceXHTTPFlow(t *testing.T) {
	raw, hint, source := determineSocketCryptoHintWithSource(&testXHTTPFlowConn{})
	if raw != nil {
		t.Fatalf("raw conn should be nil for non-TCP XHTTP-like conn, got %T", raw)
	}
	if hint != ebpf.CryptoNone {
		t.Fatalf("expected CryptoNone for XHTTP-like conn, got %d", hint)
	}
	if !strings.Contains(source, "*proxy.testXHTTPFlowConn") {
		t.Fatalf("expected source to include XHTTP-like conn type, got %q", source)
	}
}

func TestDetermineSocketCryptoHintWithSourceRustConn(t *testing.T) {
	raw, hint, source := determineSocketCryptoHintWithSource(&xtls.RustConn{})
	if raw != nil {
		t.Fatalf("raw conn should be nil for zero-value RustConn in test, got %T", raw)
	}
	if hint != ebpf.CryptoUserspaceTLS {
		t.Fatalf("expected CryptoUserspaceTLS for zero-value RustConn, got %d", hint)
	}
	if !strings.Contains(source, "*tls.RustConn(userspace)") {
		t.Fatalf("expected source to include RustConn userspace state, got %q", source)
	}
}

func TestDetermineSocketCryptoHintWithSourceNilRealityWrappers(t *testing.T) {
	raw, hint, source := determineSocketCryptoHintWithSource(&xreality.Conn{})
	if raw != nil {
		t.Fatalf("raw conn should be nil for nil-inner reality.Conn, got %T", raw)
	}
	if hint != ebpf.CryptoUserspaceTLS {
		t.Fatalf("expected CryptoUserspaceTLS for nil-inner reality.Conn, got %d", hint)
	}
	if !strings.Contains(source, "*reality.Conn(nil)") {
		t.Fatalf("expected source to include nil reality conn marker, got %q", source)
	}

	raw, hint, source = determineSocketCryptoHintWithSource(&xreality.UConn{})
	if raw != nil {
		t.Fatalf("raw conn should be nil for nil-inner reality.UConn, got %T", raw)
	}
	if hint != ebpf.CryptoUserspaceTLS {
		t.Fatalf("expected CryptoUserspaceTLS for nil-inner reality.UConn, got %d", hint)
	}
	if !strings.Contains(source, "*reality.UConn(nil)") {
		t.Fatalf("expected source to include nil reality uconn marker, got %q", source)
	}
}

func TestCopyRawConnXHTTPFlowLogsAreDebugGated(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		t.Skip("XHTTP raw copy fallback path is only exercised on linux/android")
	}
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	run := func(level clog.Severity) []string {
		handler := &testSeverityCaptureHandler{level: level}
		clog.RegisterHandler(handler)

		err := CopyRawConnIfExist(context.Background(), &testEOFConn{}, &testXHTTPFlowConn{}, buf.Discard, nil, nil)
		if err != nil {
			t.Fatalf("CopyRawConnIfExist returned unexpected error: %v", err)
		}
		return handler.msgs
	}

	infoMsgs := run(clog.Severity_Info)
	debugMsgs := run(clog.Severity_Debug)

	infoLog := strings.Join(infoMsgs, "\n")
	if strings.Contains(infoLog, "writer is not *net.TCPConn") {
		t.Fatal("XHTTP fallback debug log should be filtered at info level")
	}

	debugLog := strings.Join(debugMsgs, "\n")
	if !strings.Contains(debugLog, "writer is not *net.TCPConn") && !strings.Contains(debugLog, "missing inbound metadata") {
		t.Fatal("missing XHTTP fallback debug log at debug level")
	}
	if strings.Contains(debugLog, "writer is not *net.TCPConn") && !strings.Contains(debugLog, "*proxy.testXHTTPFlowConn") {
		t.Fatal("missing XHTTP flow type in debug logs")
	}
}

func TestLogPipelineSummaryIncludesUserspaceExit(t *testing.T) {
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	logPipelineSummary(context.Background(), pipeline.DecisionSnapshot{
		Kind:           "proxy",
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonDeferredTLSGuard,
		Caps:           pipeline.CapabilitySummary{KTLSSupported: true, SockmapSupported: true, SpliceSupported: true},
		CopyPath:       pipeline.CopyPathUserspace,
		TLSOffloadPath: pipeline.TLSOffloadUserspace,
		CopyGateState:  pipeline.CopyGatePendingDetach,
		CopyGateReason: pipeline.CopyGateReasonUnspecified,
		UserspaceExit:  pipeline.UserspaceExitRemoteEOFNoResponse,
	})

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "userspace_exit=remote_eof_no_response") {
		t.Fatalf("pipeline summary missing userspace_exit field: %s", logs)
	}
}

func TestLogVisionTransitionSourceAndDrain(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	source := NewVisionTransitionSource(&testTraceConn{id: 1}, bytes.NewReader([]byte("plain")), bytes.NewBufferString("raw"))
	source.kind = VisionTransitionKindOpaque
	source.origin = VisionIngressOriginGoReality

	LogVisionTransitionSource(context.Background(), "inbound", source)
	LogVisionTransitionDrain(context.Background(), "buffered-drain", source, len("plain"), len("raw"))

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "kind=vision-transition-source") {
		t.Fatalf("missing transition source log: %s", logs)
	}
	if !strings.Contains(logs, "direction=inbound") || !strings.Contains(logs, "ingress_origin=go_reality") || !strings.Contains(logs, "buffered_plaintext=5") || !strings.Contains(logs, "buffered_raw_ahead=3") {
		t.Fatalf("missing transition source fields in logs: %s", logs)
	}
	if !strings.Contains(logs, "kind=vision-transition-drain") || !strings.Contains(logs, "ingress_origin=go_reality") || !strings.Contains(logs, "plaintext_len=5") || !strings.Contains(logs, "raw_ahead_len=3") {
		t.Fatalf("missing transition drain fields in logs: %s", logs)
	}
}

func TestLogVisionTransitionEvent(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	source := NewVisionTransitionSource(&testTraceConn{id: 2}, nil, nil)
	source.kind = VisionTransitionKindDeferredRust
	source.origin = VisionIngressOriginNativeRealityDeferred

	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventCommandObserved, 2, 1, 0, 0, false, true)

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "kind=vision-transition-event") {
		t.Fatalf("missing transition event log: %s", logs)
	}
	if !strings.Contains(logs, "direction=uplink") ||
		!strings.Contains(logs, "transition_kind=deferred_rust_conn") ||
		!strings.Contains(logs, "ingress_origin=native_reality_deferred") ||
		!strings.Contains(logs, "event=command_observed") ||
		!strings.Contains(logs, "command=2") ||
		!strings.Contains(logs, "switch_to_direct_copy=true") {
		t.Fatalf("missing transition event fields in logs: %s", logs)
	}
}

func TestVisionReaderEmitsTransitionCommandEvent(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	left, right := mustTCPPair(t)
	defer left.Close()
	defer right.Close()

	ts := NewTrafficState(nil)
	ts.Outbound.WithinPaddingBuffers = true
	ts.Outbound.CurrentCommand = 2

	inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGatePendingDetach), Conn: left}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	b := buf.New()
	b.Write([]byte("abc"))
	reader := &singleReadReader{mb: buf.MultiBuffer{b}}
	source := NewVisionTransitionSource(left, nil, nil)
	source.kind = VisionTransitionKindDeferredRust
	source.origin = VisionIngressOriginNativeRealityDeferred

	vr := NewVisionReader(reader, ts, false, ctx, source, nil)
	mb, err := vr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	buf.ReleaseMulti(mb)

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "kind=vision-transition-event") ||
		!strings.Contains(logs, "direction=downlink") ||
		!strings.Contains(logs, "ingress_origin=native_reality_deferred") ||
		!strings.Contains(logs, "event=command_observed") ||
		!strings.Contains(logs, "command=2") ||
		!strings.Contains(logs, "switch_to_direct_copy=true") {
		t.Fatalf("missing vision reader command event fields in logs: %s", logs)
	}
}

func TestVisionReaderEmitsNoDetachTransitionEvent(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	uuid := []byte("0123456789abcdef")
	ts := NewTrafficState(uuid)

	inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGatePendingDetach)}
	outbound := &session.Outbound{CanSpliceCopy: int32(session.CopyGatePendingDetach)}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	userUUID := append([]byte(nil), uuid...)
	padded := XtlsPadding(buf.FromBytes([]byte("ok")), CommandPaddingEnd, &userUUID, false, ctx, []uint32{0, 0, 0, 1})
	reader := &singleReadReader{mb: buf.MultiBuffer{padded}}

	source := NewVisionTransitionSource(&testTraceConn{id: 3}, nil, nil)
	source.kind = VisionTransitionKindRealityConn
	source.origin = VisionIngressOriginGoRealityFallback

	vr := NewVisionReader(reader, ts, true, ctx, source, outbound)
	mb, err := vr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	buf.ReleaseMulti(mb)

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "kind=vision-transition-event") ||
		!strings.Contains(logs, "direction=uplink") ||
		!strings.Contains(logs, "ingress_origin=go_reality_fallback") ||
		!strings.Contains(logs, "event=command_observed") ||
		!strings.Contains(logs, "command=1") ||
		!strings.Contains(logs, "switch_to_direct_copy=false") {
		t.Fatalf("missing no-detach transition event fields in logs: %s", logs)
	}
}

func TestVisionReaderEmitsPayloadBypassTransitionEvent(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	ts := NewTrafficState([]byte("0123456789abcdef"))
	rawDNS := []byte{
		0x00, 0x2c,
		0x12, 0x34,
		0x01, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x03, 'w', 'w', 'w', 0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e',
		0x03, 'c', 'o', 'm', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
	reader := &singleReadReader{mb: buf.MultiBuffer{buf.FromBytes(rawDNS)}}

	inbound := &session.Inbound{
		Local: xnet.TCPDestination(xnet.IPAddress([]byte{127, 0, 0, 1}), xnet.Port(2036)),
	}
	outbound := &session.Outbound{
		Target: xnet.TCPDestination(xnet.IPAddress([]byte{1, 1, 1, 1}), xnet.Port(53)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	source := NewVisionTransitionSource(&testTraceConn{id: 4}, nil, nil)
	source.kind = VisionTransitionKindRealityConn
	source.origin = VisionIngressOriginGoReality

	vr := NewVisionReader(reader, ts, true, ctx, source, outbound)
	mb, err := vr.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() error = %v", err)
	}
	buf.ReleaseMulti(mb)

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "kind=vision-transition-event") ||
		!strings.Contains(logs, "event=payload_bypass") ||
		!strings.Contains(logs, "ingress_origin=go_reality") {
		t.Fatalf("missing payload bypass transition event fields in logs: %s", logs)
	}
}

func TestLogVisionTransitionSummary(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 5}
	source := NewVisionTransitionSource(conn, nil, nil)
	source.kind = VisionTransitionKindDeferredRust
	source.origin = VisionIngressOriginNativeRealityDeferred

	LogVisionTransitionSource(context.Background(), "inbound", source)
	LogVisionTransitionDrain(context.Background(), "deferred-detach", source, 11, 7)
	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventCommandObserved, 0, 1, 0, 0, true, false)
	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventCommandObserved, 1, 0, 0, 0, false, false)
	LogVisionTransitionEvent(context.Background(), "downlink", source, VisionTransitionEventCommandObserved, 2, 0, 0, 0, false, true)
	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventPayloadBypass, -1, 0, 0, 0, false, false)
	LogVisionTransitionSummary(context.Background(), conn, nil)

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "kind=vision-transition-summary") ||
		!strings.Contains(logs, "transition_kind=deferred_rust_conn") ||
		!strings.Contains(logs, "ingress_origin=native_reality_deferred") ||
		!strings.Contains(logs, "uplink_command0_count=1") ||
		!strings.Contains(logs, "uplink_command1_count=1") ||
		!strings.Contains(logs, "downlink_command2_count=1") ||
		!strings.Contains(logs, "uplink_payload_bypass=true") ||
		!strings.Contains(logs, "uplink_semantic=explicit_no_detach") ||
		!strings.Contains(logs, "downlink_semantic=explicit_direct_copy") ||
		!strings.Contains(logs, "drain_mode=deferred_detach") ||
		!strings.Contains(logs, "drain_count=1") ||
		!strings.Contains(logs, "drain_plaintext_bytes=11") ||
		!strings.Contains(logs, "drain_raw_ahead_bytes=7") {
		t.Fatalf("missing transition summary fields in logs: %s", logs)
	}
}

func TestVisionTransitionSummarySnapshotWithoutDebug(t *testing.T) {
	conn := &testTraceConn{id: 6}
	source := NewVisionTransitionSource(conn, nil, nil)
	source.kind = VisionTransitionKindRealityConn
	source.origin = VisionIngressOriginGoReality

	LogVisionTransitionSource(context.Background(), "inbound", source)
	LogVisionTransitionDrain(context.Background(), "buffered-drain", source, 5, 3)
	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventCommandObserved, 0, 1, 0, 0, true, false)
	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventCommandObserved, 2, 0, 0, 0, false, true)

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.Kind != VisionTransitionKindRealityConn {
		t.Fatalf("summary.Kind=%q, want %q", summary.Kind, VisionTransitionKindRealityConn)
	}
	if summary.IngressOrigin != VisionIngressOriginGoReality {
		t.Fatalf("summary.IngressOrigin=%q, want %q", summary.IngressOrigin, VisionIngressOriginGoReality)
	}
	if summary.Uplink.Command0Count != 1 || summary.Uplink.Command2Count != 1 {
		t.Fatalf("unexpected uplink command counts: %+v", summary.Uplink)
	}
	if summary.Uplink.Semantic != VisionSemanticExplicitDirect {
		t.Fatalf("summary.Uplink.Semantic=%q, want %q", summary.Uplink.Semantic, VisionSemanticExplicitDirect)
	}
	if summary.DrainMode != VisionDrainModeBuffered || summary.DrainCount != 1 || summary.DrainPlaintextBytes != 5 || summary.DrainRawAheadBytes != 3 {
		t.Fatalf("unexpected drain summary: %+v", summary)
	}

	LogVisionTransitionSummary(context.Background(), conn, nil)
	if _, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		t.Fatal("expected summary state to be consumed after LogVisionTransitionSummary")
	}
}

func TestObserveVisionTransitionProducerAPIWithoutDebug(t *testing.T) {
	conn := &testTraceConn{id: 7}

	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 1)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "downlink", VisionTransitionEventPayloadBypass, -1)
	ObserveVisionTransitionDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 9, 4)

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.Kind != VisionTransitionKindDeferredRust {
		t.Fatalf("summary.Kind=%q, want %q", summary.Kind, VisionTransitionKindDeferredRust)
	}
	if summary.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		t.Fatalf("summary.IngressOrigin=%q, want %q", summary.IngressOrigin, VisionIngressOriginNativeRealityDeferred)
	}
	if summary.Uplink.Command0Count != 1 || summary.Uplink.Command1Count != 1 {
		t.Fatalf("unexpected uplink command counts: %+v", summary.Uplink)
	}
	if summary.Uplink.Semantic != VisionSemanticExplicitNoDetach {
		t.Fatalf("summary.Uplink.Semantic=%q, want %q", summary.Uplink.Semantic, VisionSemanticExplicitNoDetach)
	}
	if !summary.Downlink.PayloadBypass || summary.Downlink.Semantic != VisionSemanticPayloadBypass {
		t.Fatalf("unexpected downlink summary: %+v", summary.Downlink)
	}
	if summary.DrainMode != VisionDrainModeDeferred || summary.DrainCount != 1 || summary.DrainPlaintextBytes != 9 || summary.DrainRawAheadBytes != 4 {
		t.Fatalf("unexpected drain summary: %+v", summary)
	}
}

func TestCopyRawConnIfExistLogsStableUserspaceAfterNoDetachEOF(t *testing.T) {
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	readerPeer, readerConn := net.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &xtls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{57, 144, 150, 192}), xnet.Port(443)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(100*time.Millisecond, func() {
		inbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionNoDetach)
		outbound.SetCopyGate(session.CopyGateForcedUserspace, session.CopyGateReasonVisionNoDetach)
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil after EOF stable-userspace close", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for stable-userspace EOF flow")
	}

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "reason=vision_no_detach_userspace") {
		t.Fatalf("missing stable userspace reason in logs: %s", logs)
	}
	if !strings.Contains(logs, "userspace_exit=stable_userspace_close") {
		t.Fatalf("missing stable userspace exit in logs: %s", logs)
	}
}

func TestCopyRawConnIfExistLogsQuietUplinkTelemetryOnly(t *testing.T) {
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Debug}
	clog.RegisterHandler(handler)

	readerPeer, readerConn := net.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	writerConn := &xtls.DeferredRustConn{}
	copyCtx, cancelCopy := context.WithCancel(context.Background())
	defer cancelCopy()
	timer := signal.CancelAfterInactivity(copyCtx, cancelCopy, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{91, 108, 56, 133}), xnet.Port(443)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	storeVisionUplinkTimestamp(writerConn, time.Now().Add(-visionFirstResponseMax).UnixNano())

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(2500*time.Millisecond, func() {
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil after quiet-uplink telemetry path drains on peer close", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for quiet-uplink telemetry path to drain")
	}

	logs := strings.Join(handler.msgs, "\n")
	if strings.Contains(logs, "kind=vision.uplink_quiesce_handoff") {
		t.Fatalf("unexpected quiesce handoff log after telemetry-only simplification: %s", logs)
	}
	if strings.Contains(logs, "reason=userspace_idle_timeout") {
		t.Fatalf("unexpected local userspace timeout reason in logs: %s", logs)
	}
	if !(strings.Contains(logs, "reason=userspace_complete") || strings.Contains(logs, "reason=deferred_tls_guard")) {
		t.Fatalf("missing expected quiet-uplink terminal reason in logs: %s", logs)
	}
}
