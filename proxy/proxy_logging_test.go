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
	ObserveVisionTransitionDrain(source.Conn(), source.Kind(), source.origin, VisionDrainModeBuffered, len("plain"), len("raw"))
	TraceVisionTransitionDrain(context.Background(), "buffered-drain", source, len("plain"), len("raw"))

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

func TestTraceVisionTransitionDrainDoesNotMutateSummaryWithoutObserve(t *testing.T) {
	conn := &testTraceConn{id: 101}
	source := NewVisionTransitionSource(conn, nil, nil)
	source.kind = VisionTransitionKindDeferredRust
	source.origin = VisionIngressOriginNativeRealityDeferred

	TraceVisionTransitionDrain(context.Background(), "deferred-detach", source, 11, 7)

	if _, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		t.Fatal("TraceVisionTransitionDrain() should not create seam summary state without explicit observe")
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
	ObserveVisionTransportLifecycle(source.Conn(), source.Kind(), source.origin, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransportLifecycle(source.Conn(), source.Kind(), source.origin, xtls.DeferredRustLifecycleDetachCompleted)
	ObserveVisionTransportLifecycle(source.Conn(), source.Kind(), source.origin, xtls.DeferredRustLifecycleKTLSEnabled)
	ObserveVisionTransportProgress(source.Conn(), source.Kind(), source.origin, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 17})
	ObserveVisionTransportProgress(source.Conn(), source.Kind(), source.origin, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 5})
	ObserveVisionTransportDrain(source.Conn(), source.Kind(), source.origin, VisionDrainModeDeferred, 13, 9)
	ObserveVisionTransitionDrain(source.Conn(), source.Kind(), source.origin, VisionDrainModeDeferred, 11, 7)
	TraceVisionTransitionDrain(context.Background(), "deferred-detach", source, 11, 7)
	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventCommandObserved, 0, 1, 0, 0, true, false)
	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventCommandObserved, 1, 0, 0, 0, false, false)
	LogVisionTransitionEvent(context.Background(), "downlink", source, VisionTransitionEventCommandObserved, 2, 0, 0, 0, false, true)
	LogVisionTransitionEvent(context.Background(), "uplink", source, VisionTransitionEventPayloadBypass, -1, 0, 0, 0, false, false)
	LogVisionTransitionSummary(context.Background(), conn, nil, nil)

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
		!strings.Contains(logs, "native_provisional_semantic=none") ||
		!strings.Contains(logs, "drain_mode=deferred_detach") ||
		!strings.Contains(logs, "drain_count=1") ||
		!strings.Contains(logs, "drain_plaintext_bytes=11") ||
		!strings.Contains(logs, "drain_raw_ahead_bytes=7") ||
		!strings.Contains(logs, "transport_drain_mode=deferred_detach") ||
		!strings.Contains(logs, "transport_drain_count=1") ||
		!strings.Contains(logs, "transport_drain_plaintext_bytes=13") ||
		!strings.Contains(logs, "transport_drain_raw_ahead_bytes=9") ||
		!strings.Contains(logs, "drain_relation=mismatch") ||
		!strings.Contains(logs, "bridge_assessment=native_divergent") ||
		!strings.Contains(logs, "transport_read_ops=1") ||
		!strings.Contains(logs, "transport_read_bytes=5") ||
		!strings.Contains(logs, "transport_write_ops=1") ||
		!strings.Contains(logs, "transport_write_bytes=17") ||
		!strings.Contains(logs, "transport_progress=bidirectional") ||
		!strings.Contains(logs, "transport_lifecycle_state=ktls_enabled") ||
		!strings.Contains(logs, "transport_detach_status=completed") ||
		!strings.Contains(logs, "transport_ktls_promotion=enabled") {
		t.Fatalf("missing transition summary fields in logs: %s", logs)
	}
}

func TestVisionTransitionSummarySnapshotWithoutDebug(t *testing.T) {
	conn := &testTraceConn{id: 6}
	source := NewVisionTransitionSource(conn, nil, nil)
	source.kind = VisionTransitionKindRealityConn
	source.origin = VisionIngressOriginGoReality

	LogVisionTransitionSource(context.Background(), "inbound", source)
	ObserveVisionTransportLifecycle(source.Conn(), source.Kind(), source.origin, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransportLifecycle(source.Conn(), source.Kind(), source.origin, xtls.DeferredRustLifecycleDetachFailed)
	ObserveVisionTransportLifecycle(source.Conn(), source.Kind(), source.origin, xtls.DeferredRustLifecycleKTLSFailed)
	ObserveVisionTransportDrain(source.Conn(), source.Kind(), source.origin, VisionDrainModeDeferred, 8, 6)
	ObserveVisionTransitionDrain(source.Conn(), source.Kind(), source.origin, VisionDrainModeBuffered, 5, 3)
	TraceVisionTransitionDrain(context.Background(), "buffered-drain", source, 5, 3)
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
	if summary.TransportDrainMode != VisionDrainModeDeferred || summary.TransportDrainCount != 1 || summary.TransportDrainPlaintextLen != 8 || summary.TransportDrainRawAheadLen != 6 {
		t.Fatalf("unexpected transport drain summary: %+v", summary)
	}
	if summary.DrainRelation != VisionDrainRelationMismatch {
		t.Fatalf("summary.DrainRelation=%q, want %q", summary.DrainRelation, VisionDrainRelationMismatch)
	}
	if summary.BridgeAssessment != VisionBridgeAssessmentGoBaseline {
		t.Fatalf("summary.BridgeAssessment=%q, want %q", summary.BridgeAssessment, VisionBridgeAssessmentGoBaseline)
	}
	if summary.TransportLifecycleState != VisionTransportLifecycleDeferredActive {
		t.Fatalf("summary.TransportLifecycleState=%q, want %q", summary.TransportLifecycleState, VisionTransportLifecycleDeferredActive)
	}
	if summary.TransportDetachStatus != VisionTransportDetachStatusFailed {
		t.Fatalf("summary.TransportDetachStatus=%q, want %q", summary.TransportDetachStatus, VisionTransportDetachStatusFailed)
	}
	if summary.TransportKTLSPromotion != VisionTransportKTLSPromotionFailed {
		t.Fatalf("summary.TransportKTLSPromotion=%q, want %q", summary.TransportKTLSPromotion, VisionTransportKTLSPromotionFailed)
	}

	LogVisionTransitionSummary(context.Background(), conn, nil, nil)
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
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleKTLSUnsupported)
	ObserveVisionTransportDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 6, 2)
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
	if summary.TransportDrainMode != VisionDrainModeDeferred || summary.TransportDrainCount != 1 || summary.TransportDrainPlaintextLen != 6 || summary.TransportDrainRawAheadLen != 2 {
		t.Fatalf("unexpected transport drain summary: %+v", summary)
	}
	if summary.DrainRelation != VisionDrainRelationMismatch {
		t.Fatalf("summary.DrainRelation=%q, want %q", summary.DrainRelation, VisionDrainRelationMismatch)
	}
	if summary.BridgeAssessment != VisionBridgeAssessmentNativeDivergent {
		t.Fatalf("summary.BridgeAssessment=%q, want %q", summary.BridgeAssessment, VisionBridgeAssessmentNativeDivergent)
	}
	if summary.TransportLifecycleState != VisionTransportLifecycleDeferredActive {
		t.Fatalf("summary.TransportLifecycleState=%q, want %q", summary.TransportLifecycleState, VisionTransportLifecycleDeferredActive)
	}
	if summary.TransportDetachStatus != VisionTransportDetachStatusNone {
		t.Fatalf("summary.TransportDetachStatus=%q, want %q", summary.TransportDetachStatus, VisionTransportDetachStatusNone)
	}
	if summary.TransportKTLSPromotion != VisionTransportKTLSPromotionUnsupported {
		t.Fatalf("summary.TransportKTLSPromotion=%q, want %q", summary.TransportKTLSPromotion, VisionTransportKTLSPromotionUnsupported)
	}
}

func TestVisionTransitionSourceSnapshotIncludesRuntimeBridgeState(t *testing.T) {
	conn := &testTraceConn{id: 8}
	source := NewVisionTransitionSource(conn, nil, nil)
	source.kind = VisionTransitionKindDeferredRust
	source.origin = VisionIngressOriginNativeRealityDeferred

	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "canary-scope|reality|tcp")
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 1)
	ObserveVisionTransitionDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeBuffered, 4, 2)
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 11})
	ObserveVisionTransportDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 9, 6)

	snap := source.Snapshot()
	if snap.Kind != VisionTransitionKindDeferredRust {
		t.Fatalf("snapshot kind = %q, want %q", snap.Kind, VisionTransitionKindDeferredRust)
	}
	if snap.IngressOrigin != VisionIngressOriginNativeRealityDeferred {
		t.Fatalf("snapshot ingress origin = %q, want %q", snap.IngressOrigin, VisionIngressOriginNativeRealityDeferred)
	}
	if snap.ScopeKey != "canary-scope|reality|tcp" {
		t.Fatalf("snapshot scope key = %q, want %q", snap.ScopeKey, "canary-scope|reality|tcp")
	}
	if snap.UplinkSemantic != VisionSemanticExplicitNoDetach {
		t.Fatalf("snapshot uplink semantic = %q, want %q", snap.UplinkSemantic, VisionSemanticExplicitNoDetach)
	}
	if snap.NativeProvisionalSemantic != VisionNativeProvisionalSemanticNone {
		t.Fatalf("snapshot native provisional semantic = %q, want %q", snap.NativeProvisionalSemantic, VisionNativeProvisionalSemanticNone)
	}
	if snap.DrainMode != VisionDrainModeBuffered || snap.DrainCount != 1 || snap.DrainPlaintext != 4 || snap.DrainRawAhead != 2 {
		t.Fatalf("unexpected accepted drain snapshot: %+v", snap)
	}
	if snap.TransportDrainMode != VisionDrainModeDeferred || snap.TransportDrainCount != 1 || snap.TransportDrainPlaintext != 9 || snap.TransportDrainRawAhead != 6 {
		t.Fatalf("unexpected transport drain snapshot: %+v", snap)
	}
	if snap.DrainRelation != VisionDrainRelationMismatch {
		t.Fatalf("snapshot drain relation = %q, want %q", snap.DrainRelation, VisionDrainRelationMismatch)
	}
	if snap.BridgeAssessment != VisionBridgeAssessmentNativeDivergent {
		t.Fatalf("snapshot bridge assessment = %q, want %q", snap.BridgeAssessment, VisionBridgeAssessmentNativeDivergent)
	}
	if snap.TransportReadOps != 0 || snap.TransportReadBytes != 0 {
		t.Fatalf("unexpected transport read snapshot: %+v", snap)
	}
	if snap.TransportWriteOps != 1 || snap.TransportWriteBytes != 11 {
		t.Fatalf("unexpected transport write snapshot: %+v", snap)
	}
	if snap.TransportProgress != VisionTransportProgressWriteOnly {
		t.Fatalf("snapshot transport progress = %q, want %q", snap.TransportProgress, VisionTransportProgressWriteOnly)
	}
	if snap.TransportLifecycleState != VisionTransportLifecycleDeferredActive {
		t.Fatalf("snapshot transport lifecycle state = %q, want %q", snap.TransportLifecycleState, VisionTransportLifecycleDeferredActive)
	}
	if snap.TransportDetachStatus != VisionTransportDetachStatusNone {
		t.Fatalf("snapshot transport detach status = %q, want %q", snap.TransportDetachStatus, VisionTransportDetachStatusNone)
	}
	if snap.TransportKTLSPromotion != VisionTransportKTLSPromotionNone {
		t.Fatalf("snapshot transport ktls promotion = %q, want %q", snap.TransportKTLSPromotion, VisionTransportKTLSPromotionNone)
	}
}

func TestVisionTransitionSummaryDrainRelationVariants(t *testing.T) {
	tests := []struct {
		name    string
		observe func(conn *testTraceConn)
		want    VisionDrainRelation
	}{
		{
			name: "accepted only",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransitionDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 5, 2)
			},
			want: VisionDrainRelationAcceptedOnly,
		},
		{
			name: "transport only",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransportDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 5, 2)
			},
			want: VisionDrainRelationTransportOnly,
		},
		{
			name: "aligned",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransitionDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 5, 2)
				ObserveVisionTransportDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 5, 2)
			},
			want: VisionDrainRelationAligned,
		},
		{
			name: "mismatch",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransitionDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeBuffered, 5, 2)
				ObserveVisionTransportDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 8, 3)
			},
			want: VisionDrainRelationMismatch,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &testTraceConn{id: 200 + i}
			tc.observe(conn)

			summary, ok := SnapshotVisionTransitionSummary(conn, nil)
			if !ok {
				t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
			}
			if summary.DrainRelation != tc.want {
				t.Fatalf("summary.DrainRelation=%q, want %q", summary.DrainRelation, tc.want)
			}
		})
	}
}

func TestVisionTransitionSummaryBridgeAssessmentVariants(t *testing.T) {
	tests := []struct {
		name    string
		observe func(conn *testTraceConn)
		want    VisionBridgeAssessment
	}{
		{
			name: "go baseline",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindRealityConn, VisionIngressOriginGoReality)
			},
			want: VisionBridgeAssessmentGoBaseline,
		},
		{
			name: "native pending",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
			},
			want: VisionBridgeAssessmentNativePending,
		},
		{
			name: "native aligned",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDetachCompleted)
				ObserveVisionTransitionDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 5, 2)
				ObserveVisionTransportDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 5, 2)
			},
			want: VisionBridgeAssessmentNativeAligned,
		},
		{
			name: "native divergent",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDetachCompleted)
				ObserveVisionTransitionDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeBuffered, 5, 2)
				ObserveVisionTransportDrain(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 8, 3)
			},
			want: VisionBridgeAssessmentNativeDivergent,
		},
		{
			name: "native detach failed",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDetachFailed)
			},
			want: VisionBridgeAssessmentNativeDetachFailed,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &testTraceConn{id: 300 + i}
			tc.observe(conn)

			summary, ok := SnapshotVisionTransitionSummary(conn, nil)
			if !ok {
				t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
			}
			if summary.BridgeAssessment != tc.want {
				t.Fatalf("summary.BridgeAssessment=%q, want %q", summary.BridgeAssessment, tc.want)
			}
		})
	}
}

func TestVisionTransitionSummaryTransportProgressVariants(t *testing.T) {
	tests := []struct {
		name    string
		observe func(conn *testTraceConn)
		want    VisionTransportProgressProfile
	}{
		{
			name: "none",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
			},
			want: VisionTransportProgressNone,
		},
		{
			name: "write only",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 8})
			},
			want: VisionTransportProgressWriteOnly,
		},
		{
			name: "read only",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 5})
			},
			want: VisionTransportProgressReadOnly,
		},
		{
			name: "bidirectional",
			observe: func(conn *testTraceConn) {
				ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
				ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 8})
				ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 5})
			},
			want: VisionTransportProgressBidirectional,
		},
	}

	for i, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &testTraceConn{id: 500 + i}
			tc.observe(conn)

			summary, ok := SnapshotVisionTransitionSummary(conn, nil)
			if !ok {
				t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
			}
			if summary.TransportProgress != tc.want {
				t.Fatalf("summary.TransportProgress=%q, want %q", summary.TransportProgress, tc.want)
			}
		})
	}
}

func TestLogVisionTransitionSummaryUpdatesBridgeAssessmentCountersWithoutDebug(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)

	goConn := &testTraceConn{id: 400}
	ObserveVisionTransitionSource(goConn, VisionTransitionKindRealityConn, VisionIngressOriginGoReality)
	ObserveVisionTransitionScope(goConn, "scope-a|reality|tcp")
	LogVisionTransitionSummary(context.Background(), goConn, nil, nil)

	nativeConn := &testTraceConn{id: 401}
	ObserveVisionTransitionSource(nativeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(nativeConn, "scope-b|reality|tcp")
	ObserveVisionTransportLifecycle(nativeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDetachCompleted)
	ObserveVisionTransitionDrain(nativeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeBuffered, 5, 2)
	ObserveVisionTransportDrain(nativeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 8, 3)
	LogVisionTransitionSummary(context.Background(), nativeConn, nil, nil)

	stats := SnapshotVisionBridgeAssessmentStats()
	if stats.GoBaseline != 1 {
		t.Fatalf("stats.GoBaseline=%d, want 1", stats.GoBaseline)
	}
	if stats.NativeDivergent != 1 {
		t.Fatalf("stats.NativeDivergent=%d, want 1", stats.NativeDivergent)
	}
	if stats.NativePending != 0 || stats.NativeAligned != 0 || stats.NativeDetachFailed != 0 {
		t.Fatalf("unexpected assessment counters: %+v", stats)
	}

	scopeA := SnapshotVisionBridgeAssessmentStatsForScope("scope-a|reality|tcp")
	if scopeA.GoBaseline != 1 || scopeA.NativeDivergent != 0 {
		t.Fatalf("unexpected scope-a counters: %+v", scopeA)
	}
	scopeB := SnapshotVisionBridgeAssessmentStatsForScope("scope-b|reality|tcp")
	if scopeB.NativeDivergent != 1 || scopeB.GoBaseline != 0 {
		t.Fatalf("unexpected scope-b counters: %+v", scopeB)
	}
}

func TestVisionBridgeAssessmentStatsExpireOutsideRollingWindow(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)

	base := time.Unix(1_000_000, 0)
	visionBridgeAssessmentNowFn = func() time.Time { return base }

	conn := &testTraceConn{id: 402}
	ObserveVisionTransitionSource(conn, VisionTransitionKindRealityConn, VisionIngressOriginGoReality)
	ObserveVisionTransitionScope(conn, "scope-expire|reality|tcp")
	LogVisionTransitionSummary(context.Background(), conn, nil, nil)

	stats := SnapshotVisionBridgeAssessmentStatsForScope("scope-expire|reality|tcp")
	if stats.GoBaseline != 1 {
		t.Fatalf("initial stats.GoBaseline=%d, want 1", stats.GoBaseline)
	}

	visionBridgeAssessmentNowFn = func() time.Time {
		return base.Add(11 * visionBridgeAssessmentBucketWidth)
	}
	stats = SnapshotVisionBridgeAssessmentStatsForScope("scope-expire|reality|tcp")
	if stats != (VisionBridgeAssessmentStats{}) {
		t.Fatalf("expected expired scoped stats, got %+v", stats)
	}
}

func TestVisionBridgeProbeEpochCollectsFreshScopedStatsAndCompletesAtBudget(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	resetVisionBridgeProbeEpochsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)
	t.Cleanup(resetVisionBridgeProbeEpochsForTest)

	base := time.Unix(2_000_000, 0)
	visionBridgeAssessmentNowFn = func() time.Time { return base }
	visionBridgeProbeNowFn = func() time.Time { return base }

	scope := "scope-probe|reality|tcp"
	start := EnsureVisionBridgeProbeEpoch(scope, 2, time.Minute)
	if start.State != VisionBridgeProbeStateActive {
		t.Fatalf("start.State=%q, want %q", start.State, VisionBridgeProbeStateActive)
	}
	if start.Observed != 0 {
		t.Fatalf("start.Observed=%d, want 0", start.Observed)
	}

	alignedConn := &testTraceConn{id: 405}
	ObserveVisionTransitionSource(alignedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(alignedConn, scope)
	ObserveVisionTransportLifecycle(alignedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDetachCompleted)
	ObserveVisionTransitionDrain(alignedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 8, 3)
	ObserveVisionTransportDrain(alignedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 8, 3)
	LogVisionTransitionSummary(context.Background(), alignedConn, nil, nil)

	mid := SnapshotVisionBridgeProbeEpochForScope(scope)
	if mid.State != VisionBridgeProbeStateActive {
		t.Fatalf("mid.State=%q, want %q", mid.State, VisionBridgeProbeStateActive)
	}
	if mid.Observed != 1 {
		t.Fatalf("mid.Observed=%d, want 1", mid.Observed)
	}
	if mid.Verdict != VisionBridgeProbeVerdictNativeAligned {
		t.Fatalf("mid.Verdict=%q, want %q", mid.Verdict, VisionBridgeProbeVerdictNativeAligned)
	}

	failureConn := &testTraceConn{id: 406}
	ObserveVisionTransitionSource(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(failureConn, scope)
	ObserveVisionTransportLifecycle(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	LogVisionTransitionSummary(context.Background(), failureConn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionUplinkCompleteUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	final := SnapshotVisionBridgeProbeEpochForScope(scope)
	if final.State != VisionBridgeProbeStateCompleted {
		t.Fatalf("final.State=%q, want %q", final.State, VisionBridgeProbeStateCompleted)
	}
	if final.Observed != 2 {
		t.Fatalf("final.Observed=%d, want 2", final.Observed)
	}
	if final.Verdict != VisionBridgeProbeVerdictNativePendingCommand0 {
		t.Fatalf("final.Verdict=%q, want %q", final.Verdict, VisionBridgeProbeVerdictNativePendingCommand0)
	}
	if final.Stats.NativePendingCommand0Failure != 1 {
		t.Fatalf("final.Stats.NativePendingCommand0Failure=%d, want 1", final.Stats.NativePendingCommand0Failure)
	}
}

func TestVisionBridgeProbeEpochPrefersBidirectionalCommand0Verdict(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	resetVisionBridgeProbeEpochsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)
	t.Cleanup(resetVisionBridgeProbeEpochsForTest)

	base := time.Unix(2_100_000, 0)
	visionBridgeAssessmentNowFn = func() time.Time { return base }
	visionBridgeProbeNowFn = func() time.Time { return base }

	scope := "scope-probe-bidi|reality|tcp"
	start := EnsureVisionBridgeProbeEpoch(scope, 1, time.Minute)
	if start.State != VisionBridgeProbeStateActive {
		t.Fatalf("start.State=%q, want %q", start.State, VisionBridgeProbeStateActive)
	}

	failureConn := &testTraceConn{id: 1406}
	ObserveVisionTransitionSource(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(failureConn, scope)
	ObserveVisionTransportLifecycle(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 9})
	observeVisionTransportProvisionalEvent(failureConn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeActive})
	observeVisionTransportProvisionalEvent(failureConn, xtls.DeferredRustProvisionalObservation{Outcome: xtls.DeferredRustProvisionalOutcomeFailedPending, TerminalReason: xtls.DeferredRustProvisionalTerminalReasonOther})
	LogVisionTransitionSummary(context.Background(), failureConn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionUplinkCompleteUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	final := SnapshotVisionBridgeProbeEpochForScope(scope)
	if final.State != VisionBridgeProbeStateCompleted {
		t.Fatalf("final.State=%q, want %q", final.State, VisionBridgeProbeStateCompleted)
	}
	if final.Verdict != VisionBridgeProbeVerdictNativeProvisionalFailedPending {
		t.Fatalf("final.Verdict=%q, want %q", final.Verdict, VisionBridgeProbeVerdictNativeProvisionalFailedPending)
	}
	if final.FailedPendingReason != VisionNativeProvisionalTerminalReasonOther {
		t.Fatalf("final.FailedPendingReason=%q, want %q", final.FailedPendingReason, VisionNativeProvisionalTerminalReasonOther)
	}
	if final.Stats.NativeProvisionalCommand0Bidirectional != 1 {
		t.Fatalf("final.Stats.NativeProvisionalCommand0Bidirectional=%d, want 1", final.Stats.NativeProvisionalCommand0Bidirectional)
	}
	if final.Stats.NativeProvisionalCommand0BidirectionalFailure != 1 {
		t.Fatalf("final.Stats.NativeProvisionalCommand0BidirectionalFailure=%d, want 1", final.Stats.NativeProvisionalCommand0BidirectionalFailure)
	}
	if final.Stats.NativeProvisionalFailedPending != 1 {
		t.Fatalf("final.Stats.NativeProvisionalFailedPending=%d, want 1", final.Stats.NativeProvisionalFailedPending)
	}
	if final.Stats.NativeProvisionalFailedPendingOther != 1 {
		t.Fatalf("final.Stats.NativeProvisionalFailedPendingOther=%d, want 1", final.Stats.NativeProvisionalFailedPendingOther)
	}
	if final.Stats.NativePendingCommand0BidirectionalFailure != 1 {
		t.Fatalf("final.Stats.NativePendingCommand0BidirectionalFailure=%d, want 1", final.Stats.NativePendingCommand0BidirectionalFailure)
	}
}

func TestVisionBridgeProbeEpochTracksFailedPendingTerminalReason(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	resetVisionBridgeProbeEpochsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)
	t.Cleanup(resetVisionBridgeProbeEpochsForTest)

	base := time.Unix(2_150_000, 0)
	visionBridgeAssessmentNowFn = func() time.Time { return base }
	visionBridgeProbeNowFn = func() time.Time { return base }

	scope := "scope-probe-terminal-reason|reality|tcp"
	start := EnsureVisionBridgeProbeEpoch(scope, 1, time.Minute)
	if start.State != VisionBridgeProbeStateActive {
		t.Fatalf("start.State=%q, want %q", start.State, VisionBridgeProbeStateActive)
	}

	conn := &testTraceConn{id: 2406}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, scope)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 12})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeActive})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeFailedPending, TerminalReason: xtls.DeferredRustProvisionalTerminalReasonReset})
	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionUplinkCompleteUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitRemoteReset,
	})

	final := SnapshotVisionBridgeProbeEpochForScope(scope)
	if final.State != VisionBridgeProbeStateCompleted {
		t.Fatalf("final.State=%q, want %q", final.State, VisionBridgeProbeStateCompleted)
	}
	if final.Verdict != VisionBridgeProbeVerdictNativeProvisionalFailedPendingLocalClose {
		t.Fatalf("final.Verdict=%q, want %q", final.Verdict, VisionBridgeProbeVerdictNativeProvisionalFailedPendingLocalClose)
	}
	if final.FailedPendingReason != VisionNativeProvisionalTerminalReasonReset {
		t.Fatalf("final.FailedPendingReason=%q, want %q", final.FailedPendingReason, VisionNativeProvisionalTerminalReasonReset)
	}
	if final.Stats.NativeProvisionalFailedPendingReset != 1 {
		t.Fatalf("final.Stats.NativeProvisionalFailedPendingReset=%d, want 1", final.Stats.NativeProvisionalFailedPendingReset)
	}
}

func TestVisionBridgeProbeEpochTracksBridgeOwnedLocalCloseFailedPendingReason(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	resetVisionBridgeProbeEpochsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)
	t.Cleanup(resetVisionBridgeProbeEpochsForTest)

	base := time.Unix(2_151_000, 0)
	visionBridgeAssessmentNowFn = func() time.Time { return base }
	visionBridgeProbeNowFn = func() time.Time { return base }

	scope := "scope-probe-terminal-reason-local-close|reality|tcp"
	start := EnsureVisionBridgeProbeEpoch(scope, 1, time.Minute)
	if start.State != VisionBridgeProbeStateActive {
		t.Fatalf("start.State=%q, want %q", start.State, VisionBridgeProbeStateActive)
	}

	conn := &testTraceConn{id: 24061}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, scope)
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 12})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeActive})
	ObserveVisionNativeProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeFailedPending)
	ObserveVisionNativeProvisionalTerminalReason(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalTerminalReasonOther)
	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionControlUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitLocalCloseNoResponse,
	})

	final := SnapshotVisionBridgeProbeEpochForScope(scope)
	if final.State != VisionBridgeProbeStateCompleted {
		t.Fatalf("final.State=%q, want %q", final.State, VisionBridgeProbeStateCompleted)
	}
	if final.Verdict != VisionBridgeProbeVerdictNativeProvisionalFailedPendingLocalClose {
		t.Fatalf("final.Verdict=%q, want %q", final.Verdict, VisionBridgeProbeVerdictNativeProvisionalFailedPendingLocalClose)
	}
	if final.FailedPendingReason != VisionNativeProvisionalTerminalReasonLocalClose {
		t.Fatalf("final.FailedPendingReason=%q, want %q", final.FailedPendingReason, VisionNativeProvisionalTerminalReasonLocalClose)
	}
	if final.Stats.NativeProvisionalFailedPendingLocalClose != 1 {
		t.Fatalf("final.Stats.NativeProvisionalFailedPendingLocalClose=%d, want 1", final.Stats.NativeProvisionalFailedPendingLocalClose)
	}
	if final.Stats.NativeProvisionalFailedPendingOther != 0 {
		t.Fatalf("final.Stats.NativeProvisionalFailedPendingOther=%d, want 0", final.Stats.NativeProvisionalFailedPendingOther)
	}
}

func TestVisionBridgeProbeEpochIgnoresBridgeProducedProvisionalLifecycleForVerdict(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	resetVisionBridgeProbeEpochsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)
	t.Cleanup(resetVisionBridgeProbeEpochsForTest)

	base := time.Unix(2_175_000, 0)
	visionBridgeAssessmentNowFn = func() time.Time { return base }
	visionBridgeProbeNowFn = func() time.Time { return base }

	scope := "scope-probe-bridge-fallback|reality|tcp"
	start := EnsureVisionBridgeProbeEpoch(scope, 1, time.Minute)
	if start.State != VisionBridgeProbeStateActive {
		t.Fatalf("start.State=%q, want %q", start.State, VisionBridgeProbeStateActive)
	}

	conn := &testTraceConn{id: 2407}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, scope)
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 12})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionUplinkCompleteUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	final := SnapshotVisionBridgeProbeEpochForScope(scope)
	if final.State != VisionBridgeProbeStateCompleted {
		t.Fatalf("final.State=%q, want %q", final.State, VisionBridgeProbeStateCompleted)
	}
	if final.Verdict != VisionBridgeProbeVerdictNativePendingCommand0Bidirectional {
		t.Fatalf("final.Verdict=%q, want %q", final.Verdict, VisionBridgeProbeVerdictNativePendingCommand0Bidirectional)
	}
	if final.Stats.NativeProvisionalCommand0Bidirectional != 0 {
		t.Fatalf("final.Stats.NativeProvisionalCommand0Bidirectional=%d, want 0", final.Stats.NativeProvisionalCommand0Bidirectional)
	}
	if final.Stats.NativeProvisionalCommand0BidirectionalFailure != 0 {
		t.Fatalf("final.Stats.NativeProvisionalCommand0BidirectionalFailure=%d, want 0", final.Stats.NativeProvisionalCommand0BidirectionalFailure)
	}
	if final.Stats.NativePendingCommand0BidirectionalFailure != 1 {
		t.Fatalf("final.Stats.NativePendingCommand0BidirectionalFailure=%d, want 1", final.Stats.NativePendingCommand0BidirectionalFailure)
	}
}

func TestVisionBridgeProbeEpochExpiresByDuration(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	resetVisionBridgeProbeEpochsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)
	t.Cleanup(resetVisionBridgeProbeEpochsForTest)

	base := time.Unix(3_000_000, 0)
	visionBridgeProbeNowFn = func() time.Time { return base }

	scope := "scope-probe-expire|reality|tcp"
	start := EnsureVisionBridgeProbeEpoch(scope, 16, 2*time.Second)
	if start.State != VisionBridgeProbeStateActive {
		t.Fatalf("start.State=%q, want %q", start.State, VisionBridgeProbeStateActive)
	}
	visionBridgeProbeNowFn = func() time.Time { return base.Add(3 * time.Second) }
	final := SnapshotVisionBridgeProbeEpochForScope(scope)
	if final.State != VisionBridgeProbeStateCompleted {
		t.Fatalf("final.State=%q, want %q", final.State, VisionBridgeProbeStateCompleted)
	}
	if final.Verdict != VisionBridgeProbeVerdictNoSignal {
		t.Fatalf("final.Verdict=%q, want %q", final.Verdict, VisionBridgeProbeVerdictNoSignal)
	}
}

func TestLogVisionTransitionSummaryClassifiesPendingQuality(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)

	benignConn := &testTraceConn{id: 403}
	ObserveVisionTransitionSource(benignConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(benignConn, "scope-pending|reality|tcp")
	ObserveVisionTransportLifecycle(benignConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	LogVisionTransitionSummary(context.Background(), benignConn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonControlPlaneDNSGuard,
		UserspaceBytes: 128,
		UserspaceExit:  pipeline.UserspaceExitComplete,
	})

	failureConn := &testTraceConn{id: 404}
	ObserveVisionTransitionSource(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(failureConn, "scope-pending|reality|tcp")
	ObserveVisionTransportLifecycle(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(failureConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	LogVisionTransitionSummary(context.Background(), failureConn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionUplinkCompleteUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	stats := SnapshotVisionBridgeAssessmentStatsForScope("scope-pending|reality|tcp")
	if stats.NativePending != 2 {
		t.Fatalf("stats.NativePending=%d, want 2", stats.NativePending)
	}
	if stats.NativePendingBenign != 1 {
		t.Fatalf("stats.NativePendingBenign=%d, want 1", stats.NativePendingBenign)
	}
	if stats.NativePendingFailure != 1 {
		t.Fatalf("stats.NativePendingFailure=%d, want 1", stats.NativePendingFailure)
	}
	if stats.NativePendingCommand0Failure != 1 {
		t.Fatalf("stats.NativePendingCommand0Failure=%d, want 1", stats.NativePendingCommand0Failure)
	}
}

func TestLogVisionTransitionSummaryClassifiesBidirectionalCommand0PendingGap(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)

	conn := &testTraceConn{id: 1404}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-pending-gap|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 13})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 7})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeActive})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Outcome: xtls.DeferredRustProvisionalOutcomeFailedPending, TerminalReason: xtls.DeferredRustProvisionalTerminalReasonOther})
	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionUplinkCompleteUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitLocalCloseNoResponse,
	})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if ok {
		t.Fatalf("expected summary to be consumed at flow end, got %+v", summary)
	}
	stats := SnapshotVisionBridgeAssessmentStatsForScope("scope-pending-gap|reality|tcp")
	if stats.NativePendingFailure != 1 {
		t.Fatalf("stats.NativePendingFailure=%d, want 1", stats.NativePendingFailure)
	}
	if stats.NativePendingCommand0Failure != 1 {
		t.Fatalf("stats.NativePendingCommand0Failure=%d, want 1", stats.NativePendingCommand0Failure)
	}
	if stats.NativePendingCommand0BidirectionalFailure != 1 {
		t.Fatalf("stats.NativePendingCommand0BidirectionalFailure=%d, want 1", stats.NativePendingCommand0BidirectionalFailure)
	}
	if stats.NativeProvisionalCommand0Bidirectional != 1 {
		t.Fatalf("stats.NativeProvisionalCommand0Bidirectional=%d, want 1", stats.NativeProvisionalCommand0Bidirectional)
	}
	if stats.NativeProvisionalCommand0BidirectionalFailure != 0 {
		t.Fatalf("stats.NativeProvisionalCommand0BidirectionalFailure=%d, want 0", stats.NativeProvisionalCommand0BidirectionalFailure)
	}
	if stats.NativeProvisionalFailedPending != 0 {
		t.Fatalf("stats.NativeProvisionalFailedPending=%d, want 0", stats.NativeProvisionalFailedPending)
	}
}

func TestVisionTransitionSummaryPublishesNativeProvisionalSemantic(t *testing.T) {
	conn := &testTraceConn{id: 1405}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 15})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 6})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeActive})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalSemantic != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalSemantic=%q, want %q", summary.NativeProvisionalSemantic, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceTransportProducer {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceTransportProducer)
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalObserved=%q, want %q", summary.NativeProvisionalObserved, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalObservedSource != VisionNativeProvisionalSemanticSourceTransportProducer {
		t.Fatalf("summary.NativeProvisionalObservedSource=%q, want %q", summary.NativeProvisionalObservedSource, VisionNativeProvisionalSemanticSourceTransportProducer)
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeActive {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeActive)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceTransportProducer {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceTransportProducer)
	}
	if summary.PendingGap != VisionPendingGapCommand0BidirectionalNoDet {
		t.Fatalf("summary.PendingGap=%q, want %q", summary.PendingGap, VisionPendingGapCommand0BidirectionalNoDet)
	}
}

func TestVisionTransitionSummaryClearsPublishedNativeProvisionalSemantic(t *testing.T) {
	conn := &testTraceConn{id: 1406}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-clear|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 15})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 6})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeActive})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalSemantic != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalSemantic=%q, want %q", summary.NativeProvisionalSemantic, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceTransportProducer {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceTransportProducer)
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalObserved=%q, want %q", summary.NativeProvisionalObserved, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalObservedSource != VisionNativeProvisionalSemanticSourceTransportProducer {
		t.Fatalf("summary.NativeProvisionalObservedSource=%q, want %q", summary.NativeProvisionalObservedSource, VisionNativeProvisionalSemanticSourceTransportProducer)
	}

	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 1)
	ResolveVisionNativeProvisionalNoDetachAtSemanticBoundary(&VisionTransitionSource{
		conn:   conn,
		kind:   VisionTransitionKindDeferredRust,
		origin: VisionIngressOriginNativeRealityDeferred,
	})

	summary, ok = SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary after explicit no-detach")
	}
	if summary.NativeProvisionalSemantic != VisionNativeProvisionalSemanticNone {
		t.Fatalf("summary.NativeProvisionalSemantic=%q, want %q", summary.NativeProvisionalSemantic, VisionNativeProvisionalSemanticNone)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceNone {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceNone)
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalObserved=%q, want %q", summary.NativeProvisionalObserved, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalObservedSource != VisionNativeProvisionalSemanticSourceTransportProducer {
		t.Fatalf("summary.NativeProvisionalObservedSource=%q, want %q", summary.NativeProvisionalObservedSource, VisionNativeProvisionalSemanticSourceTransportProducer)
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeResolvedNoDetach {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeResolvedNoDetach)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceExplicitProducer)
	}
}

func TestObserveVisionNativeProvisionalSemanticProducerOverrideAndClear(t *testing.T) {
	conn := &testTraceConn{id: 1407}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-producer|reality|tcp")

	ObserveVisionNativeExplicitProvisionalSemantic(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalSemanticCommand0Bidirectional)

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary after producer override")
	}
	if summary.NativeProvisionalSemantic != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalSemantic=%q, want %q", summary.NativeProvisionalSemantic, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceExplicitProducer)
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalObserved=%q, want %q", summary.NativeProvisionalObserved, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalObservedSource != VisionNativeProvisionalSemanticSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalObservedSource=%q, want %q", summary.NativeProvisionalObservedSource, VisionNativeProvisionalSemanticSourceExplicitProducer)
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeActive {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeActive)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceDerived {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceDerived)
	}

	ObserveVisionNativeExplicitProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeFailedPending)

	summary, ok = SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary after outcome producer override")
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeFailedPending {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeFailedPending)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceExplicitProducer)
	}

	ObserveVisionNativeExplicitProvisionalSemantic(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalSemanticNone)
	ObserveVisionNativeExplicitProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeNone)

	summary, ok = SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary after producer clear")
	}
	if summary.NativeProvisionalSemantic != VisionNativeProvisionalSemanticNone {
		t.Fatalf("summary.NativeProvisionalSemantic=%q, want %q", summary.NativeProvisionalSemantic, VisionNativeProvisionalSemanticNone)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceNone {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceNone)
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalObserved=%q, want %q", summary.NativeProvisionalObserved, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalObservedSource != VisionNativeProvisionalSemanticSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalObservedSource=%q, want %q", summary.NativeProvisionalObservedSource, VisionNativeProvisionalSemanticSourceExplicitProducer)
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeActive {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeActive)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceDerived {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceDerived)
	}
}

func TestVisionTransitionSummaryUsesProducerNativeProvisionalSemanticForPendingGap(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)

	conn := &testTraceConn{id: 1408}
	scope := "scope-provisional-gap|reality|tcp"
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, scope)
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionNativeProvisionalSemantic(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalSemanticCommand0Bidirectional)

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary after producer provisional semantic")
	}
	if summary.PendingGap != VisionPendingGapCommand0BidirectionalNoDet {
		t.Fatalf("summary.PendingGap=%q, want %q", summary.PendingGap, VisionPendingGapCommand0BidirectionalNoDet)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceBridgeProducer {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceBridgeProducer)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceDerived {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceDerived)
	}

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionUplinkCompleteUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	stats := SnapshotVisionBridgeAssessmentStatsForScope(scope)
	if stats.NativeProvisionalCommand0Bidirectional != 0 {
		t.Fatalf("stats.NativeProvisionalCommand0Bidirectional=%d, want 0", stats.NativeProvisionalCommand0Bidirectional)
	}
	if stats.NativeProvisionalCommand0BidirectionalFailure != 0 {
		t.Fatalf("stats.NativeProvisionalCommand0BidirectionalFailure=%d, want 0", stats.NativeProvisionalCommand0BidirectionalFailure)
	}
	if stats.NativePendingCommand0BidirectionalFailure != 1 {
		t.Fatalf("stats.NativePendingCommand0BidirectionalFailure=%d, want 1", stats.NativePendingCommand0BidirectionalFailure)
	}
}

func TestVisionTransitionSummaryDerivesNativeProvisionalOutcomeFailure(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 1409}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-outcome-failure|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionNativeProvisionalSemantic(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalSemanticCommand0Bidirectional)

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionUplinkCompleteUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_observed=command0_bidirectional") ||
		!strings.Contains(logs, "native_provisional_observed_source=bridge_producer") ||
		!strings.Contains(logs, "native_provisional_outcome=failed_pending") ||
		!strings.Contains(logs, "native_provisional_outcome_source=bridge_producer") ||
		!strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing native provisional outcome fields in logs: %s", logs)
	}
}

func TestObserveVisionNativeProvisionalOutcomeProducerOverrideAndClear(t *testing.T) {
	conn := &testTraceConn{id: 1410}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-outcome-producer|reality|tcp")
	ObserveVisionNativeExplicitProvisionalSemantic(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalSemanticCommand0Bidirectional)

	ObserveVisionNativeExplicitProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeBenignClose)

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary after outcome producer override")
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeBenignClose {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeBenignClose)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceExplicitProducer)
	}
	if summary.PendingQuality != VisionPendingQualityBenign {
		t.Fatalf("summary.PendingQuality=%q, want %q", summary.PendingQuality, VisionPendingQualityBenign)
	}

	ObserveVisionNativeExplicitProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeNone)

	summary, ok = SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary after outcome producer clear")
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeActive {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeActive)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceDerived {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceDerived)
	}
}

func TestVisionTransitionSummaryDoesNotDeriveLiveNativeProvisionalLifecycleWithoutProducer(t *testing.T) {
	conn := &testTraceConn{id: 14140}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-no-live-derived-provisional|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 17})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 9})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalSemantic != VisionNativeProvisionalSemanticNone {
		t.Fatalf("summary.NativeProvisionalSemantic=%q, want %q", summary.NativeProvisionalSemantic, VisionNativeProvisionalSemanticNone)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceNone {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceNone)
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticNone {
		t.Fatalf("summary.NativeProvisionalObserved=%q, want %q", summary.NativeProvisionalObserved, VisionNativeProvisionalSemanticNone)
	}
	if summary.NativeProvisionalObservedSource != VisionNativeProvisionalSemanticSourceNone {
		t.Fatalf("summary.NativeProvisionalObservedSource=%q, want %q", summary.NativeProvisionalObservedSource, VisionNativeProvisionalSemanticSourceNone)
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeNone {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeNone)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceNone {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceNone)
	}
	if summary.PendingGap != VisionPendingGapCommand0BidirectionalNoDet {
		t.Fatalf("summary.PendingGap=%q, want %q", summary.PendingGap, VisionPendingGapCommand0BidirectionalNoDet)
	}
}

func TestResolveVisionNativeProvisionalNoDetachAtSemanticBoundaryUsesTransportFallback(t *testing.T) {
	conn := &testTraceConn{id: 14141}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-transport-fallback-no-detach|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 1)

	ResolveVisionNativeProvisionalNoDetachAtSemanticBoundary(&VisionTransitionSource{
		conn:   conn,
		kind:   VisionTransitionKindDeferredRust,
		origin: VisionIngressOriginNativeRealityDeferred,
	})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeResolvedNoDetach {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeResolvedNoDetach)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceExplicitProducer)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceNone {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceNone)
	}
	if summary.NativeProvisionalTerminalReason != VisionNativeProvisionalTerminalReasonNone {
		t.Fatalf("summary.NativeProvisionalTerminalReason=%q, want %q", summary.NativeProvisionalTerminalReason, VisionNativeProvisionalTerminalReasonNone)
	}
	if summary.PendingQuality != VisionPendingQualityNone {
		t.Fatalf("summary.PendingQuality=%q, want %q", summary.PendingQuality, VisionPendingQualityNone)
	}
}

func TestResolveVisionNativeProvisionalNoDetachAtSemanticBoundaryOverridesFailedPending(t *testing.T) {
	conn := &testTraceConn{id: 14144}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-transport-failed-then-no-detach|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})

	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Outcome:        xtls.DeferredRustProvisionalOutcomeFailedPending,
		TerminalReason: xtls.DeferredRustProvisionalTerminalReasonEOF,
	})
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 1)

	ResolveVisionNativeProvisionalNoDetachAtSemanticBoundary(&VisionTransitionSource{
		conn:   conn,
		kind:   VisionTransitionKindDeferredRust,
		origin: VisionIngressOriginNativeRealityDeferred,
	})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeResolvedNoDetach {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeResolvedNoDetach)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceExplicitProducer)
	}
	if summary.PendingQuality != VisionPendingQualityBenign {
		t.Fatalf("summary.PendingQuality=%q, want %q", summary.PendingQuality, VisionPendingQualityBenign)
	}
	if summary.PendingClass != VisionPendingClassExplicitNoDetach {
		t.Fatalf("summary.PendingClass=%q, want %q", summary.PendingClass, VisionPendingClassExplicitNoDetach)
	}
	if summary.PendingGap != VisionPendingGapOther {
		t.Fatalf("summary.PendingGap=%q, want %q", summary.PendingGap, VisionPendingGapOther)
	}
	if summary.NativeProvisionalTerminalReason != VisionNativeProvisionalTerminalReasonNone {
		t.Fatalf("summary.NativeProvisionalTerminalReason=%q, want %q", summary.NativeProvisionalTerminalReason, VisionNativeProvisionalTerminalReasonNone)
	}
}

func TestLogVisionTransitionSummaryMergedExplicitNoDetachOverridesFailedPending(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	failedConn := &testTraceConn{id: 14145}
	noDetachConn := &testTraceConn{id: 14146}

	ObserveVisionTransitionSource(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(failedConn, "scope-merged-failed-then-command1|reality|tcp")
	ObserveVisionTransitionEvent(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	observeVisionTransportProvisionalEvent(failedConn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	observeVisionTransportProvisionalEvent(failedConn, xtls.DeferredRustProvisionalObservation{
		Outcome:        xtls.DeferredRustProvisionalOutcomeFailedPending,
		TerminalReason: xtls.DeferredRustProvisionalTerminalReasonEOF,
	})

	ObserveVisionTransitionSource(noDetachConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(noDetachConn, "scope-merged-failed-then-command1|reality|tcp")
	ObserveVisionTransitionEvent(noDetachConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(noDetachConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 1)

	LogVisionTransitionSummary(context.Background(), failedConn, noDetachConn, nil)

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=resolved_no_detach") {
		t.Fatalf("expected resolved no-detach outcome in merged summary logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_outcome_source=explicit_producer") {
		t.Fatalf("expected explicit producer ownership in merged summary logs: %s", logs)
	}
	if strings.Contains(logs, "pending_quality=user_visible_failure") {
		t.Fatalf("unexpected stale failure classification in merged summary logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_quality=benign") {
		t.Fatalf("expected benign classification in merged summary logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_class=explicit_no_detach") {
		t.Fatalf("expected explicit no-detach class in merged summary logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_gap=other") {
		t.Fatalf("expected non-command0 pending gap in merged summary logs: %s", logs)
	}
}

func TestObserveVisionTransportProvisionalEventPublishesFailedPendingTerminalReason(t *testing.T) {
	conn := &testTraceConn{id: 14111}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-terminal-reset|reality|tcp")
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 11})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 7})

	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeActive})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Outcome: xtls.DeferredRustProvisionalOutcomeFailedPending, TerminalReason: xtls.DeferredRustProvisionalTerminalReasonReset})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticCommand0Bidirectional {
		t.Fatalf("summary.NativeProvisionalObserved=%q, want %q", summary.NativeProvisionalObserved, VisionNativeProvisionalSemanticCommand0Bidirectional)
	}
	if summary.NativeProvisionalObservedSource != VisionNativeProvisionalSemanticSourceTransportProducer {
		t.Fatalf("summary.NativeProvisionalObservedSource=%q, want %q", summary.NativeProvisionalObservedSource, VisionNativeProvisionalSemanticSourceTransportProducer)
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeFailedPending {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeFailedPending)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceExplicitProducer)
	}
	if summary.NativeProvisionalTerminalReason != VisionNativeProvisionalTerminalReasonReset {
		t.Fatalf("summary.NativeProvisionalTerminalReason=%q, want %q", summary.NativeProvisionalTerminalReason, VisionNativeProvisionalTerminalReasonReset)
	}
}

func TestObserveVisionTransportProvisionalEventPublishesBenignPendingCloseTerminalReason(t *testing.T) {
	conn := &testTraceConn{id: 14112}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-terminal-close|reality|tcp")

	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional, Outcome: xtls.DeferredRustProvisionalOutcomeActive})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{Outcome: xtls.DeferredRustProvisionalOutcomeBenignClose, TerminalReason: xtls.DeferredRustProvisionalTerminalReasonLocalClose})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeBenignClose {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeBenignClose)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceExplicitProducer {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceExplicitProducer)
	}
	if summary.NativeProvisionalTerminalReason != VisionNativeProvisionalTerminalReasonLocalClose {
		t.Fatalf("summary.NativeProvisionalTerminalReason=%q, want %q", summary.NativeProvisionalTerminalReason, VisionNativeProvisionalTerminalReasonLocalClose)
	}
}

func TestVisionTransitionSummaryDoesNotReDeriveTransportPublishedProvisionalSemantic(t *testing.T) {
	conn := &testTraceConn{id: 14142}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-transport-provisional-no-rederive-semantic|reality|tcp")
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 11})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 7})

	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticNone,
		Outcome:  xtls.DeferredRustProvisionalOutcomeNone,
	})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalSemantic != VisionNativeProvisionalSemanticNone {
		t.Fatalf("summary.NativeProvisionalSemantic=%q, want %q", summary.NativeProvisionalSemantic, VisionNativeProvisionalSemanticNone)
	}
	if summary.NativeProvisionalSource != VisionNativeProvisionalSemanticSourceNone {
		t.Fatalf("summary.NativeProvisionalSource=%q, want %q", summary.NativeProvisionalSource, VisionNativeProvisionalSemanticSourceNone)
	}
}

func TestVisionTransitionSummaryDoesNotReDeriveTransportPublishedProvisionalOutcome(t *testing.T) {
	conn := &testTraceConn{id: 14143}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-transport-provisional-no-rederive-outcome|reality|tcp")
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticNone,
		Outcome:  xtls.DeferredRustProvisionalOutcomeNone,
	})

	summary, ok := SnapshotVisionTransitionSummary(conn, nil)
	if !ok {
		t.Fatal("SnapshotVisionTransitionSummary() returned no summary")
	}
	if summary.NativeProvisionalOutcome != VisionNativeProvisionalOutcomeNone {
		t.Fatalf("summary.NativeProvisionalOutcome=%q, want %q", summary.NativeProvisionalOutcome, VisionNativeProvisionalOutcomeNone)
	}
	if summary.NativeProvisionalOutcomeSource != VisionNativeProvisionalOutcomeSourceNone {
		t.Fatalf("summary.NativeProvisionalOutcomeSource=%q, want %q", summary.NativeProvisionalOutcomeSource, VisionNativeProvisionalOutcomeSourceNone)
	}
	if summary.NativeProvisionalObserved != VisionNativeProvisionalSemanticNone {
		t.Fatalf("summary.NativeProvisionalObserved=%q, want %q", summary.NativeProvisionalObserved, VisionNativeProvisionalSemanticNone)
	}
	if summary.NativeProvisionalObservedSource != VisionNativeProvisionalSemanticSourceNone {
		t.Fatalf("summary.NativeProvisionalObservedSource=%q, want %q", summary.NativeProvisionalObservedSource, VisionNativeProvisionalSemanticSourceNone)
	}
}

func TestVisionTransitionSummaryUsesProducerProvisionalFailureForPendingClassification(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 14135}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-failure-class|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionNativeProvisionalSemantic(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalSemanticCommand0Bidirectional)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonDeferredTLSGuard,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	if _, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		t.Fatalf("expected summary to be consumed after logging")
	}
	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=failed_pending") {
		t.Fatalf("missing failed pending provisional outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_outcome_source=bridge_producer") {
		t.Fatalf("missing bridge producer ownership in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing failed pending terminal reason in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_quality=user_visible_failure") {
		t.Fatalf("missing failure pending quality in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_class=command0_only") {
		t.Fatalf("missing command0 pending class in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_gap=command0_bidirectional_no_detach") {
		t.Fatalf("missing command0 bidirectional pending gap in logs: %s", logs)
	}
}

func TestVisionTransitionSummaryFinalizesActiveProducerProvisionalFailure(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 14147}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-active-final-failure|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonDeferredTLSGuard,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	if _, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		t.Fatalf("expected summary to be consumed after logging")
	}
	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=failed_pending") {
		t.Fatalf("missing finalized failed pending provisional outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_outcome_source=bridge_producer") {
		t.Fatalf("missing bridge producer ownership in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing local_close terminal reason in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_quality=user_visible_failure") {
		t.Fatalf("missing failure pending quality in logs: %s", logs)
	}
}

func TestVisionTransitionSummaryUsesProducerProvisionalBenignOutcomeForPendingClassification(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 14137}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-benign-class|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionNativeProvisionalSemantic(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalSemanticCommand0Bidirectional)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonControlPlaneDNSGuard,
		UserspaceBytes: 64,
		UserspaceExit:  pipeline.UserspaceExitComplete,
	})
	if _, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		t.Fatalf("expected summary to be consumed after logging")
	}
	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=benign_pending_close") {
		t.Fatalf("missing benign provisional outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing benign pending terminal reason in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_quality=benign") {
		t.Fatalf("missing benign pending quality in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_class=command0_only") {
		t.Fatalf("missing command0 pending class in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_gap=command0_bidirectional_no_detach") {
		t.Fatalf("missing command0 bidirectional pending gap in logs: %s", logs)
	}
}

func TestVisionTransitionSummaryFinalizesActiveProducerProvisionalBenignClose(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 14148}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-active-final-benign|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 15})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 6})
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonControlPlaneDNSGuard,
		UserspaceBytes: 64,
		UserspaceExit:  pipeline.UserspaceExitComplete,
	})

	if _, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		t.Fatalf("expected summary to be consumed after logging")
	}
	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=benign_pending_close") {
		t.Fatalf("missing benign provisional outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_outcome_source=bridge_producer") {
		t.Fatalf("missing bridge producer benign ownership in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing local_close terminal reason in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_quality=benign") {
		t.Fatalf("missing benign pending quality in logs: %s", logs)
	}
}

func TestVisionTransitionSummaryFinalizesObservedProducerProvisionalFailure(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 14149}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-observed-final-failure|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionNativeExplicitProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeNone)

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonDeferredTLSGuard,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitLocalCloseNoResponse,
	})

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=failed_pending") {
		t.Fatalf("missing finalized failed_pending outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_outcome_source=bridge_producer") {
		t.Fatalf("missing bridge-owned local-close ownership in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing local_close terminal reason in logs: %s", logs)
	}
}

func TestVisionTransitionSummaryNormalizesBridgeFailedPendingToBridgeOwnedLocalClose(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 14150}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-bridge-failed-final-normalize|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionNativeProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeFailedPending)
	ObserveVisionNativeProvisionalTerminalReason(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalTerminalReasonOther)

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionControlUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitLocalCloseNoResponse,
	})

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=failed_pending") {
		t.Fatalf("missing finalized failed_pending outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_outcome_source=bridge_producer") {
		t.Fatalf("missing bridge producer ownership after normalization in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing normalized local_close terminal reason in logs: %s", logs)
	}
}

func TestVisionTransitionSummaryNormalizesExplicitFailedPendingToBridgeOwnedLocalClose(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 14151}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-explicit-failed-final-normalize|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	observeVisionTransportProvisionalEvent(conn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionNativeExplicitProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeFailedPending)
	ObserveVisionNativeProvisionalTerminalReason(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalTerminalReasonOther)

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionControlUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitLocalCloseNoResponse,
	})

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=failed_pending") {
		t.Fatalf("missing finalized failed_pending outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_outcome_source=bridge_producer") {
		t.Fatalf("missing bridge producer ownership after explicit normalization in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing normalized local_close terminal reason in logs: %s", logs)
	}
}

func TestVisionTransitionSummaryMergedBridgeFailedPendingNormalizesToLocalClose(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	failedConn := &testTraceConn{id: 14161}
	secondaryConn := &testTraceConn{id: 14162}

	ObserveVisionTransitionSource(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(failedConn, "scope-merged-bridge-local-close|reality|tcp")
	ObserveVisionTransportLifecycle(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	observeVisionTransportProvisionalEvent(failedConn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	ObserveVisionTransportProgress(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 21})
	ObserveVisionTransportProgress(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 8})
	ObserveVisionTransitionEvent(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionNativeProvisionalOutcome(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeFailedPending)
	ObserveVisionNativeProvisionalTerminalReason(failedConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalTerminalReasonOther)

	ObserveVisionTransitionSource(secondaryConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(secondaryConn, "scope-merged-bridge-local-close|reality|tcp")
	ObserveVisionTransitionEvent(secondaryConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)

	LogVisionTransitionSummary(context.Background(), failedConn, secondaryConn, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonVisionControlUserspace,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitLocalCloseNoResponse,
	})

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=failed_pending") {
		t.Fatalf("missing finalized failed_pending outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_outcome_source=bridge_producer") {
		t.Fatalf("missing bridge producer ownership after merge in logs: %s", logs)
	}
	if !strings.Contains(logs, "native_provisional_terminal_reason=local_close") {
		t.Fatalf("missing normalized merged local_close terminal reason in logs: %s", logs)
	}
}

func TestVisionTransitionSummaryUsesProducerResolvedNoDetachForPendingClassification(t *testing.T) {
	t.Setenv("XRAY_DEBUG_VISION_TRANSITION_TRACE", "1")
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	conn := &testTraceConn{id: 14139}
	ObserveVisionTransitionSource(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(conn, "scope-provisional-resolved-no-detach-class|reality|tcp")
	ObserveVisionTransportLifecycle(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionNativeProvisionalSemantic(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalSemanticCommand0Bidirectional)
	ObserveVisionTransitionEvent(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionNativeProvisionalOutcome(conn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionNativeProvisionalOutcomeResolvedNoDetach)

	LogVisionTransitionSummary(context.Background(), conn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonDeferredTLSGuard,
		UserspaceBytes: 0,
		UserspaceExit:  pipeline.UserspaceExitTimeout,
	})

	if _, ok := SnapshotVisionTransitionSummary(conn, nil); ok {
		t.Fatalf("expected summary to be consumed after logging")
	}
	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "native_provisional_outcome=resolved_no_detach") {
		t.Fatalf("missing resolved no-detach provisional outcome in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_quality=benign") {
		t.Fatalf("missing benign pending quality in logs: %s", logs)
	}
	if strings.Contains(logs, "pending_quality=user_visible_failure") {
		t.Fatalf("unexpected failure pending quality in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_class=explicit_no_detach") {
		t.Fatalf("missing explicit no-detach pending class in logs: %s", logs)
	}
	if !strings.Contains(logs, "pending_gap=other") {
		t.Fatalf("missing no-detach pending gap in logs: %s", logs)
	}
}

func TestLogVisionTransitionSummaryCountsNativeProvisionalOutcomes(t *testing.T) {
	resetVisionBridgeAssessmentStatsForTest()
	t.Cleanup(resetVisionBridgeAssessmentStatsForTest)

	scope := "scope-provisional-outcomes|reality|tcp"

	activeConn := &testTraceConn{id: 1410}
	ObserveVisionTransitionSource(activeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(activeConn, scope)
	ObserveVisionTransportLifecycle(activeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(activeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(activeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(activeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 15})
	ObserveVisionTransportProgress(activeConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 6})
	observeVisionTransportProvisionalEvent(activeConn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	LogVisionTransitionSummary(context.Background(), activeConn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonDeferredTLSGuard,
		UserspaceBytes: 1,
		UserspaceExit:  pipeline.UserspaceExitRemoteEOFNoResponse,
	})

	resolvedDirectConn := &testTraceConn{id: 1411}
	ObserveVisionTransitionSource(resolvedDirectConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(resolvedDirectConn, scope)
	ObserveVisionTransitionEvent(resolvedDirectConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(resolvedDirectConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(resolvedDirectConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 15})
	ObserveVisionTransportProgress(resolvedDirectConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 6})
	observeVisionTransportProvisionalEvent(resolvedDirectConn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	ObserveVisionTransportLifecycle(resolvedDirectConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDetachCompleted)
	ObserveVisionTransitionDrain(resolvedDirectConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 5, 2)
	ObserveVisionTransportDrain(resolvedDirectConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, VisionDrainModeDeferred, 5, 2)
	observeVisionTransportProvisionalEvent(resolvedDirectConn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeResolvedDirect,
	})
	LogVisionTransitionSummary(context.Background(), resolvedDirectConn, nil, nil)

	benignConn := &testTraceConn{id: 1412}
	ObserveVisionTransitionSource(benignConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred)
	ObserveVisionTransitionScope(benignConn, scope)
	ObserveVisionTransportLifecycle(benignConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustLifecycleDeferredActive)
	ObserveVisionTransitionEvent(benignConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransitionEvent(benignConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, "uplink", VisionTransitionEventCommandObserved, 0)
	ObserveVisionTransportProgress(benignConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressWrite, Bytes: 15})
	ObserveVisionTransportProgress(benignConn, VisionTransitionKindDeferredRust, VisionIngressOriginNativeRealityDeferred, xtls.DeferredRustProgressEvent{Direction: xtls.DeferredRustProgressRead, Bytes: 6})
	observeVisionTransportProvisionalEvent(benignConn, xtls.DeferredRustProvisionalObservation{
		Semantic: xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:  xtls.DeferredRustProvisionalOutcomeActive,
	})
	observeVisionTransportProvisionalEvent(benignConn, xtls.DeferredRustProvisionalObservation{
		Semantic:       xtls.DeferredRustProvisionalSemanticCommand0Bidirectional,
		Outcome:        xtls.DeferredRustProvisionalOutcomeBenignClose,
		TerminalReason: xtls.DeferredRustProvisionalTerminalReasonLocalClose,
	})
	LogVisionTransitionSummary(context.Background(), benignConn, nil, &pipeline.DecisionSnapshot{
		Path:           pipeline.PathUserspace,
		Reason:         pipeline.ReasonControlPlaneDNSGuard,
		UserspaceBytes: 64,
		UserspaceExit:  pipeline.UserspaceExitComplete,
	})

	stats := SnapshotVisionBridgeAssessmentStatsForScope(scope)
	if stats.NativeProvisionalActive != 1 {
		t.Fatalf("stats.NativeProvisionalActive=%d, want 1", stats.NativeProvisionalActive)
	}
	if stats.NativeProvisionalResolvedDirect != 1 {
		t.Fatalf("stats.NativeProvisionalResolvedDirect=%d, want 1", stats.NativeProvisionalResolvedDirect)
	}
	if stats.NativeProvisionalBenignClose != 0 {
		t.Fatalf("stats.NativeProvisionalBenignClose=%d, want 0", stats.NativeProvisionalBenignClose)
	}
	if stats.NativeProvisionalResolvedNoDetach != 0 {
		t.Fatalf("stats.NativeProvisionalResolvedNoDetach=%d, want 0", stats.NativeProvisionalResolvedNoDetach)
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
