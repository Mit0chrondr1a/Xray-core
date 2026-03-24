package proxy

import (
	"context"
	goerrors "errors"
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
	if strings.Contains(logs, "vision_phase=") || strings.Contains(logs, "vision_semantic_phase=") {
		t.Fatalf("pipeline summary should not include removed vision summary fields: %s", logs)
	}
}

func TestInferTLSOffloadPathFromCryptoDetectsKTLS(t *testing.T) {
	if got := inferTLSOffloadPathFromCrypto(ebpf.CryptoKTLSBoth, ebpf.CryptoNone); got != pipeline.TLSOffloadKTLS {
		t.Fatalf("inferTLSOffloadPathFromCrypto(kTLS, raw)=%q, want %q", got, pipeline.TLSOffloadKTLS)
	}
	if got := inferTLSOffloadPathFromCrypto(ebpf.CryptoNone, ebpf.CryptoNone); got != pipeline.TLSOffloadNotRequired {
		t.Fatalf("inferTLSOffloadPathFromCrypto(raw, raw)=%q, want %q", got, pipeline.TLSOffloadNotRequired)
	}
	if got := inferTLSOffloadPathFromCrypto(ebpf.CryptoUserspaceTLS, ebpf.CryptoUserspaceTLS); got != pipeline.TLSOffloadUnknown {
		t.Fatalf("inferTLSOffloadPathFromCrypto(userspace, userspace)=%q, want %q", got, pipeline.TLSOffloadUnknown)
	}
}

func TestAnnotateFallbackTLSOffloadOverridesUserspaceSummary(t *testing.T) {
	ctx := context.WithValue(context.Background(), fallbackRuntimeRecoveryContextKey{}, fallbackRuntimeRecoveryMeta{
		Tag:                    "reality-vision-main",
		FrontendTransport:      "deferred_rust",
		FrontendTLSOffloadPath: pipeline.TLSOffloadKTLS,
	})
	decision := &pipeline.DecisionSnapshot{
		Path:           pipeline.PathSplice,
		TLSOffloadPath: pipeline.TLSOffloadUserspace,
	}

	annotateFallbackTLSOffload(ctx, decision)

	if decision.TLSOffloadPath != pipeline.TLSOffloadKTLS {
		t.Fatalf("decision.TLSOffloadPath=%q, want %q", decision.TLSOffloadPath, pipeline.TLSOffloadKTLS)
	}
}

func TestMaybeReportFallbackNativeRuntimeRecoveryOnRawHandoffLogsMeasuredTLSOffload(t *testing.T) {
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	oldReport := reportNativeRuntimeRecoveryByTagFn
	t.Cleanup(func() {
		reportNativeRuntimeRecoveryByTagFn = oldReport
	})

	reportNativeRuntimeRecoveryByTagFn = func(string) bool { return true }

	handler := &testSeverityCaptureHandler{level: clog.Severity_Info}
	clog.RegisterHandler(handler)

	ctx := context.WithValue(context.Background(), fallbackRuntimeRecoveryContextKey{}, fallbackRuntimeRecoveryMeta{
		Tag:                    "reality-vision-main",
		FrontendTransport:      "deferred_rust",
		FrontendTLSOffloadPath: pipeline.TLSOffloadKTLS,
		State:                  &fallbackRuntimeRecoveryState{},
	})

	if !maybeReportFallbackNativeRuntimeRecoveryOnRawHandoff(ctx, "response") {
		t.Fatal("maybeReportFallbackNativeRuntimeRecoveryOnRawHandoff()=false, want true")
	}

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "tls_offload_path=ktls") {
		t.Fatalf("fallback runtime recovery log missing measured tls_offload_path: %s", logs)
	}
	if strings.Contains(logs, "copy_path=splice") {
		t.Fatalf("fallback runtime recovery log should not hardcode copy_path before execution: %s", logs)
	}
}

func TestCopyRawConnIfExistLogsPendingUserspaceAfterNoDetachEOF(t *testing.T) {
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
		Tag:           "native-vision-logging",
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Conn:          writerConn,
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{57, 144, 150, 192}), xnet.Port(443)),
	}
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(100*time.Millisecond, func() {
		markVisionNoDetachObserved(ctx, outbound)
		sendVisionSignal(visionCh, session.VisionSignal{Command: 1})
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil after EOF pending-userspace close", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for pending-userspace EOF flow")
	}

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "reason=vision_no_detach_userspace") {
		t.Fatalf("missing stable no-detach reason in logs: %s", logs)
	}
	if !strings.Contains(logs, "userspace_exit=stable_userspace_close") {
		t.Fatalf("missing stable no-detach exit in logs: %s", logs)
	}
}

func TestCopyRawConnIfExistLogsLateExplicitPostDetachSignalDuringGrace(t *testing.T) {
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
		Tag:           "native-vision-logging",
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Conn:          writerConn,
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{91, 108, 56, 133}), xnet.Port(443)),
	}
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(100*time.Millisecond, func() {
		sendVisionSignal(visionCh, session.VisionSignal{Command: 0})
	})
	time.AfterFunc(6200*time.Millisecond, func() {
		markVisionPostDetachObserved(ctx, outbound)
		markDeferredRustConnDetachedForTest(writerConn)
		sendVisionSignal(visionCh, session.VisionSignal{Command: 2})
	})
	time.AfterFunc(6450*time.Millisecond, func() {
		_, _ = readerPeer.Write([]byte("late-explicit-post-detach"))
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil && !goerrors.Is(err, io.EOF) {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil/EOF after late explicit post-detach signal", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for late explicit post-detach signal flow")
	}

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "kind=vision.signal_received] command=2") {
		t.Fatalf("missing late explicit post-detach signal log: %s", logs)
	}
	if strings.Contains(logs, "kind=vision.native_runtime_feedback") {
		t.Fatalf("unexpected native runtime feedback log after late explicit post-detach signal: %s", logs)
	}
	if strings.Contains(logs, "kind=vision.pre_detach_deadline_no_detach") {
		t.Fatalf("unexpected pre-detach no-detach resolution log during late explicit post-detach signal: %s", logs)
	}
}

func TestCopyRawConnIfExistDoesNotLogRuntimeFeedbackForZeroByteTimeoutWithoutVisionSignalChannel(t *testing.T) {
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})
	oldReport := reportNativeRuntimeRegressionByTagFn
	reportNativeRuntimeRegressionByTagFn = func(string) bool { return true }
	t.Cleanup(func() {
		reportNativeRuntimeRegressionByTagFn = oldReport
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
		Tag:           "native-vision-logging",
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Conn:          writerConn,
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{91, 108, 56, 133}), xnet.Port(443)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()
	time.AfterFunc(8*time.Second, func() {
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil && !goerrors.Is(err, io.EOF) {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil/EOF after peer closes paced no-signal flow", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for paced no-signal flow to finish after peer close")
	}

	logs := strings.Join(handler.msgs, "\n")
	if strings.Contains(logs, "kind=vision.native_runtime_feedback") {
		t.Fatalf("unexpected native runtime feedback log after zero-byte paced no-signal flow: %s", logs)
	}
	if strings.Contains(logs, "reason=userspace_idle_timeout") {
		t.Fatalf("unexpected timeout reason after peer-closed paced no-signal flow: %s", logs)
	}
	if !strings.Contains(logs, "reason=userspace_complete") {
		t.Fatalf("missing userspace-complete reason in paced no-signal flow logs: %s", logs)
	}
	if !strings.Contains(logs, "copy_gate_state=copy_pending_detach") {
		t.Fatalf("missing pending-detach copy gate in paced no-signal summary: %s", logs)
	}
	if !strings.Contains(logs, "userspace_bytes=0") {
		t.Fatalf("missing zero-byte evidence in paced no-signal summary: %s", logs)
	}
}

func TestCopyRawConnIfExistDoesNotLogRuntimeFeedbackForPartialProgressTimeoutWithoutVisionSignalChannel(t *testing.T) {
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})
	oldReport := reportNativeRuntimeRegressionByTagFn
	reportNativeRuntimeRegressionByTagFn = func(string) bool { return true }
	t.Cleanup(func() {
		reportNativeRuntimeRegressionByTagFn = oldReport
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
		Tag:           "native-vision-logging-partial",
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Conn:          writerConn,
	}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGatePendingDetach),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{57, 144, 14, 36}), xnet.Port(5222)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, writerConn, buf.Discard, timer, nil)
	}()

	time.AfterFunc(200*time.Millisecond, func() {
		_, _ = readerPeer.Write([]byte("partial-progress"))
	})
	time.AfterFunc(8*time.Second, func() {
		_ = readerPeer.Close()
	})

	select {
	case err := <-errCh:
		if err != nil && !goerrors.Is(err, io.EOF) {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil/EOF after peer closes paced partial-progress flow", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("timeout waiting for paced partial-progress flow to finish after peer close")
	}

	logs := strings.Join(handler.msgs, "\n")
	if strings.Contains(logs, "kind=vision.native_runtime_feedback") {
		t.Fatalf("unexpected native runtime feedback log after paced partial-progress await-signal flow: %s", logs)
	}
	if strings.Contains(logs, "reason=userspace_idle_timeout") {
		t.Fatalf("unexpected timeout reason after paced partial-progress flow: %s", logs)
	}
	if !strings.Contains(logs, "reason=userspace_complete") {
		t.Fatalf("missing userspace-complete reason in paced partial-progress flow logs: %s", logs)
	}
	if !strings.Contains(logs, "copy_gate_state=copy_pending_detach") {
		t.Fatalf("missing pending-detach copy gate in paced partial-progress summary: %s", logs)
	}
	if !strings.Contains(logs, "userspace_bytes=16") {
		t.Fatalf("missing partial-progress evidence in paced partial-progress summary: %s", logs)
	}
}

func TestObserveVisionUplinkCompleteLogsLocalNoDetachResolution(t *testing.T) {
	t.Cleanup(func() {
		clog.RegisterHandler(clog.NewLogger(clog.CreateStdoutLogWriter()))
	})

	handler := &testSeverityCaptureHandler{level: clog.Severity_Debug}
	clog.RegisterHandler(handler)

	inbound := &session.Inbound{Tag: "native-vision-log-resolution", Conn: &xtls.DeferredRustConn{}}
	inbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	outbound := &session.Outbound{}
	outbound.SetCanSpliceCopy(session.CopyGatePendingDetach)
	visionCh := make(chan session.VisionSignal, 1)
	ctx := session.ContextWithInbound(session.ContextWithVisionSignal(context.Background(), visionCh), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	if !ObserveVisionUplinkComplete(ctx, inbound, outbound) {
		t.Fatal("ObserveVisionUplinkComplete() = false, want true")
	}

	logs := strings.Join(handler.msgs, "\n")
	if !strings.Contains(logs, "kind=vision.uplink_complete_local_no_detach") {
		t.Fatalf("missing local no-detach uplink completion log: %s", logs)
	}
	if !strings.Contains(logs, "tag=native-vision-log-resolution") {
		t.Fatalf("missing native vision tag in local no-detach log: %s", logs)
	}
	if !strings.Contains(logs, "semantic_phase=vision_no_detach") {
		t.Fatalf("missing vision_no_detach semantic phase in local resolution log: %s", logs)
	}
	if !strings.Contains(logs, "inbound_gate=copy_forced_userspace") {
		t.Fatalf("missing forced userspace inbound gate in local resolution log: %s", logs)
	}
	if !strings.Contains(logs, "outbound_gates=0:copy_forced_userspace/vision_no_detach") {
		t.Fatalf("missing forced userspace outbound gate summary in local resolution log: %s", logs)
	}
	if strings.Contains(logs, "command=1 observed") {
		t.Fatalf("local resolution log should not claim command=1 was observed on wire: %s", logs)
	}
}
