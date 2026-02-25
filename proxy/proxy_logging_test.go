package proxy

import (
	"context"
	"io"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	clog "github.com/xtls/xray-core/common/log"
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
	if !strings.Contains(debugLog, "writer is not *net.TCPConn") {
		t.Fatal("missing XHTTP fallback debug log at debug level")
	}
	if !strings.Contains(debugLog, "*proxy.testXHTTPFlowConn") {
		t.Fatal("missing XHTTP flow type in debug logs")
	}
}
