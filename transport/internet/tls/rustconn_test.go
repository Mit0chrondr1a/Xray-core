package tls

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/native"
)

func TestRustConn_ReadWriteOnClosed(t *testing.T) {
	rc := &RustConn{rawConn: nil}
	_, err := rc.Read(make([]byte, 10))
	if err == nil {
		t.Fatal("expected error reading from closed RustConn")
	}
	_, err = rc.Write([]byte("test"))
	if err == nil {
		t.Fatal("expected error writing to closed RustConn")
	}
}

func TestRustConn_ReadWriteWithInitErr(t *testing.T) {
	rc := &RustConn{initErr: io.ErrClosedPipe}
	_, err := rc.Read(make([]byte, 10))
	if err != io.ErrClosedPipe {
		t.Fatalf("expected ErrClosedPipe, got %v", err)
	}
	_, err = rc.Write([]byte("test"))
	if err != io.ErrClosedPipe {
		t.Fatalf("expected ErrClosedPipe, got %v", err)
	}
}

func TestRustConn_DrainedData(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	drained := []byte("hello from handshake drain")
	rc := &RustConn{
		rawConn:     client,
		drainedData: drained,
		ktls:        KTLSState{Enabled: false},
	}

	buf := make([]byte, 100)
	n, err := rc.Read(buf)
	if err != nil {
		t.Fatalf("unexpected error reading drained data: %v", err)
	}
	if string(buf[:n]) != string(drained) {
		t.Fatalf("drained data mismatch: got %q, want %q", buf[:n], drained)
	}
}

func TestRustConn_DrainedDataPartialRead(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	drained := []byte("abcdefghij")
	rc := &RustConn{
		rawConn:     client,
		drainedData: drained,
		ktls:        KTLSState{Enabled: false},
	}

	buf := make([]byte, 3)
	n, err := rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "abc" {
		t.Fatalf("first read: got %q, want %q", buf[:n], "abc")
	}

	n, err = rc.Read(buf)
	if err != nil {
		t.Fatal(err)
	}
	if string(buf[:n]) != "def" {
		t.Fatalf("second read: got %q, want %q", buf[:n], "def")
	}
}

func TestRustConn_CloseZeroesDrainedData(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	drained := []byte("secret handshake data")
	drainedCopy := make([]byte, len(drained))
	copy(drainedCopy, drained)

	rc := &RustConn{
		rawConn:     client,
		drainedData: drainedCopy,
		ktls:        KTLSState{Enabled: false},
	}
	rc.Close()

	for i, b := range drainedCopy {
		if b != 0 {
			t.Fatalf("drainedData byte %d not zeroed after Close: %02x", i, b)
		}
	}
}

func TestRustConn_LocalRemoteAddr(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	rc := &RustConn{rawConn: client}
	if rc.LocalAddr() == nil {
		t.Fatal("expected non-nil LocalAddr")
	}
	if rc.RemoteAddr() == nil {
		t.Fatal("expected non-nil RemoteAddr")
	}

	rcNil := &RustConn{rawConn: nil}
	if rcNil.LocalAddr() != nil {
		t.Fatal("expected nil LocalAddr for nil rawConn")
	}
	if rcNil.RemoteAddr() != nil {
		t.Fatal("expected nil RemoteAddr for nil rawConn")
	}
}

func TestRustConn_SetDeadlineOnClosed(t *testing.T) {
	rc := &RustConn{rawConn: nil}
	if err := rc.SetDeadline(time.Now()); err == nil {
		t.Fatal("expected error for SetDeadline on closed RustConn")
	}
	if err := rc.SetReadDeadline(time.Now()); err == nil {
		t.Fatal("expected error for SetReadDeadline on closed RustConn")
	}
	if err := rc.SetWriteDeadline(time.Now()); err == nil {
		t.Fatal("expected error for SetWriteDeadline on closed RustConn")
	}
}

func TestRustConn_HandshakeContext(t *testing.T) {
	rc := &RustConn{initErr: io.EOF}
	if err := rc.HandshakeContext(context.Background()); err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}

	rcOK := &RustConn{}
	if err := rcOK.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}

func TestRustConn_VerifyHostname(t *testing.T) {
	rc := &RustConn{serverName: "example.com"}
	if err := rc.VerifyHostname("example.com"); err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if err := rc.VerifyHostname("other.com"); err == nil {
		t.Fatal("expected error for hostname mismatch")
	}

	rcEmpty := &RustConn{}
	if err := rcEmpty.VerifyHostname("any.com"); err == nil {
		t.Fatal("expected error when server name is empty")
	}

	rcErr := &RustConn{initErr: io.EOF}
	if err := rcErr.VerifyHostname("any.com"); err != io.EOF {
		t.Fatalf("expected initErr, got %v", err)
	}
}

func TestRustConn_NegotiatedProtocol(t *testing.T) {
	rc := &RustConn{alpn: "h2"}
	if got := rc.NegotiatedProtocol(); got != "h2" {
		t.Fatalf("expected h2, got %q", got)
	}
}

func TestRustConn_HandshakeContextServerName(t *testing.T) {
	rc := &RustConn{serverName: "test.example.com"}
	if got := rc.HandshakeContextServerName(context.Background()); got != "test.example.com" {
		t.Fatalf("expected test.example.com, got %q", got)
	}
}

func TestNewRustConnChecked_NilResult(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	_, err := NewRustConnChecked(client, nil, "")
	if err == nil {
		t.Fatal("expected error for nil result")
	}
}

func TestNewRustConnChecked_NilRawConn(t *testing.T) {
	result := &native.TlsResult{KtlsTx: true, KtlsRx: true}
	_, err := NewRustConnChecked(nil, result, "")
	if err == nil {
		t.Fatal("expected error for nil raw connection")
	}
}

func TestNewRustConnChecked_PartialKTLS(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	result := &native.TlsResult{KtlsTx: true, KtlsRx: false}
	_, err := NewRustConnChecked(client, result, "")
	if err == nil {
		t.Fatal("expected error when kTLS is not fully offloaded")
	}
}

func TestNewRustConn_ErrorWrapsInInitErr(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	result := &native.TlsResult{KtlsTx: false, KtlsRx: false}
	rc := NewRustConn(client, result, "")
	if rc.initErr == nil {
		t.Fatal("expected initErr to be set for partial kTLS")
	}
}

func TestValidateNativeKTLS(t *testing.T) {
	if err := validateNativeKTLS(nil); err == nil {
		t.Fatal("expected error for nil result")
	}

	result := &native.TlsResult{KtlsTx: true, KtlsRx: true}
	if err := validateNativeKTLS(result); err != nil {
		t.Fatalf("expected nil error for full kTLS, got %v", err)
	}

	result2 := &native.TlsResult{KtlsTx: true, KtlsRx: false}
	if err := validateNativeKTLS(result2); err == nil {
		t.Fatal("expected error for partial kTLS")
	}
}

func TestDeferredRustConn_DrainAndDetachNilHandle(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()

	dc := &DeferredRustConn{rawConn: client}
	plain, raw, err := dc.DrainAndDetach()
	if err == nil {
		t.Fatal("expected error for nil deferred handle")
	}
	if len(plain) != 0 || len(raw) != 0 {
		t.Fatal("expected no drained data on error")
	}
	if dc.IsDetached() {
		t.Fatal("expected connection to remain attached after failed drain")
	}
	_ = dc.Close()
}

func TestDeferredRustConn_ReadWriteAfterDetached(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	dc := &DeferredRustConn{
		rawConn:     client,
		drainedData: []byte("hi"),
	}
	dc.detached.Store(true)

	buf := make([]byte, 2)
	if n, err := dc.Read(buf); err != nil {
		t.Fatalf("expected detached read to serve staged bytes, got error: %v", err)
	} else if got := string(buf[:n]); got != "hi" {
		t.Fatalf("detached staged read = %q, want %q", got, "hi")
	}
	writeToClient := make(chan error, 1)
	go func() {
		_, err := server.Write([]byte("ok"))
		writeToClient <- err
	}()
	if n, err := dc.Read(buf); err != nil {
		t.Fatalf("expected detached read to continue on raw socket, got error: %v", err)
	} else if got := string(buf[:n]); got != "ok" {
		t.Fatalf("detached raw read = %q, want %q", got, "ok")
	}
	if err := <-writeToClient; err != nil {
		t.Fatalf("server write failed: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		var b [1]byte
		_, err := server.Read(b[:])
		readDone <- err
	}()
	if n, err := dc.Write([]byte{0x01}); err != nil {
		t.Fatalf("expected detached write to use raw socket, got error: %v", err)
	} else if n != 1 {
		t.Fatalf("expected detached write to write 1 byte, got %d", n)
	}
	if err := <-readDone; err != nil {
		t.Fatalf("server read failed: %v", err)
	}
	if !dc.IsDetached() {
		t.Fatal("expected IsDetached() to report true")
	}
}

func TestDeferredRustConn_RestoreNonBlockNilHandle(t *testing.T) {
	dc := &DeferredRustConn{rawConn: nil}
	// Nil handle should be a no-op (returns nil).
	if err := dc.RestoreNonBlock(); err != nil {
		t.Fatalf("expected nil error for nil handle, got %v", err)
	}
}

func TestDeferredRustConn_RestoreNonBlockAfterDetach(t *testing.T) {
	dc := &DeferredRustConn{rawConn: nil}
	dc.detached.Store(true)
	// Already detached — should be a no-op.
	if err := dc.RestoreNonBlock(); err != nil {
		t.Fatalf("expected nil error after detach, got %v", err)
	}
}
