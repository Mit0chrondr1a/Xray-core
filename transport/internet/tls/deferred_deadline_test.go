package tls

import (
	"errors"
	"net"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/native"
)

func TestDeferredRustConnReadUsesDeadlineAwareNativePath(t *testing.T) {
	oldRead := deferredReadFn
	oldReadWithDeadline := deferredReadWithDeadlineFn
	t.Cleanup(func() {
		deferredReadFn = oldRead
		deferredReadWithDeadlineFn = oldReadWithDeadline
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	deferredReadFn = func(_ *native.DeferredSessionHandle, _ []byte) (int, error) {
		t.Fatal("unexpected non-deadline deferred read")
		return 0, nil
	}

	called := false
	deferredReadWithDeadlineFn = func(_ *native.DeferredSessionHandle, _ []byte, deadline time.Time) (int, error) {
		called = true
		if deadline.IsZero() {
			t.Fatal("deadline-aware deferred read received zero deadline")
		}
		return 0, os.ErrDeadlineExceeded
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	if err := dc.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	_, err := dc.Read(make([]byte, 8))
	if !called {
		t.Fatal("deadline-aware deferred read was not used")
	}
	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read() error = %v, want deadline exceeded", err)
	}
	if netErr, ok := err.(interface{ Timeout() bool }); !ok || !netErr.Timeout() {
		t.Fatalf("Read() error = %T %v, want timeout-capable error", err, err)
	}
}

func TestDeferredRustConnReadWithoutDeadlineUsesLegacyPath(t *testing.T) {
	oldRead := deferredReadFn
	oldReadWithDeadline := deferredReadWithDeadlineFn
	t.Cleanup(func() {
		deferredReadFn = oldRead
		deferredReadWithDeadlineFn = oldReadWithDeadline
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	deferredReadFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		copy(b, []byte("R"))
		return 1, nil
	}
	deferredReadWithDeadlineFn = func(h *native.DeferredSessionHandle, b []byte, deadline time.Time) (int, error) {
		if !deadline.IsZero() {
			t.Fatal("unexpected non-zero deadline")
		}
		return deferredReadFn(h, b)
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	buf := make([]byte, 1)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 1 || buf[0] != 'R' {
		t.Fatalf("Read() = (%d, %q), want (1, %q)", n, buf[:n], "R")
	}
}

func TestDeferredRustConnReadCacheBeatsExpiredDeadline(t *testing.T) {
	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	dc := &DeferredRustConn{
		rawConn:         client,
		handle:          &native.DeferredSessionHandle{},
		deferredReadBuf: []byte("cached"),
		deferredReadLen: len("cached"),
	}
	if err := dc.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	buf := make([]byte, len("cached"))
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got := string(buf[:n]); got != "cached" {
		t.Fatalf("Read() = %q, want %q", got, "cached")
	}
}
