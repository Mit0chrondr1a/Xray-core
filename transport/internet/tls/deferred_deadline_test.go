package tls

import (
	"errors"
	"io"
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

func TestDeferredRustConnReadWithoutDeadlineRetriesWouldBlock(t *testing.T) {
	oldReadWithDeadline := deferredReadWithDeadlineFn
	oldWaitReadable := deferredWaitReadableFn
	t.Cleanup(func() {
		deferredReadWithDeadlineFn = oldReadWithDeadline
		deferredWaitReadableFn = oldWaitReadable
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	calls := 0
	waitCalls := 0
	deferredReadWithDeadlineFn = func(_ *native.DeferredSessionHandle, b []byte, deadline time.Time) (int, error) {
		calls++
		if !deadline.IsZero() {
			t.Fatal("unexpected non-zero deadline")
		}
		if calls == 1 {
			return 0, native.ErrDeferredWouldBlock
		}
		copy(b, []byte("OK"))
		return 2, nil
	}
	deferredWaitReadableFn = func(_ *DeferredRustConn) error {
		waitCalls++
		return nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	buf := make([]byte, 2)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if calls < 2 {
		t.Fatalf("Read() calls = %d, want retry after would-block", calls)
	}
	if waitCalls != 1 {
		t.Fatalf("waitReadable calls = %d, want 1", waitCalls)
	}
	if got := string(buf[:n]); got != "OK" {
		t.Fatalf("Read() = %q, want %q", got, "OK")
	}
}

func TestDeferredRustConnReadWithoutDeadlinePropagatesNetpollerWaitError(t *testing.T) {
	oldReadWithDeadline := deferredReadWithDeadlineFn
	oldWaitReadable := deferredWaitReadableFn
	t.Cleanup(func() {
		deferredReadWithDeadlineFn = oldReadWithDeadline
		deferredWaitReadableFn = oldWaitReadable
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	deferredReadWithDeadlineFn = func(_ *native.DeferredSessionHandle, _ []byte, deadline time.Time) (int, error) {
		if !deadline.IsZero() {
			t.Fatal("unexpected non-zero deadline")
		}
		return 0, native.ErrDeferredWouldBlock
	}

	want := io.EOF
	deferredWaitReadableFn = func(_ *DeferredRustConn) error {
		return want
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	_, err := dc.Read(make([]byte, 1))
	if !errors.Is(err, want) {
		t.Fatalf("Read() error = %v, want %v", err, want)
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

func TestDeferredDeadlineOverrunRequiresMaterialMiss(t *testing.T) {
	start := time.Now()
	deadline := start.Add(50 * time.Millisecond)

	if overrun, ok := deferredDeadlineOverrun(start, deadline, deadline.Add(100*time.Millisecond)); ok {
		t.Fatalf("deferredDeadlineOverrun() unexpectedly reported short miss: %v", overrun)
	}

	overrun, ok := deferredDeadlineOverrun(start, deadline, deadline.Add(deferredDeadlineOverrunLogGap+25*time.Millisecond))
	if !ok {
		t.Fatal("deferredDeadlineOverrun() did not report material miss")
	}
	want := deferredDeadlineOverrunLogGap + 25*time.Millisecond
	if overrun != want {
		t.Fatalf("deferredDeadlineOverrun() = %v, want %v", overrun, want)
	}
}

func TestDeferredDeadlineOverrunSkipsExpiredOrUnsetDeadlines(t *testing.T) {
	start := time.Now()
	if _, ok := deferredDeadlineOverrun(start, time.Time{}, start.Add(time.Second)); ok {
		t.Fatal("zero deadline should not report overrun")
	}
	expired := start.Add(-time.Millisecond)
	if _, ok := deferredDeadlineOverrun(start, expired, start.Add(time.Second)); ok {
		t.Fatal("deadline already expired at call start should not report overrun")
	}
}

func TestDeferredReadParkedRequiresZeroDeadlineAndLongBlock(t *testing.T) {
	start := time.Now()

	if parked, ok := deferredReadParked(start, time.Time{}, start.Add(2*time.Second)); ok {
		t.Fatalf("deferredReadParked() unexpectedly reported short parked read: %v", parked)
	}

	parked, ok := deferredReadParked(start, time.Time{}, start.Add(deferredReadParkedThreshold+250*time.Millisecond))
	if !ok {
		t.Fatal("deferredReadParked() did not report long parked zero-deadline read")
	}
	want := deferredReadParkedThreshold + 250*time.Millisecond
	if parked != want {
		t.Fatalf("deferredReadParked() = %v, want %v", parked, want)
	}
}

func TestDeferredReadParkedSkipsDeadlineAwareReads(t *testing.T) {
	start := time.Now()
	deadline := start.Add(time.Second)
	if _, ok := deferredReadParked(start, deadline, start.Add(deferredReadParkedThreshold+time.Second)); ok {
		t.Fatal("deadline-aware read should not report parked")
	}
}
