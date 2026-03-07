package tls

import (
	goerrors "errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/native"
)

func TestDeferredRustConnWriteDefaultsToImmediateSmallWrite(t *testing.T) {
	oldWrite := deferredWriteFn
	t.Cleanup(func() {
		deferredWriteFn = oldWrite
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var writes [][]byte
	deferredWriteFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		writes = append(writes, append([]byte(nil), b...))
		return len(b), nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	first := make([]byte, deferredWriteBatchThreshold-256)
	for i := range first {
		first[i] = 'a'
	}

	if n, err := dc.Write(first); err != nil || n != len(first) {
		t.Fatalf("first Write() = (%d, %v), want (%d, nil)", n, err, len(first))
	}
	if len(writes) != 1 {
		t.Fatalf("DeferredWrite calls after first small write = %d, want 1", len(writes))
	}
	if got, want := len(writes[0]), len(first); got != want {
		t.Fatalf("immediate payload len = %d, want %d", got, want)
	}
	if dc.deferredWriteLen != 0 {
		t.Fatalf("default immediate write should not leave pending bytes, pending=%d", dc.deferredWriteLen)
	}
}

func TestDeferredRustConnWriteCoalescesSmallWritesWhenEnabled(t *testing.T) {
	oldWrite := deferredWriteFn
	t.Cleanup(func() {
		deferredWriteFn = oldWrite
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var writes [][]byte
	deferredWriteFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		writes = append(writes, append([]byte(nil), b...))
		return len(b), nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	dc.SetDeferredWriteBatching(true)
	first := make([]byte, deferredWriteBatchThreshold-256)
	second := make([]byte, 512)
	for i := range first {
		first[i] = 'a'
	}
	for i := range second {
		second[i] = 'b'
	}

	if n, err := dc.Write(first); err != nil || n != len(first) {
		t.Fatalf("first Write() = (%d, %v), want (%d, nil)", n, err, len(first))
	}
	if len(writes) != 0 {
		t.Fatalf("DeferredWrite calls after first small write = %d, want 0", len(writes))
	}

	if n, err := dc.Write(second); err != nil || n != len(second) {
		t.Fatalf("second Write() = (%d, %v), want (%d, nil)", n, err, len(second))
	}
	if len(writes) != 1 {
		t.Fatalf("DeferredWrite calls = %d, want 1", len(writes))
	}
	if got, want := len(writes[0]), len(first)+len(second); got != want {
		t.Fatalf("coalesced payload len = %d, want %d", got, want)
	}
	if writes[0][0] != 'a' || writes[0][len(writes[0])-1] != 'b' {
		t.Fatalf("coalesced payload boundaries = %q...%q, want 'a'...'b'", writes[0][0], writes[0][len(writes[0])-1])
	}
}

func TestDeferredRustConnReadFlushesPendingWrite(t *testing.T) {
	oldWrite := deferredWriteFn
	oldRead := deferredReadFn
	t.Cleanup(func() {
		deferredWriteFn = oldWrite
		deferredReadFn = oldRead
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var order []string
	var flushed []byte
	deferredWriteFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		order = append(order, "write")
		flushed = append([]byte(nil), b...)
		return len(b), nil
	}
	deferredReadFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		order = append(order, "read")
		copy(b, []byte("OK"))
		return 2, nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	dc.SetDeferredWriteBatching(true)
	if _, err := dc.Write([]byte("req")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	buf := make([]byte, 2)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 2 || string(buf[:n]) != "OK" {
		t.Fatalf("Read() = (%d, %q), want (2, %q)", n, buf[:n], "OK")
	}
	if string(flushed) != "req" {
		t.Fatalf("flushed pending write = %q, want %q", flushed, "req")
	}
	if len(order) != 2 || order[0] != "write" || order[1] != "read" {
		t.Fatalf("operation order = %v, want [write read]", order)
	}
}

func TestDeferredRustConnDrainAndDetachFlushesPendingWrite(t *testing.T) {
	oldWrite := deferredWriteFn
	oldDrain := deferredDrainAndDetachFn
	t.Cleanup(func() {
		deferredWriteFn = oldWrite
		deferredDrainAndDetachFn = oldDrain
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var order []string
	deferredWriteFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		order = append(order, "write:"+string(b))
		return len(b), nil
	}
	deferredDrainAndDetachFn = func(_ *native.DeferredSessionHandle) ([]byte, []byte, error) {
		order = append(order, "detach")
		return []byte("plain"), []byte("raw"), nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	dc.SetDeferredWriteBatching(true)
	if _, err := dc.Write([]byte("pending")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	plain, raw, err := dc.DrainAndDetach()
	if err != nil {
		t.Fatalf("DrainAndDetach() error = %v", err)
	}
	if string(plain) != "plain" || string(raw) != "raw" {
		t.Fatalf("DrainAndDetach() = (%q, %q), want (%q, %q)", plain, raw, "plain", "raw")
	}
	if len(order) != 2 || order[0] != "write:pending" || order[1] != "detach" {
		t.Fatalf("operation order = %v, want [write:pending detach]", order)
	}
}

func TestEnableKTLSOutcomeFlushesPendingWriteBeforePromotion(t *testing.T) {
	oldWrite := deferredWriteFn
	oldEnable := deferredEnableKTLSFn
	oldAlive := deferredHandleAliveFn
	oldSupported := nativeFullKTLSSupportedFn
	oldCooldown := deferredKTLSPromotionDisabledUntilUnixNano.Load()
	const scope = "test-write-batch-enable"
	t.Cleanup(func() {
		deferredWriteFn = oldWrite
		deferredEnableKTLSFn = oldEnable
		deferredHandleAliveFn = oldAlive
		nativeFullKTLSSupportedFn = oldSupported
		deferredKTLSPromotionDisabledUntilUnixNano.Store(oldCooldown)
		deferredKTLSPromotionScopes.Delete(scope)
		deferredKTLSPromotionScopeMetrics.Delete(scope)
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var order []string
	deferredWriteFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		order = append(order, "write:"+string(b))
		return len(b), nil
	}
	deferredEnableKTLSFn = func(*native.DeferredSessionHandle) (*native.TlsResult, error) {
		order = append(order, "enable")
		return nil, goerrors.New("boom")
	}
	deferredHandleAliveFn = func(*native.DeferredSessionHandle) bool { return true }
	nativeFullKTLSSupportedFn = func() bool { return true }

	dc := &DeferredRustConn{
		rawConn:   client,
		handle:    &native.DeferredSessionHandle{},
		ktlsScope: scope,
	}
	dc.SetDeferredWriteBatching(true)
	if _, err := dc.Write([]byte("req")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if _, err := dc.EnableKTLSOutcome(); err == nil {
		t.Fatal("EnableKTLSOutcome() error = nil, want non-nil")
	}
	if len(order) != 2 || order[0] != "write:req" || order[1] != "enable" {
		t.Fatalf("operation order = %v, want [write:req enable]", order)
	}
}

func TestDeferredRustConnReadFlushShortWrite(t *testing.T) {
	oldWrite := deferredWriteFn
	oldRead := deferredReadFn
	t.Cleanup(func() {
		deferredWriteFn = oldWrite
		deferredReadFn = oldRead
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	deferredWriteFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		return len(b) - 1, nil
	}
	deferredReadFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		copy(b, []byte("X"))
		return 1, nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	dc.SetDeferredWriteBatching(true)
	if _, err := dc.Write([]byte("req")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	buf := make([]byte, 1)
	if _, err := dc.Read(buf); !goerrors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Read() error = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestDeferredRustConnReadUsesConfiguredDeadline(t *testing.T) {
	oldRead := deferredReadWithDeadlineFn
	t.Cleanup(func() {
		deferredReadWithDeadlineFn = oldRead
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var seenDeadline time.Time
	deferredReadWithDeadlineFn = func(_ *native.DeferredSessionHandle, _ []byte, deadline time.Time) (int, error) {
		seenDeadline = deadline
		return 0, os.ErrDeadlineExceeded
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	deadline := time.Now().Add(25 * time.Millisecond)
	if err := dc.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	if _, err := dc.Read(make([]byte, 1)); !goerrors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("Read() error = %v, want %v", err, os.ErrDeadlineExceeded)
	}
	if seenDeadline.IsZero() {
		t.Fatal("deferred read deadline was not forwarded")
	}
	if seenDeadline.Before(deadline.Add(-5*time.Millisecond)) || seenDeadline.After(deadline.Add(5*time.Millisecond)) {
		t.Fatalf("deferred read deadline = %v, want near %v", seenDeadline, deadline)
	}
}

func TestDeferredRustConnReadFlushUsesReadDeadlineWhenWriteDeadlineUnset(t *testing.T) {
	oldWrite := deferredWriteWithDeadlineFn
	oldRead := deferredReadWithDeadlineFn
	t.Cleanup(func() {
		deferredWriteWithDeadlineFn = oldWrite
		deferredReadWithDeadlineFn = oldRead
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	var flushDeadline time.Time
	deferredWriteWithDeadlineFn = func(_ *native.DeferredSessionHandle, b []byte, deadline time.Time) (int, error) {
		flushDeadline = deadline
		return len(b), nil
	}
	deferredReadWithDeadlineFn = func(_ *native.DeferredSessionHandle, b []byte, deadline time.Time) (int, error) {
		copy(b, []byte("R"))
		return 1, nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	dc.SetDeferredWriteBatching(true)
	if _, err := dc.Write([]byte("req")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	deadline := time.Now().Add(30 * time.Millisecond)
	if err := dc.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline() error = %v", err)
	}

	buf := make([]byte, 1)
	if _, err := dc.Read(buf); err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if flushDeadline.IsZero() {
		t.Fatal("read-triggered flush did not receive a deadline")
	}
	if flushDeadline.Before(deadline.Add(-5*time.Millisecond)) || flushDeadline.After(deadline.Add(5*time.Millisecond)) {
		t.Fatalf("flush deadline = %v, want near %v", flushDeadline, deadline)
	}
}

func TestDeferredRustConnWriteDeadlineBypassesBatching(t *testing.T) {
	oldWrite := deferredWriteFn
	oldWriteWithDeadline := deferredWriteWithDeadlineFn
	t.Cleanup(func() {
		deferredWriteFn = oldWrite
		deferredWriteWithDeadlineFn = oldWriteWithDeadline
	})

	server, client := net.Pipe()
	defer server.Close()
	defer client.Close()

	deferredWriteFn = func(_ *native.DeferredSessionHandle, _ []byte) (int, error) {
		t.Fatal("buffering path should not use deadline-free deferred write")
		return 0, nil
	}

	var (
		seenDeadline time.Time
		seenPayload  []byte
	)
	deferredWriteWithDeadlineFn = func(_ *native.DeferredSessionHandle, b []byte, deadline time.Time) (int, error) {
		seenDeadline = deadline
		seenPayload = append([]byte(nil), b...)
		return len(b), nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}
	deadline := time.Now().Add(25 * time.Millisecond)
	if err := dc.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline() error = %v", err)
	}

	payload := []byte("abc")
	if n, err := dc.Write(payload); err != nil || n != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	if string(seenPayload) != string(payload) {
		t.Fatalf("deadline-aware write payload = %q, want %q", seenPayload, payload)
	}
	if seenDeadline.IsZero() {
		t.Fatal("write deadline was not forwarded")
	}
	if dc.deferredWriteLen != 0 {
		t.Fatalf("deadline-aware write should not leave batched bytes, pending=%d", dc.deferredWriteLen)
	}
}
