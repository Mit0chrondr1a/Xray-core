package tls

import (
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/native"
)

func TestDeferredRustConnDrainAndDetachWaitsForInFlightRead(t *testing.T) {
	oldRead := deferredReadFn
	oldDrain := deferredDrainAndDetachFn
	t.Cleanup(func() {
		deferredReadFn = oldRead
		deferredDrainAndDetachFn = oldDrain
	})

	server, client := gonet.Pipe()
	defer server.Close()
	defer client.Close()

	readStarted := make(chan struct{})
	releaseRead := make(chan struct{})
	detachCalled := make(chan struct{})

	deferredReadFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		close(readStarted)
		<-releaseRead
		copy(b, []byte("R"))
		return 1, nil
	}
	deferredDrainAndDetachFn = func(_ *native.DeferredSessionHandle) ([]byte, []byte, error) {
		close(detachCalled)
		return nil, nil, nil
	}

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}

	readDone := make(chan struct{})
	go func() {
		defer close(readDone)
		buf := make([]byte, 1)
		_, _ = dc.Read(buf)
	}()

	<-readStarted

	detachDone := make(chan struct{})
	go func() {
		defer close(detachDone)
		_, _, _ = dc.DrainAndDetach()
	}()

	select {
	case <-detachCalled:
		t.Fatal("DrainAndDetach started before in-flight read completed")
	case <-time.After(50 * time.Millisecond):
	}

	close(releaseRead)

	select {
	case <-detachCalled:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DrainAndDetach did not resume after in-flight read completed")
	}

	<-readDone
	<-detachDone
}

func TestDeferredRustConnDrainAndDetachCallsObserverAfterSuccess(t *testing.T) {
	oldDrain := deferredDrainAndDetachFn
	oldObserver := snapshotDeferredRustDrainObserver()
	oldLifecycle := snapshotDeferredRustLifecycleObserver()
	t.Cleanup(func() {
		deferredDrainAndDetachFn = oldDrain
		SetDeferredRustDrainObserver(oldObserver)
		SetDeferredRustLifecycleObserver(oldLifecycle)
	})

	server, client := gonet.Pipe()
	defer server.Close()
	defer client.Close()

	deferredDrainAndDetachFn = func(_ *native.DeferredSessionHandle) ([]byte, []byte, error) {
		return []byte("plain"), []byte("raw"), nil
	}

	var (
		gotConn gonet.Conn
		gotP    int
		gotR    int
	)
	observed := make(chan struct{}, 1)
	SetDeferredRustDrainObserver(func(conn gonet.Conn, plaintextLen int, rawAheadLen int) {
		gotConn = conn
		gotP = plaintextLen
		gotR = rawAheadLen
		observed <- struct{}{}
	})

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}

	plain, raw, err := dc.DrainAndDetach()
	if err != nil {
		t.Fatalf("DrainAndDetach() error = %v", err)
	}
	if string(plain) != "plain" || string(raw) != "raw" {
		t.Fatalf("DrainAndDetach() = (%q, %q), want (%q, %q)", plain, raw, "plain", "raw")
	}

	select {
	case <-observed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DeferredRust drain observer was not called")
	}

	if gotConn != dc {
		t.Fatalf("observer conn = %T %v, want %T %v", gotConn, gotConn, dc, dc)
	}
	if gotP != len("plain") || gotR != len("raw") {
		t.Fatalf("observer lens = (%d, %d), want (%d, %d)", gotP, gotR, len("plain"), len("raw"))
	}
}

func TestNewDeferredRustConnCallsLifecycleObserver(t *testing.T) {
	oldObserver := snapshotDeferredRustLifecycleObserver()
	t.Cleanup(func() {
		SetDeferredRustLifecycleObserver(oldObserver)
	})

	server, client := gonet.Pipe()
	defer server.Close()
	defer client.Close()

	var (
		gotConn  gonet.Conn
		gotEvent DeferredRustLifecycleEvent
	)
	observed := make(chan struct{}, 1)
	SetDeferredRustLifecycleObserver(func(conn gonet.Conn, event DeferredRustLifecycleEvent) {
		gotConn = conn
		gotEvent = event
		observed <- struct{}{}
	})

	dc, err := NewDeferredRustConn(client, &native.DeferredResult{Handle: &native.DeferredSessionHandle{}})
	if err != nil {
		t.Fatalf("NewDeferredRustConn() error = %v", err)
	}
	if dc == nil {
		t.Fatal("NewDeferredRustConn() returned nil conn")
	}

	select {
	case <-observed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DeferredRust lifecycle observer was not called")
	}

	if gotConn != dc {
		t.Fatalf("observer conn = %T %v, want %T %v", gotConn, gotConn, dc, dc)
	}
	if gotEvent != DeferredRustLifecycleDeferredActive {
		t.Fatalf("observer event = %q, want %q", gotEvent, DeferredRustLifecycleDeferredActive)
	}
}

func TestDeferredRustConnEnableKTLSOutcomeCallsLifecycleObserverForUnsupported(t *testing.T) {
	oldSupported := nativeFullKTLSSupportedFn
	oldObserver := snapshotDeferredRustLifecycleObserver()
	t.Cleanup(func() {
		nativeFullKTLSSupportedFn = oldSupported
		SetDeferredRustLifecycleObserver(oldObserver)
	})

	server, client := gonet.Pipe()
	defer server.Close()
	defer client.Close()

	nativeFullKTLSSupportedFn = func() bool { return false }

	var gotEvent DeferredRustLifecycleEvent
	observed := make(chan struct{}, 1)
	SetDeferredRustLifecycleObserver(func(_ gonet.Conn, event DeferredRustLifecycleEvent) {
		gotEvent = event
		observed <- struct{}{}
	})

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}

	out, err := dc.EnableKTLSOutcome()
	if err != nil {
		t.Fatalf("EnableKTLSOutcome() error = %v", err)
	}
	if out.Status != KTLSPromotionUnsupported {
		t.Fatalf("EnableKTLSOutcome().Status = %v, want %v", out.Status, KTLSPromotionUnsupported)
	}

	select {
	case <-observed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DeferredRust lifecycle observer was not called")
	}

	if gotEvent != DeferredRustLifecycleKTLSUnsupported {
		t.Fatalf("observer event = %q, want %q", gotEvent, DeferredRustLifecycleKTLSUnsupported)
	}
}

func TestDeferredRustConnReadCallsProgressObserver(t *testing.T) {
	oldRead := deferredReadFn
	oldObserver := snapshotDeferredRustProgressObserver()
	t.Cleanup(func() {
		deferredReadFn = oldRead
		SetDeferredRustProgressObserver(oldObserver)
	})

	server, client := gonet.Pipe()
	defer server.Close()
	defer client.Close()

	deferredReadFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		copy(b, []byte("abc"))
		return 3, nil
	}

	var got DeferredRustProgressEvent
	observed := make(chan struct{}, 1)
	SetDeferredRustProgressObserver(func(_ gonet.Conn, event DeferredRustProgressEvent) {
		got = event
		observed <- struct{}{}
	})

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}

	buf := make([]byte, 3)
	n, err := dc.Read(buf)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if n != 3 {
		t.Fatalf("Read() = %d, want 3", n)
	}

	select {
	case <-observed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DeferredRust progress observer was not called for read")
	}

	if got.Direction != DeferredRustProgressRead {
		t.Fatalf("observer direction = %q, want %q", got.Direction, DeferredRustProgressRead)
	}
	if got.Bytes != 3 {
		t.Fatalf("observer bytes = %d, want 3", got.Bytes)
	}
}

func TestDeferredRustConnWriteCallsProgressObserver(t *testing.T) {
	oldWrite := deferredWriteFn
	oldObserver := snapshotDeferredRustProgressObserver()
	t.Cleanup(func() {
		deferredWriteFn = oldWrite
		SetDeferredRustProgressObserver(oldObserver)
	})

	server, client := gonet.Pipe()
	defer server.Close()
	defer client.Close()

	deferredWriteFn = func(_ *native.DeferredSessionHandle, b []byte) (int, error) {
		return len(b), nil
	}

	var got DeferredRustProgressEvent
	observed := make(chan struct{}, 1)
	SetDeferredRustProgressObserver(func(_ gonet.Conn, event DeferredRustProgressEvent) {
		got = event
		observed <- struct{}{}
	})

	dc := &DeferredRustConn{
		rawConn: client,
		handle:  &native.DeferredSessionHandle{},
	}

	n, err := dc.Write([]byte("abcd"))
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if n != 4 {
		t.Fatalf("Write() = %d, want 4", n)
	}

	select {
	case <-observed:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("DeferredRust progress observer was not called for write")
	}

	if got.Direction != DeferredRustProgressWrite {
		t.Fatalf("observer direction = %q, want %q", got.Direction, DeferredRustProgressWrite)
	}
	if got.Bytes != 4 {
		t.Fatalf("observer bytes = %d, want 4", got.Bytes)
	}
}
