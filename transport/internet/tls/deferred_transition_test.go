package tls

import (
	"net"
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

	server, client := net.Pipe()
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
