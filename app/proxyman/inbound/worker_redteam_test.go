package inbound

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

type testClosableWriter struct {
	closed atomic.Bool
}

func (w *testClosableWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return nil
}

func (w *testClosableWriter) Close() error {
	w.closed.Store(true)
	return nil
}

func makeTestBuffer(payload []byte) *buf.Buffer {
	b := buf.New()
	copy(b.Extend(int32(len(payload))), payload)
	return b
}

func TestVuln_CWE_400_SlowPathMissingReturn(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{}

	go func() {
		time.Sleep(5 * time.Millisecond)
		<-sem
	}()

	if !simulateTimerWaitQueue(sem, 20*time.Millisecond) {
		t.Fatal("expected slow-path connection to be admitted after capacity frees")
	}

	<-sem
}

func TestVuln_CWE_362_UDPConnCancelVisibilityRace(t *testing.T) {
	id := connID{
		src: xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(12001)),
	}
	writer := &testClosableWriter{}
	conn := &udpConn{
		lastActivityTime: time.Now().Unix(),
		writer:           writer,
		done:             done.New(),
	}
	w := &udpWorker{
		activeConn: map[connID]*udpConn{
			id: conn,
		},
	}

	if err := w.clean(); err != nil {
		t.Fatalf("clean() returned unexpected error: %v", err)
	}
	if len(w.activeConn) != 1 {
		t.Fatalf("clean() removed an active UDP session unexpectedly: len=%d", len(w.activeConn))
	}
	if conn.done.Done() {
		t.Fatal("fresh connection was closed unexpectedly")
	}
	if writer.closed.Load() {
		t.Fatal("writer was closed for a fresh connection")
	}
}

func TestVuln_CWE_404_UDPPipeLeakOnRejection(t *testing.T) {
	t.Setenv("XRAY_CONNECTION_QUEUE_TIMEOUT_MS", "1")

	w := &udpWorker{
		activeConn:       make(map[connID]*udpConn),
		sessionSemaphore: make(chan struct{}, 1),
		ctx:              context.Background(),
	}
	w.sessionSemaphore <- struct{}{}

	b := makeTestBuffer([]byte("drop-me"))
	source := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(12002))
	w.callback(b, source, xnet.Destination{})

	if len(w.activeConn) != 0 {
		t.Fatalf("unexpected UDP session created on queue rejection: len=%d", len(w.activeConn))
	}
	if got := len(w.sessionSemaphore); got != 1 {
		t.Fatalf("session semaphore leaked on rejection: len=%d want=1", got)
	}
	if !b.IsEmpty() {
		t.Fatal("rejected packet buffer was not released")
	}
}

func TestVuln_CWE_400_TimerAccumulation(t *testing.T) {
	t.Setenv("XRAY_CONNECTION_QUEUE_TIMEOUT_MS", "2")

	w := &udpWorker{
		sessionSemaphore: make(chan struct{}, 1),
		ctx:              context.Background(),
	}
	w.sessionSemaphore <- struct{}{}
	source := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(12003))

	const attempts = 6
	start := time.Now()
	for i := 0; i < attempts; i++ {
		if w.acquireSessionSlot(source) {
			t.Fatal("acquireSessionSlot unexpectedly succeeded on a saturated semaphore")
		}
	}
	if got := len(w.sessionSemaphore); got != 1 {
		t.Fatalf("session semaphore accounting mismatch: len=%d want=1", got)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("rejections were slower than expected: elapsed=%v", elapsed)
	}
}

func TestVuln_CWE_754_QueueTimeoutMinimumBypass(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want time.Duration
	}{
		{name: "one_ms", raw: "1", want: 1 * time.Millisecond},
		{name: "small_custom", raw: "5", want: 5 * time.Millisecond},
		{name: "invalid_uses_default", raw: "invalid", want: defaultQueueTimeout},
		{name: "negative_uses_default", raw: "-1", want: defaultQueueTimeout},
		{name: "cap_applies", raw: "999999", want: maxQueueTimeout},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := parseQueueTimeoutMS(tc.raw); got != tc.want {
				t.Fatalf("parseQueueTimeoutMS(%q) = %v, want %v", tc.raw, got, tc.want)
			}
		})
	}
}
