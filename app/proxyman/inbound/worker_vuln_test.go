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

type packetCaptureWriter struct {
	calls atomic.Int32
	bytes atomic.Int64
}

func (w *packetCaptureWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	w.calls.Add(1)
	w.bytes.Add(int64(mb.Len()))
	return nil
}

func (w *packetCaptureWriter) Close() error {
	return nil
}

func TestVuln_CWE_400_QueueTimeoutRetryBypass(t *testing.T) {
	t.Run("retry admits when slot frees near deadline", func(t *testing.T) {
		sem := make(chan struct{}, 1)
		sem <- struct{}{}

		go func() {
			time.Sleep(8 * time.Millisecond)
			<-sem
		}()

		if !simulateTimerWaitQueue(sem, 10*time.Millisecond) {
			t.Fatal("expected final retry path to admit when capacity becomes available")
		}
		<-sem
	})

	t.Run("rejects when capacity never frees", func(t *testing.T) {
		sem := make(chan struct{}, 1)
		sem <- struct{}{}

		if simulateTimerWaitQueue(sem, 5*time.Millisecond) {
			t.Fatal("unexpected admission when semaphore remained saturated")
		}
	})
}

func TestVuln_CWE_459_UDPConnLeakOnQueueTimeout(t *testing.T) {
	t.Setenv("XRAY_CONNECTION_QUEUE_TIMEOUT_MS", "1")

	w := &udpWorker{
		activeConn:       make(map[connID]*udpConn),
		sessionSemaphore: make(chan struct{}, 1),
		ctx:              context.Background(),
	}
	w.sessionSemaphore <- struct{}{}

	for i := 0; i < 16; i++ {
		payload := makeTestBuffer([]byte{byte(i)})
		src := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(30000+i))
		w.callback(payload, src, xnet.Destination{})
		if !payload.IsEmpty() {
			t.Fatalf("payload %d was not released on queue rejection", i)
		}
	}

	if len(w.activeConn) != 0 {
		t.Fatalf("expected no sessions to be created while queue is saturated, got=%d", len(w.activeConn))
	}
	if got := len(w.sessionSemaphore); got != 1 {
		t.Fatalf("session semaphore mismatch after rejection flood: len=%d want=1", got)
	}
}

func TestVuln_CWE_362_UDPConnCancelRace(t *testing.T) {
	t.Run("existing_sessions_continue_when_queue_for_new_sessions_is_full", func(t *testing.T) {
		source := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(12010))
		id := connID{src: source}
		writer := &packetCaptureWriter{}
		conn := &udpConn{
			lastActivityTime: time.Now().Unix(),
			writer:           writer,
			done:             done.New(),
		}
		w := &udpWorker{
			activeConn: map[connID]*udpConn{
				id: conn,
			},
			sessionSemaphore: make(chan struct{}, 1),
			ctx:              context.Background(),
		}
		w.sessionSemaphore <- struct{}{}

		w.callback(makeTestBuffer([]byte("existing-session")), source, xnet.Destination{})

		if got := writer.calls.Load(); got != 1 {
			t.Fatalf("existing session payload should be written once, got=%d", got)
		}
		if got := writer.bytes.Load(); got != int64(len("existing-session")) {
			t.Fatalf("unexpected payload size written for existing session: got=%d", got)
		}
		if got := len(w.sessionSemaphore); got != 1 {
			t.Fatalf("new-session queue token changed unexpectedly: len=%d", got)
		}
	})

	t.Run("clean_closes_expired_conn_even_when_cancel_is_nil", func(t *testing.T) {
		source := xnet.UDPDestination(xnet.LocalHostIP, xnet.Port(12011))
		id := connID{src: source}
		conn := &udpConn{
			lastActivityTime: time.Now().Add(-3 * time.Minute).Unix(),
			writer:           &packetCaptureWriter{},
			done:             done.New(),
			cancel:           nil,
		}
		w := &udpWorker{
			activeConn: map[connID]*udpConn{
				id: conn,
			},
		}

		if err := w.clean(); err != nil {
			t.Fatalf("clean() returned unexpected error: %v", err)
		}
		if !conn.done.Done() {
			t.Fatal("expired connection was not closed by clean()")
		}
		if len(w.activeConn) != 0 {
			t.Fatalf("expired connection was not removed from activeConn: len=%d", len(w.activeConn))
		}
	})
}
