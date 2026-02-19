package splithttp

import (
	"io"
	"net/http"
	"testing"

	"github.com/xtls/xray-core/common/signal/done"
)

// --- httpServerConn.Write: safe Flusher assertion (M6 fix validation) ---

// nonFlushingWriter implements http.ResponseWriter but NOT http.Flusher.
// Before the M6 fix, httpServerConn.Write would panic on this.
type nonFlushingWriter struct {
	written []byte
	header  http.Header
}

func (w *nonFlushingWriter) Header() http.Header {
	if w.header == nil {
		w.header = make(http.Header)
	}
	return w.header
}

func (w *nonFlushingWriter) Write(b []byte) (int, error) {
	w.written = append(w.written, b...)
	return len(b), nil
}

func (w *nonFlushingWriter) WriteHeader(int) {}

// flushTrackingWriter implements both http.ResponseWriter and http.Flusher.
type flushTrackingWriter struct {
	nonFlushingWriter
	flushed bool
}

func (w *flushTrackingWriter) Flush() {
	w.flushed = true
}

func TestHttpServerConn_Write_WithFlusher_Flushes(t *testing.T) {
	w := &flushTrackingWriter{}
	sc := &httpServerConn{
		Instance:       done.New(),
		Reader:         nil,
		ResponseWriter: w,
	}

	n, err := sc.Write([]byte("hello"))
	if err != nil {
		t.Fatal("write error:", err)
	}
	if n != 5 {
		t.Fatalf("expected n=5, got %d", n)
	}
	if !w.flushed {
		t.Fatal("expected Flush() to be called")
	}
	if string(w.written) != "hello" {
		t.Fatalf("expected written 'hello', got %q", string(w.written))
	}
}

func TestHttpServerConn_Write_WithoutFlusher_NoPanic(t *testing.T) {
	w := &nonFlushingWriter{}
	sc := &httpServerConn{
		Instance:       done.New(),
		Reader:         nil,
		ResponseWriter: w,
	}

	// Before M6 fix, this would panic with type assertion failure
	n, err := sc.Write([]byte("safe"))
	if err != nil {
		t.Fatal("write error:", err)
	}
	if n != 4 {
		t.Fatalf("expected n=4, got %d", n)
	}
	if string(w.written) != "safe" {
		t.Fatalf("expected written 'safe', got %q", string(w.written))
	}
}

func TestHttpServerConn_Write_AfterClose_ReturnsClosedPipe(t *testing.T) {
	w := &nonFlushingWriter{}
	sc := &httpServerConn{
		Instance:       done.New(),
		Reader:         nil,
		ResponseWriter: w,
	}
	sc.Close()

	_, err := sc.Write([]byte("should fail"))
	if err != io.ErrClosedPipe {
		t.Fatalf("expected io.ErrClosedPipe, got %v", err)
	}
}

func TestHttpServerConn_DoubleClose_NoPanic(t *testing.T) {
	w := &nonFlushingWriter{}
	sc := &httpServerConn{
		Instance:       done.New(),
		Reader:         nil,
		ResponseWriter: w,
	}
	sc.Close()
	// Second close should not panic
	sc.Close()
}

func TestRequestHandler_ReleaseSession_DecrementsOnlyOnce(t *testing.T) {
	h := &requestHandler{}
	sessionID := "session-1"
	session := &httpSession{
		uploadQueue:      NewUploadQueue(1),
		isFullyConnected: done.New(),
	}
	h.sessions.Store(sessionID, session)
	h.sessionCount.Store(1)

	h.releaseSession(sessionID, session)
	h.releaseSession(sessionID, session)

	if got := h.sessionCount.Load(); got != 0 {
		t.Fatalf("expected sessionCount to be 0, got %d", got)
	}
	if _, ok := h.sessions.Load(sessionID); ok {
		t.Fatal("expected session to be removed from sessions map")
	}
	if err := session.uploadQueue.Push(Packet{Payload: []byte("x"), Seq: 0}); err == nil {
		t.Fatal("expected upload queue to be closed")
	}
}

func TestRequestHandler_ReleaseSession_StaleCleanupDoesNotDeleteNewSession(t *testing.T) {
	h := &requestHandler{}
	sessionID := "session-1"
	stale := &httpSession{
		uploadQueue:      NewUploadQueue(1),
		isFullyConnected: done.New(),
	}
	current := &httpSession{
		uploadQueue:      NewUploadQueue(1),
		isFullyConnected: done.New(),
	}

	h.sessions.Store(sessionID, current)
	h.sessionCount.Store(2) // stale + current

	h.releaseSession(sessionID, stale)

	loaded, ok := h.sessions.Load(sessionID)
	if !ok {
		t.Fatal("expected current session to remain in sessions map")
	}
	if loaded.(*httpSession) != current {
		t.Fatal("expected stale cleanup to keep current session")
	}
	if got := h.sessionCount.Load(); got != 1 {
		t.Fatalf("expected sessionCount to decrement to 1, got %d", got)
	}
}
