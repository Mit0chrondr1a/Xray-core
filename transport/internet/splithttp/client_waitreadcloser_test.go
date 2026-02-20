package splithttp

import (
	"io"
	"sync/atomic"
	"testing"
	"time"
)

type countingReadCloser struct {
	closed atomic.Int32
}

func (c *countingReadCloser) Read([]byte) (int, error) {
	return 0, io.EOF
}

func (c *countingReadCloser) Close() error {
	c.closed.Add(1)
	return nil
}

func TestWaitReadCloserSetAfterCloseClosesBody(t *testing.T) {
	w := &WaitReadCloser{Wait: make(chan struct{})}
	if err := w.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	rc := &countingReadCloser{}
	w.Set(rc)

	if got := rc.closed.Load(); got != 1 {
		t.Fatalf("late body must be closed once, got %d", got)
	}
}

func TestWaitReadCloserReadReturnsClosedPipeWhenClosedBeforeSet(t *testing.T) {
	w := &WaitReadCloser{Wait: make(chan struct{})}
	errCh := make(chan error, 1)

	go func() {
		_, err := w.Read(make([]byte, 1))
		errCh <- err
	}()

	if err := w.Close(); err != nil {
		t.Fatalf("unexpected close error: %v", err)
	}

	select {
	case err := <-errCh:
		if err != io.ErrClosedPipe {
			t.Fatalf("unexpected read error: %v", err)
		}
	case <-time.After(200 * time.Millisecond):
		t.Fatal("Read did not unblock after Close")
	}
}

func TestWaitReadCloserCloseClosesUnderlyingOnlyOnce(t *testing.T) {
	w := &WaitReadCloser{Wait: make(chan struct{})}
	rc := &countingReadCloser{}
	w.Set(rc)

	if err := w.Close(); err != nil {
		t.Fatalf("unexpected first close error: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("unexpected second close error: %v", err)
	}

	if got := rc.closed.Load(); got != 1 {
		t.Fatalf("underlying body closed %d times, want 1", got)
	}
}
