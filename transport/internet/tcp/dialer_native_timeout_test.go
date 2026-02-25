package tcp

import (
	"context"
	"errors"
	"io"
	gonet "net"
	"sync"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	xtls "github.com/xtls/xray-core/transport/internet/tls"
)

type recordingConn struct {
	mu        sync.Mutex
	deadlines []time.Time
}

func (c *recordingConn) Read(_ []byte) (int, error)  { return 0, io.EOF }
func (c *recordingConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *recordingConn) Close() error                { return nil }
func (c *recordingConn) LocalAddr() gonet.Addr       { return &gonet.TCPAddr{} }
func (c *recordingConn) RemoteAddr() gonet.Addr      { return &gonet.TCPAddr{} }
func (c *recordingConn) SetReadDeadline(t time.Time) error {
	return c.SetDeadline(t)
}
func (c *recordingConn) SetWriteDeadline(t time.Time) error {
	return c.SetDeadline(t)
}
func (c *recordingConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.deadlines = append(c.deadlines, t)
	return nil
}
func (c *recordingConn) snapshotDeadlines() []time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]time.Time, len(c.deadlines))
	copy(out, c.deadlines)
	return out
}

func TestRustClientWithContext_CancelSetsAndClearsDeadline(t *testing.T) {
	saved := rustClientWithTimeoutFn
	defer func() { rustClientWithTimeoutFn = saved }()

	conn := &recordingConn{}
	entered := make(chan struct{})
	unblock := make(chan struct{})

	rustClientWithTimeoutFn = func(gonet.Conn, *xtls.Config, xnet.Destination, time.Duration) (gonet.Conn, error) {
		close(entered)
		<-unblock
		return nil, errors.New("injected failure")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		_, err := rustClientWithContext(ctx, conn, nil, xnet.Destination{})
		done <- err
	}()

	<-entered
	cancel()
	time.Sleep(10 * time.Millisecond)
	close(unblock)

	if err := <-done; err == nil {
		t.Fatal("expected rustClientWithContext to return injected failure")
	}

	deadlines := conn.snapshotDeadlines()
	if len(deadlines) == 0 {
		t.Fatal("expected SetDeadline calls")
	}

	last := deadlines[len(deadlines)-1]
	if !last.IsZero() {
		t.Fatalf("expected final deadline clear, got %v", last)
	}

	hasNonZero := false
	for _, d := range deadlines {
		if !d.IsZero() {
			hasNonZero = true
			break
		}
	}
	if !hasNonZero {
		t.Fatal("expected at least one non-zero deadline from cancellation watcher")
	}
}
