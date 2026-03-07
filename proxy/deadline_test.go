package proxy

import (
	goerrors "errors"
	"net"
	"testing"
	"time"

	"github.com/xtls/xray-core/transport/internet/splithttp"
)

type deadlineTestConn struct {
	testEOFConn
	setReadDeadlineErr error
	lastReadDeadline   time.Time
}

func (c *deadlineTestConn) SetReadDeadline(t time.Time) error {
	c.lastReadDeadline = t
	return c.setReadDeadlineErr
}

func TestSetHandshakeReadDeadlineIgnoresSplitDeadlineUnsupported(t *testing.T) {
	conn := &deadlineTestConn{setReadDeadlineErr: splithttp.ErrDeadlineUnsupported()}
	deadline := time.Now().Add(5 * time.Second)
	if err := SetHandshakeReadDeadline(conn, deadline); err != nil {
		t.Fatalf("SetHandshakeReadDeadline() error = %v, want nil", err)
	}
	if !conn.lastReadDeadline.Equal(deadline) {
		t.Fatalf("deadline = %v, want %v", conn.lastReadDeadline, deadline)
	}
}

func TestSetHandshakeReadDeadlinePropagatesOtherErrors(t *testing.T) {
	wantErr := goerrors.New("boom")
	conn := &deadlineTestConn{setReadDeadlineErr: wantErr}
	if err := SetHandshakeReadDeadline(conn, time.Now()); !goerrors.Is(err, wantErr) {
		t.Fatalf("SetHandshakeReadDeadline() error = %v, want %v", err, wantErr)
	}
}

func TestClearHandshakeReadDeadlineUsesZeroTime(t *testing.T) {
	conn := &deadlineTestConn{}
	if err := ClearHandshakeReadDeadline(conn); err != nil {
		t.Fatalf("ClearHandshakeReadDeadline() error = %v", err)
	}
	if !conn.lastReadDeadline.IsZero() {
		t.Fatalf("deadline = %v, want zero", conn.lastReadDeadline)
	}
}

var _ net.Conn = (*deadlineTestConn)(nil)
