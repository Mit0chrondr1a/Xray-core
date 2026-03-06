package splithttp

import (
	stderrors "errors"
	"io"
	"net"
	"os"
	"testing"
	"time"
)

// dummyAddr is a minimal net.Addr for tests.
type dummyAddr string

func (d dummyAddr) Network() string { return "tcp" }
func (d dummyAddr) String() string  { return string(d) }

func TestIsSplitConn(t *testing.T) {
	r, w := io.Pipe()
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	sc := &splitConn{
		reader:     r,
		writer:     w,
		localAddr:  dummyAddr("127.0.0.1:80"),
		remoteAddr: dummyAddr("127.0.0.1:12345"),
	}

	if !IsSplitConn(sc) {
		t.Fatalf("IsSplitConn(splitConn)=false, want true")
	}

	var nilConn net.Conn
	if IsSplitConn(nilConn) {
		t.Fatalf("IsSplitConn(nil)=true, want false")
	}
}

type deadlineRecorder struct {
	readDeadline  time.Time
	writeDeadline time.Time
}

func (d *deadlineRecorder) Read([]byte) (int, error)    { return 0, io.EOF }
func (d *deadlineRecorder) Write(b []byte) (int, error) { return len(b), nil }
func (d *deadlineRecorder) Close() error                { return nil }
func (d *deadlineRecorder) SetReadDeadline(t time.Time) error {
	d.readDeadline = t
	return nil
}
func (d *deadlineRecorder) SetWriteDeadline(t time.Time) error {
	d.writeDeadline = t
	return nil
}

func TestSplitConnSetDeadlineDelegatesToUnderlyingStreams(t *testing.T) {
	rec := &deadlineRecorder{}
	deadline := time.Now().Add(time.Second)
	sc := &splitConn{reader: rec, writer: rec}

	if err := sc.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline returned error: %v", err)
	}
	if !rec.readDeadline.Equal(deadline) {
		t.Fatalf("read deadline = %v, want %v", rec.readDeadline, deadline)
	}
	if !rec.writeDeadline.Equal(deadline) {
		t.Fatalf("write deadline = %v, want %v", rec.writeDeadline, deadline)
	}
}

func TestSplitConnSetDeadlineReportsUnsupported(t *testing.T) {
	r, w := io.Pipe()
	t.Cleanup(func() {
		_ = r.Close()
		_ = w.Close()
	})

	sc := &splitConn{reader: r, writer: w}
	err := sc.SetDeadline(time.Now().Add(time.Second))
	if !stderrors.Is(err, errSplitDeadlineUnsupported) {
		t.Fatalf("SetDeadline error = %v, want unsupported", err)
	}
}

func TestSplitDeadlineExceededUnwrapsToOSErr(t *testing.T) {
	if !stderrors.Is(errSplitDeadlineExceeded, os.ErrDeadlineExceeded) {
		t.Fatal("deadline error should unwrap to os.ErrDeadlineExceeded")
	}
}
