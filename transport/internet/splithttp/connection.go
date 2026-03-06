package splithttp

import (
	stderrors "errors"
	"io"
	"net"
	"os"
	"time"
)

type splitDeadlineError struct{}

func (splitDeadlineError) Error() string   { return os.ErrDeadlineExceeded.Error() }
func (splitDeadlineError) Timeout() bool   { return true }
func (splitDeadlineError) Temporary() bool { return true }
func (splitDeadlineError) Unwrap() error   { return os.ErrDeadlineExceeded }

var (
	errSplitDeadlineExceeded    error = splitDeadlineError{}
	errSplitDeadlineUnsupported       = stderrors.New("splithttp: deadline not supported by underlying stream")
)

type deadlineSetter interface {
	SetDeadline(time.Time) error
}

type readDeadlineSetter interface {
	SetReadDeadline(time.Time) error
}

type writeDeadlineSetter interface {
	SetWriteDeadline(time.Time) error
}

type splitConn struct {
	writer     io.WriteCloser
	reader     io.ReadCloser
	remoteAddr net.Addr
	localAddr  net.Addr
	onClose    func()
}

// IsSplitConn marks this conn as a split HTTP transport that cannot expose a raw TCP fd.
func (c *splitConn) IsSplitConn() bool { return true }

func (c *splitConn) Write(b []byte) (int, error) {
	return c.writer.Write(b)
}

func (c *splitConn) Read(b []byte) (int, error) {
	return c.reader.Read(b)
}

func (c *splitConn) Close() error {
	if c.onClose != nil {
		c.onClose()
	}

	err := c.writer.Close()
	err2 := c.reader.Close()
	if err != nil {
		return err
	}

	if err2 != nil {
		return err2
	}

	return nil
}

func (c *splitConn) LocalAddr() net.Addr {
	return c.localAddr
}

func (c *splitConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func (c *splitConn) SetDeadline(t time.Time) error {
	return stderrors.Join(
		setSplitReadDeadline(c.reader, t),
		setSplitWriteDeadline(c.writer, t),
	)
}

func (c *splitConn) SetReadDeadline(t time.Time) error {
	return setSplitReadDeadline(c.reader, t)
}

func (c *splitConn) SetWriteDeadline(t time.Time) error {
	return setSplitWriteDeadline(c.writer, t)
}

// IsSplitConn reports whether the provided connection is a split HTTP wrapper.
// This allows callers (and tests) to check applicability of splice/sockmap.
func IsSplitConn(conn net.Conn) bool {
	type marker interface{ IsSplitConn() bool }
	if conn == nil {
		return false
	}
	if m, ok := conn.(marker); ok {
		return m.IsSplitConn()
	}
	return false
}

func setSplitReadDeadline(target any, t time.Time) error {
	switch v := target.(type) {
	case readDeadlineSetter:
		return v.SetReadDeadline(t)
	case deadlineSetter:
		return v.SetDeadline(t)
	default:
		return errSplitDeadlineUnsupported
	}
}

func setSplitWriteDeadline(target any, t time.Time) error {
	switch v := target.(type) {
	case writeDeadlineSetter:
		return v.SetWriteDeadline(t)
	case deadlineSetter:
		return v.SetDeadline(t)
	default:
		return errSplitDeadlineUnsupported
	}
}
