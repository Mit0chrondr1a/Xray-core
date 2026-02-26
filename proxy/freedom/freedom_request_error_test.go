package freedom

import (
	"io"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

type errReader struct {
	err error
}

func (r *errReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, r.err
}

type oneShotReader struct {
	done bool
}

func (r *oneShotReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	if r.done {
		return nil, io.EOF
	}
	r.done = true
	return buf.MultiBuffer{buf.FromBytes([]byte("x"))}, nil
}

type errWriter struct {
	err error
}

func (w *errWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	buf.ReleaseMulti(mb)
	return w.err
}

func TestIsExpectedRequestReadErrorReadEIO(t *testing.T) {
	err := buf.Copy(&errReader{err: syscall.EIO}, buf.Discard)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !buf.IsReadError(err) {
		t.Fatalf("expected read error, got %T", err)
	}
	if !isExpectedRequestReadError(err) {
		t.Fatal("expected EIO read error to be treated as request-closure")
	}
}

func TestIsExpectedRequestReadErrorWriteEIO(t *testing.T) {
	err := buf.Copy(&oneShotReader{}, &errWriter{err: syscall.EIO})
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if buf.IsReadError(err) {
		t.Fatalf("expected write error, got read error: %T", err)
	}
	if isExpectedRequestReadError(err) {
		t.Fatal("write-side EIO must not be treated as request-closure")
	}
}
