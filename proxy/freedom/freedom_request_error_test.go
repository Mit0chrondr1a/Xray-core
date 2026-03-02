package freedom

import (
	"context"
	goerrors "errors"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
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

func TestIsExpectedRequestReadErrorReadStreamCancel(t *testing.T) {
	err := buf.Copy(&errReader{err: goerrors.New("stream error: stream ID 5; CANCEL")}, buf.Discard)
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if !buf.IsReadError(err) {
		t.Fatalf("expected read error, got %T", err)
	}
	if !isExpectedRequestReadError(err) {
		t.Fatal("expected stream CANCEL read error to be treated as request-closure")
	}
}

func TestIsExpectedRequestReadErrorWriteStreamCancel(t *testing.T) {
	err := buf.Copy(&oneShotReader{}, &errWriter{err: goerrors.New("stream error: stream ID 5; CANCEL")})
	if err == nil {
		t.Fatal("expected non-nil error")
	}
	if buf.IsReadError(err) {
		t.Fatalf("expected write error, got read error: %T", err)
	}
	if isExpectedRequestReadError(err) {
		t.Fatal("write-side stream CANCEL must not be treated as request-closure")
	}
}

func TestClassifyEgressDialFailureTimeout(t *testing.T) {
	class, ok := classifyEgressDialFailure(goerrors.New("dial tcp 1.1.1.1:443: connect: connection timed out"))
	if !ok {
		t.Fatal("expected timeout failure to be classified")
	}
	if class != "timeout" {
		t.Fatalf("expected timeout class, got %q", class)
	}
}

func TestClassifyEgressDialFailureNoRoute(t *testing.T) {
	class, ok := classifyEgressDialFailure(goerrors.New("dial tcp 1.1.1.1:443: connect: no route to host"))
	if !ok {
		t.Fatal("expected no_route failure to be classified")
	}
	if class != "no_route" {
		t.Fatalf("expected no_route class, got %q", class)
	}
}

func TestClassifyEgressDialFailureRefused(t *testing.T) {
	class, ok := classifyEgressDialFailure(goerrors.New("dial tcp 1.1.1.1:443: connect: connection refused"))
	if !ok {
		t.Fatal("expected refused failure to be classified")
	}
	if class != "refused" {
		t.Fatalf("expected refused class, got %q", class)
	}
}

func TestClassifyEgressDialFailureContextCancelled(t *testing.T) {
	if class, ok := classifyEgressDialFailure(context.Canceled); ok {
		t.Fatalf("expected context cancel to be ignored, got %q", class)
	}
}

func TestEgressPenaltyStateBackoffAndReset(t *testing.T) {
	var state egressDialPenaltyState
	now := time.Now().UnixNano()

	if delay, armed, consecutive := state.noteFailure(now, "timeout"); delay != 0 || armed || consecutive != 1 {
		t.Fatalf("first failure should not arm cooldown: delay=%v armed=%v consecutive=%d", delay, armed, consecutive)
	}

	delay, armed, consecutive := state.noteFailure(now+int64(time.Millisecond), "timeout")
	if !armed {
		t.Fatal("second consecutive failure should arm cooldown")
	}
	if delay != 2*time.Second {
		t.Fatalf("expected 2s cooldown on second failure, got %v", delay)
	}
	if consecutive != 2 {
		t.Fatalf("expected consecutive=2, got %d", consecutive)
	}

	if remaining, blocked, class := state.shouldFastFail(now + int64(time.Second)); !blocked || remaining <= 0 {
		t.Fatalf("expected active cooldown; blocked=%v remaining=%v class=%q", blocked, remaining, class)
	} else if class != "timeout" {
		t.Fatalf("expected timeout block class, got %q", class)
	}

	delay, armed, consecutive = state.noteFailure(now+int64(3*time.Second), "refused")
	if !armed {
		t.Fatal("first refused failure should arm cooldown")
	}
	if delay != 1*time.Second {
		t.Fatalf("expected 1s cooldown on first refused failure, got %v", delay)
	}
	if consecutive != 1 {
		t.Fatalf("expected class switch to reset consecutive failures, got %d", consecutive)
	}

	resetAt := now + int64(egressPenaltyResetAfter) + int64(time.Second)
	if delay, armed, consecutive := state.noteFailure(resetAt, "timeout"); delay != 0 || armed || consecutive != 1 {
		t.Fatalf("failure after reset window should restart counters: delay=%v armed=%v consecutive=%d", delay, armed, consecutive)
	}
}

func TestClearEgressDialPenalty(t *testing.T) {
	dest := net.TCPDestination(net.ParseAddress("108.160.166.62"), 443)
	state := getEgressDialPenaltyState(dest)
	state.noteFailure(time.Now().UnixNano(), "timeout")

	if !clearEgressDialPenalty(dest) {
		t.Fatal("expected destination penalty state to be cleared")
	}
	if clearEgressDialPenalty(dest) {
		t.Fatal("expected second clear to report no state")
	}
}
