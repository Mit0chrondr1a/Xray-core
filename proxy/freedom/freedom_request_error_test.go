package freedom

import (
	"context"
	goerrors "errors"
	"io"
	"syscall"
	"testing"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
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

func TestShouldBypassEgressFastFail(t *testing.T) {
	tests := []struct {
		name   string
		ctx    context.Context
		dest   net.Destination
		expect bool
	}{
		{
			name:   "dns_control_always_single_shot",
			ctx:    context.Background(),
			dest:   net.TCPDestination(net.IPAddress([]byte{1, 1, 1, 1}), net.Port(53)),
			expect: true,
		},
		{
			name:   "vision_literal_ip_tcp_single_shot",
			ctx:    session.ContextWithVisionFlow(context.Background(), true),
			dest:   net.TCPDestination(net.IPAddress([]byte{173, 252, 108, 21}), net.Port(5222)),
			expect: true,
		},
		{
			name:   "vision_domain_tcp_keeps_retry_path",
			ctx:    session.ContextWithVisionFlow(context.Background(), true),
			dest:   net.TCPDestination(net.DomainAddress("i.instagram.com"), net.Port(443)),
			expect: false,
		},
		{
			name:   "non_vision_literal_ip_tcp_keeps_retry_path",
			ctx:    context.Background(),
			dest:   net.TCPDestination(net.IPAddress([]byte{173, 252, 108, 21}), net.Port(5222)),
			expect: false,
		},
		{
			name:   "vision_literal_ip_udp_keeps_retry_path",
			ctx:    session.ContextWithVisionFlow(context.Background(), true),
			dest:   net.UDPDestination(net.IPAddress([]byte{173, 252, 108, 21}), net.Port(5222)),
			expect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := shouldBypassEgressFastFail(tt.ctx, tt.dest); got != tt.expect {
				t.Fatalf("shouldBypassEgressFastFail() = %v, want %v", got, tt.expect)
			}
		})
	}
}
