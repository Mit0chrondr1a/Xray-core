package mux

import (
	"context"
	stderrors "errors"
	"io"
	"syscall"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
)

func TestClassifyMuxParentDeath(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "EOF", err: io.EOF, want: "eof"},
		{name: "ClosedPipe", err: io.ErrClosedPipe, want: "closed_pipe"},
		{name: "SyscallEPIPE", err: syscall.EPIPE, want: "closed_pipe"},
		{name: "Reset", err: syscall.ECONNRESET, want: "connection_reset"},
		{name: "Other", err: stderrors.New("boom"), want: "other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := classifyMuxParentDeath(tt.err); got != tt.want {
				t.Fatalf("classifyMuxParentDeath() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMuxParentDeathDurationsClampClockSkew(t *testing.T) {
	createdAt := time.Unix(100, 0)
	lastActivity := createdAt.Add(10 * time.Second)

	idleSeconds, lifetimeSeconds := muxParentDeathDurations(createdAt.Add(5*time.Second), createdAt, lastActivity)
	if idleSeconds != 0 {
		t.Fatalf("idleSeconds = %d, want 0", idleSeconds)
	}
	if lifetimeSeconds != 5 {
		t.Fatalf("lifetimeSeconds = %d, want 5", lifetimeSeconds)
	}
}

func TestMuxFirstFrameLatencyNsClampsUnsetOrSkewedTimes(t *testing.T) {
	createdAt := time.Unix(100, 0)

	if got := muxFirstFrameLatencyNs(createdAt, time.Time{}); got != 0 {
		t.Fatalf("zero first frame latency = %d, want 0", got)
	}
	if got := muxFirstFrameLatencyNs(createdAt, createdAt.Add(-time.Second)); got != 0 {
		t.Fatalf("skewed first frame latency = %d, want 0", got)
	}

	want := int64(3 * time.Second)
	if got := muxFirstFrameLatencyNs(createdAt, createdAt.Add(3*time.Second)); got != want {
		t.Fatalf("first frame latency = %d, want %d", got, want)
	}
}

func TestServerWorkerParentLifecycle(t *testing.T) {
	createdAt := time.Unix(100, 0)
	worker := &ServerWorker{
		createdAt:       createdAt,
		lastActivity:    createdAt.Add(7 * time.Second),
		firstFrameAt:    createdAt.Add(2 * time.Second),
		frameCount:      11,
		sessionsCreated: 3,
	}

	lifecycle := worker.parentLifecycle(createdAt.Add(10 * time.Second))
	if lifecycle.idleSeconds != 3 {
		t.Fatalf("idleSeconds = %d, want 3", lifecycle.idleSeconds)
	}
	if lifecycle.lifetimeSeconds != 10 {
		t.Fatalf("lifetimeSeconds = %d, want 10", lifecycle.lifetimeSeconds)
	}
	if lifecycle.activeSeconds != 7 {
		t.Fatalf("activeSeconds = %d, want 7", lifecycle.activeSeconds)
	}
	if lifecycle.totalFrames != 11 {
		t.Fatalf("totalFrames = %d, want 11", lifecycle.totalFrames)
	}
	if lifecycle.totalSessionsCreated != 3 {
		t.Fatalf("totalSessionsCreated = %d, want 3", lifecycle.totalSessionsCreated)
	}
	wantFirstFrameNs := int64(2 * time.Second)
	if lifecycle.firstFrameLatencyNs != wantFirstFrameNs {
		t.Fatalf("firstFrameLatencyNs = %d, want %d", lifecycle.firstFrameLatencyNs, wantFirstFrameNs)
	}
}

func TestPacketSessionIdleCloseTimeout(t *testing.T) {
	tests := []struct {
		name string
		dest net.Destination
		want time.Duration
	}{
		{
			name: "GeneralUDPDoesNotUseIdleClose",
			dest: net.UDPDestination(net.LocalHostIP, net.Port(443)),
			want: 0,
		},
		{
			name: "NTPPort",
			dest: net.UDPDestination(net.LocalHostIP, net.Port(123)),
			want: packetControlIdleCloseTimeout,
		},
		{
			name: "DNSPort853DoesNotUseControlTimeout",
			dest: net.UDPDestination(net.LocalHostIP, net.Port(853)),
			want: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := packetSessionIdleCloseTimeout(tt.dest); got != tt.want {
				t.Fatalf("packetSessionIdleCloseTimeout() = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestCopyPacketWithIdleCloseStopsOnReadTimeout(t *testing.T) {
	reader := &timeoutOnlyReader{err: buf.ErrReadTimeout}
	s := &Session{
		ID:          7,
		input:       reader,
		target:      net.UDPDestination(net.LocalHostIP, net.Port(443)),
		idleTimeout: time.Second,
	}

	err := copyPacketWithIdleClose(context.Background(), s, NewResponseWriter(s.ID, buf.Discard, protocol.TransferTypePacket))
	if err != nil {
		t.Fatalf("copyPacketWithIdleClose() error = %v, want nil", err)
	}
	if reader.timeoutCalls != 1 {
		t.Fatalf("timeoutCalls = %d, want 1", reader.timeoutCalls)
	}
}

type timeoutOnlyReader struct {
	timeoutCalls int
	err          error
}

func (r *timeoutOnlyReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	return nil, r.err
}

func (r *timeoutOnlyReader) ReadMultiBufferTimeout(time.Duration) (buf.MultiBuffer, error) {
	r.timeoutCalls++
	return nil, r.err
}
