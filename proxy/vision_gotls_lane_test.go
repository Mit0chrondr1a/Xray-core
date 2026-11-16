package proxy

import (
	"bytes"
	"context"
	gonet "net"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
)

// The read deadline of the native copy loop is a poll tick, not a liveness
// verdict. A response direction that stays quiet past the tick (keep-alive,
// long poll, push channel) must not be ended with a synthetic EOF: upstream has
// no idle ceiling here and leaves lifetime to the session's activity timer.
func TestCopyRawConnIfExistQuietResponseOutlivesIdleTick(t *testing.T) {
	readerPeer, readerConn := gonet.Pipe()
	defer readerPeer.Close()
	defer readerConn.Close()

	timerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := signal.CancelAfterInactivity(timerCtx, cancel, 30*time.Second)
	defer timer.SetTimeout(0)

	inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGateUnset)}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGateUnset),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{203, 0, 113, 5}), xnet.Port(443)),
	}
	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})

	var written bytes.Buffer
	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(ctx, readerConn, nil, buf.NewWriter(&written), timer, nil)
	}()

	// The first tick fires after 3s.
	select {
	case err := <-errCh:
		t.Fatalf("copy loop ended a quiet connection at its idle tick: err=%v", err)
	case <-time.After(3600 * time.Millisecond):
	}

	if _, err := readerPeer.Write([]byte("late-response")); err != nil {
		t.Fatalf("response source was closed underneath a quiet connection: %v", err)
	}
	_ = readerPeer.Close()

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil at response EOF", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("copy loop did not finish after response EOF")
	}
	if got := written.String(); got != "late-response" {
		t.Fatalf("written=%q, want the late response delivered", got)
	}
}
