package proxy

import (
	"bytes"
	"context"
	gotls "crypto/tls"
	"io"
	gonet "net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func mustReadFull(t *testing.T, conn gonet.Conn, n int) []byte {
	t.Helper()
	got := make([]byte, n)
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("ReadFull(%d) failed: %v", n, err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	return got
}

type laneTestCounter struct{ v atomic.Int64 }

func (c *laneTestCounter) Value() int64      { return c.v.Load() }
func (c *laneTestCounter) Set(n int64) int64 { return c.v.Swap(n) }
func (c *laneTestCounter) Add(n int64) int64 { return c.v.Add(n) - n }

// XtlsRead hands a Vision connection to CopyRawConnIfExist only after its
// reader switched to direct copy; from then on the peer sends raw bytes. The
// copy loop must read below the Go TLS wrapper on every path, as upstream does.
// Reading through the wrapper parses raw bytes as outer TLS records ("bad
// record MAC") and broke Vision clients and relays for any real TLS payload.
func TestCopyRawConnIfExistReadsBelowGoTLSWrapperAfterVisionSwitch(t *testing.T) {
	cases := []struct {
		name        string
		vision      bool
		inboundGate session.CopyGateState
	}{
		{"vision client leg uses the upstream lane", true, session.CopyGateEligible},
		{"forced-userspace inbound uses the early readv exit", true, session.CopyGateForcedUserspace},
		{"unset inbound gate", true, session.CopyGateUnset},
		{"no vision metadata falls back to the generic loop", false, session.CopyGateForcedUserspace},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server, serverPeer := mustTCPPair(t)
			local, localPeer := mustTCPPair(t)
			defer server.Close()
			defer serverPeer.Close()
			defer local.Close()
			defer localPeer.Close()

			// A Go TLS wrapper whose handshake never ran: any read through it
			// would start a handshake instead of returning the raw bytes.
			readCounter := &laneTestCounter{}
			wrapped := &stat.CounterConnection{
				Connection:  tls.Client(server, &gotls.Config{InsecureSkipVerify: true}),
				ReadCounter: readCounter,
			}

			inbound := &session.Inbound{Conn: local, CanSpliceCopy: int32(tc.inboundGate)}
			outbound := &session.Outbound{
				CanSpliceCopy: int32(session.CopyGateEligible),
				Target:        xnet.TCPDestination(xnet.IPAddress([]byte{203, 0, 113, 9}), xnet.Port(443)),
			}
			ctx := session.ContextWithInbound(context.Background(), inbound)
			ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
			if tc.vision {
				ctx = session.ContextWithVisionRawWriterProof(ctx, &session.VisionRawWriterProof{})
				ctx = session.ContextWithVisionSignal(ctx, make(chan session.VisionSignal, 1))
			}
			timerCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			timer := signal.CancelAfterInactivity(timerCtx, cancel, 30*time.Second)
			defer timer.SetTimeout(0)

			errCh := make(chan error, 1)
			go func() {
				errCh <- CopyRawConnIfExist(ctx, wrapped, local, buf.NewWriter(local), timer, nil)
			}()

			// Looks like an inner TLS application-data record, as Vision
			// direct copy would deliver it.
			raw := append([]byte{0x17, 0x03, 0x03, 0x00, 0x20}, bytes.Repeat([]byte{0xA5}, 32)...)
			go func() {
				_, _ = serverPeer.Write(raw)
				_ = serverPeer.Close()
			}()

			if got := mustReadFull(t, localPeer, len(raw)); !bytes.Equal(got, raw) {
				t.Fatalf("raw bytes altered: %x", got)
			}
			select {
			case err := <-errCh:
				if err != nil {
					t.Fatalf("CopyRawConnIfExist() error=%v, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("copy loop did not finish after EOF")
			}
			if got := readCounter.Value(); got != int64(len(raw)) {
				t.Fatalf("read counter=%d, want %d (stats must survive peeling the wrapper)", got, len(raw))
			}
		})
	}
}

// A deferred rustls connection that still terminates TLS must keep its
// wrapper; only Go TLS-style wrappers are peeled.
func TestRawCopyReaderKeepsLiveDeferredWrapper(t *testing.T) {
	dc := &tls.DeferredRustConn{}
	if rawConn, _, _, _ := UnwrapRawConn(dc); rawConn != gonet.Conn(dc) {
		t.Fatal("UnwrapRawConn must refuse to peel a live deferred rustls conn")
	}
	if _, counted := rawCopyReader(dc).(*countedReader); counted {
		t.Fatal("an unpeeled conn needs no synthetic counter")
	}
}

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
