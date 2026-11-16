package proxy

import (
	"bytes"
	"context"
	"crypto/rand"
	gotls "crypto/tls"
	"io"
	gonet "net"
	"runtime"
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

// stagedVisionSink stands in for the downlink Vision writer of a Go TLS/REALITY
// inbound: it forwards in userspace and, on a chosen write, performs what the
// real writer does at its direct-copy switch (flip the gate, then commit the
// physical destination after the write reached the socket).
type stagedVisionSink struct {
	conn     *gonet.TCPConn
	inbound  *session.Inbound
	proof    *session.VisionRawWriterProof
	commitAt int32

	calls atomic.Int32
	bytes atomic.Int64
}

func (s *stagedVisionSink) WriteMultiBuffer(mb buf.MultiBuffer) error {
	defer buf.ReleaseMulti(mb)
	n := s.calls.Add(1)
	s.bytes.Add(int64(mb.Len()))
	for _, b := range mb {
		if b == nil {
			continue
		}
		if _, err := s.conn.Write(b.Bytes()); err != nil {
			return err
		}
	}
	if s.commitAt > 0 && n == s.commitAt {
		s.inbound.SetCanSpliceCopy(session.CopyGateEligible)
		s.proof.Commit(s.conn)
	}
	return nil
}

// laneReadDeadlineSpy counts read-deadline changes. Wrapping also makes the source
// ineligible for splice, which is what the userspace-only tests want.
type laneReadDeadlineSpy struct {
	*gonet.TCPConn
	readDeadlines atomic.Int32
}

func (c *laneReadDeadlineSpy) SetReadDeadline(t time.Time) error {
	c.readDeadlines.Add(1)
	return c.TCPConn.SetReadDeadline(t)
}

func (c *laneReadDeadlineSpy) SetDeadline(t time.Time) error {
	c.readDeadlines.Add(1)
	return c.TCPConn.SetDeadline(t)
}

type goTLSLaneFixture struct {
	ctx      context.Context
	inbound  *session.Inbound
	proof    *session.VisionRawWriterProof
	timer    *signal.ActivityTimer
	target   *gonet.TCPConn // response source read by the copy loop
	upstream *gonet.TCPConn // test writes the response here
	client   *gonet.TCPConn // client-facing socket written by the copy loop
	peer     *gonet.TCPConn // test reads what the client would receive
}

func newGoTLSLaneFixture(t *testing.T, gate session.CopyGateState) *goTLSLaneFixture {
	t.Helper()
	target, upstream := mustTCPPair(t)
	client, peer := mustTCPPair(t)
	t.Cleanup(func() {
		_ = target.Close()
		_ = upstream.Close()
		_ = client.Close()
		_ = peer.Close()
	})

	inbound := &session.Inbound{Conn: client, CanSpliceCopy: int32(gate)}
	outbound := &session.Outbound{
		CanSpliceCopy: int32(session.CopyGateEligible),
		Target:        xnet.TCPDestination(xnet.IPAddress([]byte{203, 0, 113, 7}), xnet.Port(443)),
	}
	proof := &session.VisionRawWriterProof{}
	proof.RequireCommit()

	ctx := session.ContextWithInbound(context.Background(), inbound)
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
	ctx = session.ContextWithVisionRawWriterProof(ctx, proof)

	timerCtx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	timer := signal.CancelAfterInactivity(timerCtx, cancel, 30*time.Second)
	t.Cleanup(func() { timer.SetTimeout(0) })

	return &goTLSLaneFixture{
		ctx: ctx, inbound: inbound, proof: proof, timer: timer,
		target: target, upstream: upstream, client: client, peer: peer,
	}
}

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

func TestVisionGoTLSLanePredicate(t *testing.T) {
	tcp, tcpPeer := mustTCPPair(t)
	defer tcp.Close()
	defer tcpPeer.Close()

	withProof := session.ContextWithVisionRawWriterProof(context.Background(), &session.VisionRawWriterProof{})
	gated := func(state session.CopyGateState) *session.Inbound {
		return &session.Inbound{CanSpliceCopy: int32(state)}
	}

	cases := []struct {
		name    string
		ctx     context.Context
		inbound *session.Inbound
		conn    gonet.Conn
		want    bool
	}{
		{"go conn pending detach", withProof, gated(session.CopyGatePendingDetach), tcp, true},
		{"go conn already eligible", withProof, gated(session.CopyGateEligible), tcp, true},
		{"no vision proof (client, fallback, non-vision)", context.Background(), gated(session.CopyGatePendingDetach), tcp, false},
		{"forced userspace (mux parent, no-detach, security guard)", withProof, gated(session.CopyGateForcedUserspace), tcp, false},
		{"not applicable transport", withProof, gated(session.CopyGateNotApplicable), tcp, false},
		{"unset gate", withProof, gated(session.CopyGateUnset), tcp, false},
		{"deferred rustls conn keeps its own loop", withProof, gated(session.CopyGatePendingDetach), &tls.DeferredRustConn{}, false},
		{"nil inbound", withProof, nil, tcp, false},
		{"nil conn", withProof, gated(session.CopyGatePendingDetach), nil, false},
	}
	for _, tc := range cases {
		if got := visionGoTLSLane(tc.ctx, tc.inbound, tc.conn); got != tc.want {
			t.Errorf("%s: visionGoTLSLane()=%v, want %v", tc.name, got, tc.want)
		}
	}

	laneCases := []struct {
		name   string
		ctx    context.Context
		reader gonet.Conn
		writer gonet.Conn
		want   bool
	}{
		{"server: go inbound, raw target", withProof, tcpPeer, tcp, true},
		{"client: vision outbound reader behind go tls wrapper", withProof, tls.Client(tcpPeer, &gotls.Config{InsecureSkipVerify: true}), tcp, true},
		{"client: no local inbound conn", withProof, tcpPeer, nil, true},
		{"non-vision flow", context.Background(), tcpPeer, tcp, false},
		{"deferred rustls writer keeps the native loop", withProof, tcpPeer, &tls.DeferredRustConn{}, false},
		{"deferred rustls reader keeps the native loop", withProof, &tls.DeferredRustConn{}, tcp, false},
	}
	for _, tc := range laneCases {
		if got := visionUpstreamCopyLane(tc.ctx, tc.reader, tc.writer); got != tc.want {
			t.Errorf("%s: visionUpstreamCopyLane()=%v, want %v", tc.name, got, tc.want)
		}
	}

	inbound := gated(session.CopyGatePendingDetach)
	inbound.Conn = tcp
	if !IsVisionGoTLSLane(session.ContextWithInbound(withProof, inbound)) {
		t.Error("IsVisionGoTLSLane() should resolve the lane from the inbound in context")
	}
	if IsVisionGoTLSLane(withProof) {
		t.Error("IsVisionGoTLSLane() without inbound metadata must be false")
	}
}

// The response must go through the Vision writer until that writer has
// committed its raw switch, and only the remainder may bypass it via splice.
// Byte order across the handoff is the property that upstream's 1ms sleep
// protects; here the commit proof makes it deterministic.
func TestCopyRawConnIfExistVisionGoTLSLaneSplicesAfterWriterCommit(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "android" {
		t.Skip("splice is Linux-only")
	}
	f := newGoTLSLaneFixture(t, session.CopyGatePendingDetach)
	sink := &stagedVisionSink{conn: f.client, inbound: f.inbound, proof: f.proof, commitAt: 2}

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(f.ctx, f.target, f.client, sink, f.timer, nil)
	}()

	padded := []byte("vision-padded-server-hello")
	transition := []byte("vision-direct-transition-record")
	bulk := make([]byte, 1<<20)
	if _, err := rand.Read(bulk); err != nil {
		t.Fatal(err)
	}

	if _, err := f.upstream.Write(padded); err != nil {
		t.Fatal(err)
	}
	if got := mustReadFull(t, f.peer, len(padded)); !bytes.Equal(got, padded) {
		t.Fatalf("first chunk corrupted: %q", got)
	}
	if _, err := f.upstream.Write(transition); err != nil {
		t.Fatal(err)
	}
	if got := mustReadFull(t, f.peer, len(transition)); !bytes.Equal(got, transition) {
		t.Fatalf("transition chunk corrupted: %q", got)
	}

	deadline := time.Now().Add(5 * time.Second)
	for !f.proof.ReadyFor(f.client) {
		if time.Now().After(deadline) {
			t.Fatal("writer never committed its raw destination")
		}
		time.Sleep(time.Millisecond)
	}

	go func() {
		_, _ = f.upstream.Write(bulk)
		_ = f.upstream.Close()
	}()
	if got := mustReadFull(t, f.peer, len(bulk)); !bytes.Equal(got, bulk) {
		t.Fatal("bulk payload corrupted or reordered across the splice handoff")
	}

	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil at response EOF", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("copy loop did not finish after response EOF")
	}

	if got := sink.calls.Load(); got != 2 {
		t.Fatalf("Vision writer saw %d writes, want 2 (everything after the commit must splice)", got)
	}
	if got, want := sink.bytes.Load(), int64(len(padded)+len(transition)); got != want {
		t.Fatalf("Vision writer forwarded %d bytes, want %d", got, want)
	}
}

// An eligible gate alone is not enough: until the writer commits its physical
// destination the response keeps flowing through the writer. The lane must
// also leave the source socket's deadlines alone, because upstream has no idle
// ceiling in this loop and the native loop's 20-60s ceiling closes healthy
// keep-alive connections.
func TestCopyRawConnIfExistVisionGoTLSLaneStaysUserspaceWithoutCommit(t *testing.T) {
	f := newGoTLSLaneFixture(t, session.CopyGateEligible)
	sink := &stagedVisionSink{conn: f.client, inbound: f.inbound, proof: f.proof}
	source := &laneReadDeadlineSpy{TCPConn: f.target}

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(f.ctx, source, f.client, sink, f.timer, nil)
	}()

	payload := make([]byte, 256<<10)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	go func() {
		_, _ = f.upstream.Write(payload[:len(payload)/2])
		time.Sleep(150 * time.Millisecond) // an idle gap must not disturb the flow
		_, _ = f.upstream.Write(payload[len(payload)/2:])
		_ = f.upstream.Close()
	}()

	if got := mustReadFull(t, f.peer, len(payload)); !bytes.Equal(got, payload) {
		t.Fatal("userspace payload corrupted")
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil at response EOF", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("copy loop did not finish after response EOF")
	}

	if got, want := sink.bytes.Load(), int64(len(payload)); got != want {
		t.Fatalf("Vision writer forwarded %d bytes, want all %d", got, want)
	}
	if got := source.readDeadlines.Load(); got != 0 {
		t.Fatalf("lane set %d read deadlines on the response source, want none", got)
	}
}

// XRAY_DEBUG_DISABLE_ACCEL remains a kill switch for the restored splice.
func TestCopyRawConnIfExistVisionGoTLSLaneHonorsDisableAccel(t *testing.T) {
	t.Setenv("XRAY_DEBUG_DISABLE_ACCEL", "1")
	f := newGoTLSLaneFixture(t, session.CopyGateEligible)
	f.proof.Commit(f.client)
	sink := &stagedVisionSink{conn: f.client, inbound: f.inbound, proof: f.proof}

	errCh := make(chan error, 1)
	go func() {
		errCh <- CopyRawConnIfExist(f.ctx, f.target, f.client, sink, f.timer, nil)
	}()

	payload := []byte("accel-disabled-response")
	go func() {
		_, _ = f.upstream.Write(payload)
		_ = f.upstream.Close()
	}()
	if got := mustReadFull(t, f.peer, len(payload)); !bytes.Equal(got, payload) {
		t.Fatalf("payload corrupted: %q", got)
	}
	select {
	case err := <-errCh:
		if err != nil {
			t.Fatalf("CopyRawConnIfExist() error=%v, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("copy loop did not finish after response EOF")
	}
	if got, want := sink.bytes.Load(), int64(len(payload)); got != want {
		t.Fatalf("Vision writer forwarded %d bytes, want all %d with acceleration disabled", got, want)
	}
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
