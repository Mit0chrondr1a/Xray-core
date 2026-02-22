package tcp

import (
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	goreality "github.com/xtls/reality"
	"github.com/xtls/xray-core/common/native"
	"github.com/xtls/xray-core/transport/internet/ebpf"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"
	"github.com/xtls/xray-core/transport/internet/stat"
)

type testWrappedConn struct {
	net.Conn
	closeCount atomic.Int32
	closedCh   chan struct{}
}

func newTestWrappedConn(conn net.Conn) *testWrappedConn {
	return &testWrappedConn{
		Conn:     conn,
		closedCh: make(chan struct{}),
	}
}

func (c *testWrappedConn) Close() error {
	if c.closeCount.Add(1) == 1 {
		close(c.closedCh)
	}
	return c.Conn.Close()
}

type testWrappingAuthenticator struct {
	wrapped chan *testWrappedConn
}

func (a *testWrappingAuthenticator) Client(conn net.Conn) net.Conn {
	return conn
}

func (a *testWrappingAuthenticator) Server(conn net.Conn) net.Conn {
	w := newTestWrappedConn(conn)
	select {
	case a.wrapped <- w:
	default:
	}
	return w
}

func TestVuln_CWE_362_PanicHandlerClosesSharedConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	auth := &testWrappingAuthenticator{wrapped: make(chan *testWrappedConn, 1)}
	panicHit := make(chan struct{}, 1)
	v := &Listener{
		listener:      ln,
		connSemaphore: make(chan struct{}, 1),
		authConfig:    auth,
		addConn: func(stat.Connection) {
			select {
			case panicHit <- struct{}{}:
			default:
			}
			panic("test panic")
		},
	}
	go v.keepAccepting()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var wrapped *testWrappedConn
	select {
	case wrapped = <-auth.wrapped:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for wrapped connection")
	}

	select {
	case <-panicHit:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for addConn panic path")
	}

	select {
	case <-wrapped.closedCh:
	case <-time.After(time.Second):
		t.Fatal("wrapped connection was not closed by panic handler")
	}
}

func TestVuln_CWE_404_TLSWrapperLeakOnHandshakePanic(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	auth := &testWrappingAuthenticator{wrapped: make(chan *testWrappedConn, 1)}
	v := &Listener{
		listener:      ln,
		connSemaphore: make(chan struct{}, 1),
		authConfig:    auth,
		addConn: func(stat.Connection) {
			panic("panic after wrapper assignment")
		},
	}
	go v.keepAccepting()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	var wrapped *testWrappedConn
	select {
	case wrapped = <-auth.wrapped:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for wrapped connection")
	}

	select {
	case <-wrapped.closedCh:
	case <-time.After(time.Second):
		t.Fatal("wrapped connection was not closed on panic")
	}

	if got := wrapped.closeCount.Load(); got != 1 {
		t.Fatalf("wrapped connection close count = %d, want 1", got)
	}
}

func TestVuln_CWE_400_HandshakeSemaphoreExhaustion(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	added := make(chan struct{}, 2)
	block := make(chan struct{})
	defer close(block)
	v := &Listener{
		listener:      ln,
		connSemaphore: make(chan struct{}, 1),
		addConn: func(stat.Connection) {
			select {
			case added <- struct{}{}:
			default:
			}
			<-block
		},
	}
	go v.keepAccepting()

	client1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client1.Close()

	select {
	case <-added:
	case <-time.After(time.Second):
		t.Fatal("first connection did not reach addConn")
	}

	client2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()

	select {
	case <-added:
	case <-time.After(time.Second):
		t.Fatal("second connection did not reach addConn; handshake slot was not released early")
	}
}

func TestVuln_CWE_362_FdReuseAfterClose(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot create listener:", err)
	}
	defer ln.Close()

	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skip("cannot dial:", err)
	}

	sconn1, err := ln.Accept()
	if err != nil {
		t.Skip("cannot accept:", err)
	}

	tcpConn1, ok := sconn1.(*net.TCPConn)
	if !ok {
		t.Skip("not a TCP connection")
	}
	rawConn1, err := tcpConn1.SyscallConn()
	if err != nil {
		t.Skip("cannot get syscall conn:", err)
	}

	var fd1 uintptr
	rawConn1.Control(func(fd uintptr) {
		fd1 = fd
	})

	conn1.Close()
	sconn1.Close()

	conn2, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skip("cannot dial second:", err)
	}
	defer conn2.Close()

	sconn2, err := ln.Accept()
	if err != nil {
		t.Skip("cannot accept second:", err)
	}
	defer sconn2.Close()

	tcpConn2, ok := sconn2.(*net.TCPConn)
	if !ok {
		t.Skip("not a TCP connection")
	}
	rawConn2, err := tcpConn2.SyscallConn()
	if err != nil {
		t.Skip("cannot get syscall conn:", err)
	}

	var fd2 uintptr
	rawConn2.Control(func(fd uintptr) {
		fd2 = fd
	})

	if fd1 == 0 || fd2 == 0 {
		t.Fatalf("invalid file descriptors: fd1=%d fd2=%d", fd1, fd2)
	}
}

func TestVuln_CWE_252_RealityAuthFallbackSocketState(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	oldGetRealityBlacklistFn := getRealityBlacklistFn
	oldRealityServerFn := realityServerFn
	oldDoRustRealityServerFn := doRustRealityServerFn
	oldUseNativeRealityServerFn := useNativeRealityServerFn
	defer func() {
		_ = ln.Close()
		getRealityBlacklistFn = oldGetRealityBlacklistFn
		realityServerFn = oldRealityServerFn
		doRustRealityServerFn = oldDoRustRealityServerFn
		useNativeRealityServerFn = oldUseNativeRealityServerFn
	}()

	cfg := ebpf.DefaultBlacklistConfig()
	cfg.FailThreshold = 2
	cfg.FailWindow = time.Minute
	cfg.BanDuration = time.Minute
	cfg.CleanupInterval = time.Hour
	blacklist := ebpf.NewBlacklistManager(cfg)

	getRealityBlacklistFn = func() *ebpf.BlacklistManager { return blacklist }
	useNativeRealityServerFn = func(*Listener) bool { return true }

	var fallbackCalls atomic.Int32
	var addConnCalls atomic.Int32
	doRustRealityServerFn = func(*Listener, int) (*native.TlsResult, error) {
		return nil, fmt.Errorf("wrapped rust auth failure: %w", native.ErrRealityAuthFailed)
	}
	realityServerFn = func(net.Conn, *goreality.Config) (net.Conn, error) {
		fallbackCalls.Add(1)
		return nil, fmt.Errorf("go REALITY auth failed")
	}

	v := &Listener{
		listener:          ln,
		connSemaphore:     make(chan struct{}, 1),
		realityConfig:     &goreality.Config{},
		realityXrayConfig: &xrayreality.Config{},
		addConn: func(stat.Connection) {
			addConnCalls.Add(1)
		},
	}
	go v.keepAccepting()

	dialAndWaitFallback := func(want int32) {
		client, dialErr := net.Dial("tcp", ln.Addr().String())
		if dialErr != nil {
			t.Fatal(dialErr)
		}
		defer client.Close()

		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			if fallbackCalls.Load() >= want {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatalf("timed out waiting for REALITY fallback call #%d (got %d)", want, fallbackCalls.Load())
	}

	ip := net.ParseIP("127.0.0.1")

	// Probe #1: Rust auth fails and falls back to Go REALITY once.
	dialAndWaitFallback(1)
	if blacklist.IsBanned(ip) {
		t.Fatal("IP banned after one failed probe; expected a single blacklist record per probe")
	}

	// Probe #2: should accumulate one more failure and hit threshold=2.
	dialAndWaitFallback(2)
	if !blacklist.IsBanned(ip) {
		t.Fatal("IP not banned after two failed probes; expected one blacklist record per probe")
	}

	if got := addConnCalls.Load(); got != 0 {
		t.Fatalf("addConn called unexpectedly on failed handshakes: %d", got)
	}
}
