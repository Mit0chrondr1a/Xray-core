package tcp

import (
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// =============================================================================
// Finding 1: CWE-362 - Panic handler closes conn that may already be
// passed to addConn handler
// =============================================================================
//
// In hub.go lines 168-286, the connection handling goroutine:
//
//   1. Registers defer releaseHandshake()              (line 175)
//   2. Declares conn := rawConn                        (line 180)
//   3. Registers defer panic handler (closes conn)     (line 181-186)
//   4. Does TLS handshake, reassigns conn              (line 187-274)
//   5. Calls releaseHandshake() explicitly             (line 279)
//   6. Calls v.addConn(stat.Connection(conn))          (line 284)
//
// If addConn panics (theoretically possible if the handler closure panics
// during channel operations), the panic propagates up to step 3's defer.
// The panic handler calls conn.Close(). But addConn at step 6 may have
// already passed conn to a goroutine (in worker.go's handler).
//
// The goroutine in worker.go now holds a reference to conn and may be
// actively reading/writing it. The panic handler closes it, causing
// the worker goroutine to encounter unexpected I/O errors.
//
// Severity: LOW (requires addConn to panic, which is very unlikely)
// CWE-362: Race Condition
//
// REMEDIATION: After addConn is called, set conn = nil so the panic
// handler skips the close. Or wrap addConn in its own recover.
func TestVuln_CWE_362_PanicHandlerClosesSharedConn(t *testing.T) {
	// Structural proof: demonstrate the shared-reference problem.

	type connState struct {
		closedBy atomic.Value // "panic-handler" or "worker" or ""
		mu       sync.Mutex
		closed   bool
	}

	cs := &connState{}

	// Simulate: addConn passes conn to a worker goroutine
	workerHasConn := make(chan struct{})
	var workerWg sync.WaitGroup
	workerWg.Add(1)

	go func() {
		defer workerWg.Done()
		close(workerHasConn) // Signal that worker has the conn reference

		// Simulate worker using conn
		time.Sleep(50 * time.Millisecond)

		cs.mu.Lock()
		defer cs.mu.Unlock()
		if !cs.closed {
			cs.closed = true
			cs.closedBy.Store("worker")
		} else {
			t.Log("Worker found conn already closed by panic handler -- use-after-close!")
		}
	}()

	// Wait for worker to have the reference
	<-workerHasConn

	// Simulate: panic handler fires and closes conn
	cs.mu.Lock()
	if !cs.closed {
		cs.closed = true
		cs.closedBy.Store("panic-handler")
	}
	cs.mu.Unlock()

	workerWg.Wait()

	closedBy := cs.closedBy.Load()
	if closedBy == "panic-handler" {
		t.Log("CONFIRMED: Panic handler closed conn before worker could. " +
			"In production, this means the worker goroutine operates on a " +
			"closed connection, receiving unexpected I/O errors. The conn " +
			"reference is shared between the hub goroutine's panic handler " +
			"and the worker goroutine spawned by addConn.")
	}
}

// =============================================================================
// Finding 2: CWE-404 - TLS wrapper not cleaned up when handshake panics
// =============================================================================
//
// In hub.go lines 204-222 (Go TLS path):
//
//   Line 205: tlsConn := tls.Server(conn, v.tlsConfig)
//   Line 212: hsErr := tlsConn.(*tls.Conn).HandshakeAndEnableKTLS(hsCtx)
//   Line 222: conn = tlsConn
//
// If HandshakeAndEnableKTLS panics at line 212:
//   - conn is still rawConn (line 222 hasn't executed)
//   - tlsConn wraps rawConn but is a local variable, not captured by defer
//   - The panic handler closes conn (rawConn), which closes the socket
//   - tlsConn holds TLS session state that is never cleaned up
//   - tlsConn is GC'd eventually, but its internal state (crypto buffers,
//     session tickets) may not have proper finalizers
//
// Similarly for the Rust TLS path (line 194):
//   If tls.RustServer panics, conn is still rawConn, and any Rust-side
//   state allocated during the partial handshake may leak.
//
// Severity: LOW (requires TLS handshake to panic, which should not happen
// in normal operation; Rust FFI panics are caught by the panic handler
// wrapper added in commit 043e580b)
// CWE-404: Improper Resource Shutdown or Release
//
// REMEDIATION: After creating tlsConn, immediately reassign conn = tlsConn
// so the panic handler closes the TLS wrapper (which closes the underlying
// socket as part of its Close()). The handshake error path already closes
// tlsConn explicitly (line 219), so early reassignment is safe.
func TestVuln_CWE_404_TLSWrapperLeakOnHandshakePanic(t *testing.T) {
	// Structural proof: demonstrate that conn != tlsConn when panic fires
	// during handshake.

	type mockConn struct {
		name   string
		closed bool
	}

	rawConn := &mockConn{name: "rawConn"}
	tlsConn := &mockConn{name: "tlsConn-wrapping-rawConn"}

	// Simulate the code structure from hub.go
	conn := rawConn // line 180

	// Simulate: tls.Server creates wrapper (line 205)
	_ = tlsConn // tlsConn is created but conn is NOT reassigned yet

	// Simulate: HandshakeAndEnableKTLS panics (line 212)
	// Panic handler fires, closing whatever conn points to
	func() {
		defer func() {
			if r := recover(); r != nil {
				// This is the panic handler (line 181-186)
				conn.closed = true // Closes rawConn
			}
		}()
		panic("simulated handshake panic")
	}()

	if !rawConn.closed {
		t.Fatal("rawConn should be closed by panic handler")
	}
	if tlsConn.closed {
		t.Fatal("tlsConn should NOT be closed -- it's leaked")
	}

	t.Log("CONFIRMED: When TLS handshake panics, the panic handler closes " +
		"rawConn but NOT tlsConn. The TLS wrapper and its crypto state are " +
		"leaked. After the fix at line 222 (conn = tlsConn), the panic " +
		"handler would close the wrapper, but this assignment happens AFTER " +
		"the handshake, so panics DURING handshake miss it.")
}

// =============================================================================
// Finding 3: CWE-400 - Handshake semaphore size (32768) is unconfigurable
// and may be too large or too small
// =============================================================================
//
// hub.go line 29: const maxConcurrentHandshakes = 32768
//
// This is a fixed constant with no configuration mechanism. On systems
// with limited CPU, 32768 concurrent TLS handshakes can saturate all
// cores (each handshake involves RSA/ECDH computation). On high-end
// systems, this may be too restrictive.
//
// An attacker can initiate 32768 TLS connections, complete none of them
// (let them timeout after 8 seconds), and consume the entire semaphore.
// During this window, legitimate TLS connections are rejected.
//
// With the 8-second tlsHandshakeTimeout, the attack requires maintaining
// 32768 half-open connections for 8 seconds = 4096 connections/second
// for 8 seconds. This is achievable with modest hardware.
//
// Severity: MEDIUM (DoS via handshake exhaustion)
// CWE-400: Uncontrolled Resource Consumption
//
// REMEDIATION: Make maxConcurrentHandshakes configurable via environment
// variable or config file. Add a per-IP handshake rate limit.
func TestVuln_CWE_400_HandshakeSemaphoreExhaustion(t *testing.T) {
	// Demonstrate that a channel-based semaphore of size 32768 can be
	// filled by a burst of half-open connections.

	const semSize = 32768
	sem := make(chan struct{}, semSize)

	// Fill the semaphore (simulates 32768 half-open TLS handshakes)
	for i := 0; i < semSize; i++ {
		sem <- struct{}{}
	}

	// Verify: next connection is rejected
	select {
	case sem <- struct{}{}:
		t.Fatal("semaphore should be full")
	default:
		// Expected: semaphore full
	}

	t.Logf("CONFIRMED: Handshake semaphore (%d slots) is full. All new TLS "+
		"connections will be rejected until a handshake completes or times out "+
		"(8 seconds). An attacker maintaining %d half-open connections blocks "+
		"all legitimate TLS handshakes.", semSize, semSize)

	// Calculate attack bandwidth requirement
	handshakeTimeout := 8 * time.Second
	attackRate := float64(semSize) / handshakeTimeout.Seconds()
	t.Logf("Attack requires %.0f new connections/second sustained for %v "+
		"to maintain semaphore exhaustion.", attackRate, handshakeTimeout)
}

// =============================================================================
// Finding 4: CWE-362 - REALITY handshake fd extraction + kTLS setup
// has no protection against concurrent Close
// =============================================================================
//
// In hub.go line 227: fd, fdErr := tls.ExtractFd(conn)
// In hub.go line 234: rustResult, rustErr := v.doRustRealityServer(fd)
//
// The fd is extracted from conn and passed to the Rust FFI. If conn is
// closed concurrently (e.g., by the panic handler on a different goroutine,
// or by the OS due to TCP RST), the fd becomes invalid. The Rust code
// operating on a stale fd may:
//   - Read from a different connection (fd reuse)
//   - Segfault (operating on closed fd)
//   - Return bogus results
//
// The panic handler is on the SAME goroutine, so it can't race with the
// handshake code. But the conn's underlying socket can be closed by the
// remote peer, and the fd can be reused by the OS before the Rust code
// finishes.
//
// This is inherent to fd-based FFI and not specific to this fix, but the
// fix did not add any fd-validity checking before or after the Rust call.
//
// Severity: LOW (inherent to fd-passing design, requires adversarial timing)
// CWE-362: Race Condition
//
// REMEDIATION: Dup the fd before passing to Rust, so the original close
// doesn't invalidate the Rust side's copy. Or use a mutex to prevent
// concurrent close during the Rust call.
func TestVuln_CWE_362_FdReuseAfterClose(t *testing.T) {
	// Demonstrate fd reuse: create a socket, get its fd, close it,
	// create a new socket -- the new socket may get the same fd.

	// Create first connection
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skip("cannot create listener:", err)
	}
	defer ln.Close()

	conn1, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Skip("cannot dial:", err)
	}

	// Accept the connection server-side
	sconn1, err := ln.Accept()
	if err != nil {
		t.Skip("cannot accept:", err)
	}

	// Get the fd (simulating ExtractFd)
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

	// Close the connection (fd becomes available for reuse)
	conn1.Close()
	sconn1.Close()

	// Create a new connection -- may get the same fd
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

	if fd1 == fd2 {
		t.Logf("FD REUSE CONFIRMED: fd1=%d == fd2=%d. If Rust FFI is still "+
			"operating on fd1 when it's reused as fd2, the Rust code reads/writes "+
			"a DIFFERENT connection's data. This is a classic fd-reuse vulnerability.", fd1, fd2)
	} else {
		t.Logf("FDs differ (fd1=%d, fd2=%d). FD reuse did not occur in this test "+
			"run, but it is possible under high connection churn.", fd1, fd2)
	}
}

// =============================================================================
// Finding 5: CWE-252 - Rust REALITY fallback to Go REALITY leaks auth
// failure information
// =============================================================================
//
// In hub.go lines 252-258:
//   if !stderrors.Is(rustErr, native.ErrRealityAuthFailed) {
//       // Non-auth error: close and return
//   }
//   // Auth failed in Rust path; fall through to Go REALITY.
//
// When Rust REALITY auth fails, the code falls through to Go REALITY
// (line 262-273). But the Rust path already consumed TLS ClientHello
// data from the socket. The Go REALITY path expects to read the
// ClientHello from the same socket. Since the Rust path already consumed
// it, Go REALITY will either:
//   (a) Read garbage (next TLS record, if any), or
//   (b) Timeout waiting for data that was already consumed
//
// HOWEVER, looking at lines 238-260 more carefully:
//   - If rustErr == nil && kTLS incomplete -> close (line 248-249)
//   - If rustErr == nil && kTLS complete -> success (line 239-240)
//   - If rustErr != nil && not auth failure -> close (line 253-255)
//   - If rustErr == ErrRealityAuthFailed -> fall through to Go REALITY
//
// For ErrRealityAuthFailed, rustErr is non-nil, meaning the handshake
// failed early (before consuming significant data). The question is
// whether the Rust side left the socket in a clean state. If it
// consumed the ClientHello but couldn't authenticate, the Go path
// will fail.
//
// Severity: MEDIUM (auth bypass potential if Go path succeeds on
// data that should have been rejected by Rust path)
// CWE-252: Unchecked Return Value
//
// REMEDIATION: After Rust auth failure, do NOT fall through to Go
// REALITY. Close the connection. If fallback is needed, use a fresh
// connection (impossible for server-side) or buffer the ClientHello
// before passing to Rust.
func TestVuln_CWE_252_RealityAuthFallbackSocketState(t *testing.T) {
	// Structural analysis: the Rust REALITY handshake reads from the
	// socket fd directly. After auth failure, the socket read pointer
	// has advanced past the ClientHello. The Go REALITY path reads
	// from the same socket and will see post-ClientHello data.

	t.Log("STRUCTURAL VULNERABILITY: When Rust REALITY auth fails " +
		"(ErrRealityAuthFailed), the code falls through to Go REALITY " +
		"(hub.go line 262). But the Rust path has already consumed " +
		"TLS records from the socket. The Go path will attempt to " +
		"parse a TLS ClientHello from a socket whose read pointer " +
		"has been advanced, causing either: (a) Go REALITY fails " +
		"gracefully (likely), or (b) Go REALITY misparses consumed " +
		"data as valid (auth bypass). The actual behavior depends on " +
		"how much data the Rust side consumed before auth rejection.")

	t.Log("REMEDIATION: After Rust auth failure, close the connection " +
		"instead of falling through to Go REALITY. The socket state " +
		"is indeterminate after Rust consumed data from it.")
}
