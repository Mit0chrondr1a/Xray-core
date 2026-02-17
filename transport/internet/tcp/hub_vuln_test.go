package tcp

import (
	"sync"
	"sync/atomic"
	"testing"
)

// TestVuln_CWE_911_PanicAfterHandshakeRelease demonstrates a vulnerability
// in the defer ordering of the TCP hub goroutine (hub.go lines 168-281).
//
// The defer stack executes in LIFO order:
//   defer releaseHandshake()   -- registered FIRST, runs LAST
//   defer recover()            -- registered SECOND, runs FIRST
//
// This means: if a panic occurs, the recover handler runs FIRST (closes rawConn),
// then releaseHandshake runs SECOND (releases semaphore). This ordering is
// CORRECT for panics during the handshake phase.
//
// BUT: releaseHandshake() is also called explicitly at line 275, BEFORE
// v.addConn(). If addConn (or authConfig.Server at line 278) panics:
//   1. Panic fires
//   2. Recover handler runs: rawConn.Close() -- but rawConn may have been
//      wrapped by TLS (conn != rawConn). rawConn.Close() closes the underlying
//      TCP socket, but the TLS wrapper (conn) is NOT properly torn down.
//   3. releaseHandshake runs: CAS returns false (already released), no-op. CORRECT.
//
// The issue is that the recover handler closes rawConn (the original TCP conn)
// but not conn (which may be a TLS wrapper). The addConn handler received
// stat.Connection(conn) which is the TLS-wrapped connection. If addConn stored
// this connection somewhere before panicking, the stored reference points to
// a connection whose underlying socket is closed but whose TLS state is not
// properly shut down.
//
// Impact: TLS state leak on panic in addConn path. The connection appears
// usable to code that received it but reads/writes will fail with cryptic
// socket errors instead of clean TLS close_notify.
//
// REMEDIATION: The recover handler should close `conn` (the local variable
// from the goroutine scope), not just `rawConn`. Since `conn` is reassigned
// during the handshake, the panic handler needs to close whatever `conn`
// currently points to. Change the recover to use a pointer-to-conn pattern
// or close `conn` instead of `rawConn`.
func TestVuln_CWE_911_PanicAfterHandshakeRelease(t *testing.T) {
	// Demonstrate that the CAS-based releaseHandshake correctly prevents
	// double-release, but the rawConn vs conn issue persists.

	sem := make(chan struct{}, 1)
	sem <- struct{}{} // Acquire

	var released atomic.Bool
	releaseHandshake := func() {
		if released.CompareAndSwap(false, true) {
			<-sem
		}
	}

	// Simulate: explicit release (line 275)
	releaseHandshake()

	// Simulate: deferred release after panic
	releaseHandshake()

	// Verify semaphore is available (only one release happened)
	select {
	case sem <- struct{}{}:
		t.Log("CAS correctly prevented double-release of handshake semaphore.")
	default:
		t.Fatal("Semaphore still full after release — CAS failed to prevent double-drain")
	}

	// The REAL vulnerability is about conn vs rawConn in the panic handler.
	// This is a structural issue that cannot be demonstrated without a full
	// TLS stack, but the code clearly shows:
	//   line 179: rawConn.Close()  -- closes ORIGINAL socket
	//   line 182: conn := rawConn  -- conn is reassigned to TLS wrapper later
	//   line 199: conn = rustConn  -- now conn != rawConn
	//   line 280: v.addConn(stat.Connection(conn))  -- passes TLS conn
	// If addConn panics, rawConn.Close() fires but conn (TLS) is not closed.
	t.Log("STRUCTURAL: Panic handler closes rawConn (line 179) but not conn " +
		"(TLS wrapper). After handshake, conn != rawConn. If addConn panics, " +
		"the TLS session is not cleanly terminated.")
}

// TestVuln_CWE_362_HandshakeSemaphoreExhaustion demonstrates that
// maxConcurrentHandshakes (32768) is a fixed constant, not configurable.
// An attacker who opens 32768 TCP connections and sends partial TLS
// ClientHello messages (slowloris-style) will hold all semaphore slots
// for up to tlsHandshakeTimeout (8 seconds).
//
// During that 8-second window, ALL new legitimate connections are rejected
// at the select/default path (line 163-164), causing a complete denial of
// service for new connections.
//
// The handshake timeout mitigates this (each slot is held at most 8s), but
// 32768 connections * 8s = 262144 connection-seconds of blocked capacity,
// which is significant.
//
// Impact: DoS. An attacker with modest resources (32768 TCP connections) can
// block all new connections for 8 seconds per wave.
//
// REMEDIATION: Make maxConcurrentHandshakes configurable. Add per-IP rate
// limiting on the handshake path. Consider a shorter handshake timeout for
// the semaphore (separate from the TLS handshake timeout itself).
func TestVuln_CWE_362_HandshakeSemaphoreExhaustion(t *testing.T) {
	// Verify that the semaphore has the documented capacity
	sem := make(chan struct{}, maxConcurrentHandshakes)

	// Fill it
	for i := 0; i < maxConcurrentHandshakes; i++ {
		sem <- struct{}{}
	}

	// One more should fail (non-blocking)
	select {
	case sem <- struct{}{}:
		t.Fatal("Semaphore accepted more than maxConcurrentHandshakes")
	default:
		t.Logf("Semaphore correctly full at %d. An attacker holding all %d slots "+
			"with partial TLS handshakes blocks all new connections for up to %v.",
			maxConcurrentHandshakes, maxConcurrentHandshakes, tlsHandshakeTimeout)
	}
}

// TestVuln_CWE_400_DeferOrderOnPanic verifies the defer execution order
// in the hub goroutine to confirm that semaphore release happens even on panic.
func TestVuln_CWE_400_DeferOrderOnPanic(t *testing.T) {
	sem := make(chan struct{}, 1)
	sem <- struct{}{} // Acquire slot

	var order []string
	var mu sync.Mutex

	var released atomic.Bool
	releaseHandshake := func() {
		if released.CompareAndSwap(false, true) {
			mu.Lock()
			order = append(order, "release")
			mu.Unlock()
			<-sem
		}
	}

	func() {
		defer releaseHandshake()
		defer func() {
			if r := recover(); r != nil {
				mu.Lock()
				order = append(order, "recover")
				mu.Unlock()
			}
		}()

		panic("simulated panic in handshake")
	}()

	mu.Lock()
	defer mu.Unlock()

	// Defers run LIFO: recover first, then releaseHandshake
	if len(order) != 2 || order[0] != "recover" || order[1] != "release" {
		t.Fatalf("Unexpected defer order: %v (expected [recover, release])", order)
	}

	// Verify semaphore was released
	select {
	case sem <- struct{}{}:
		t.Log("Semaphore correctly released after panic. Defer order: recover -> release.")
	default:
		t.Fatal("Semaphore NOT released after panic — this would be a semaphore leak")
	}
}
