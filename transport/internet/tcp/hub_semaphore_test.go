package tcp

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- H2: Double-release panic ---
// The CAS-based idempotent release pattern ensures the semaphore is released
// exactly once, even if both the explicit release and the defer fire.

func TestIdempotentRelease_CalledTwice_ReleasesOnce(t *testing.T) {
	// Replicate the exact pattern from hub.go:
	//   var handshakeReleased atomic.Bool
	//   releaseHandshake := func() {
	//       if handshakeReleased.CompareAndSwap(false, true) {
	//           <-semaphore
	//       }
	//   }
	semaphore := make(chan struct{}, 1)
	semaphore <- struct{}{} // acquire

	var handshakeReleased atomic.Bool
	releaseHandshake := func() {
		if handshakeReleased.CompareAndSwap(false, true) {
			<-semaphore
		}
	}

	// Call release twice -- simulating both explicit release and defer.
	releaseHandshake()
	releaseHandshake()

	// Semaphore must have been drained exactly once.
	// If it was drained twice, the channel would have panicked or blocked.
	// Verify the semaphore is empty.
	select {
	case <-semaphore:
		t.Fatal("semaphore was released more than once -- double-release bug")
	default:
		// good: semaphore is empty, was released exactly once
	}
}

func TestIdempotentRelease_ConcurrentRelease_ExactlyOnce(t *testing.T) {
	const goroutines = 100
	const iterations = 1000

	for iter := 0; iter < iterations; iter++ {
		semaphore := make(chan struct{}, 1)
		semaphore <- struct{}{} // acquire

		var handshakeReleased atomic.Bool
		var releaseCount atomic.Int32

		releaseHandshake := func() {
			if handshakeReleased.CompareAndSwap(false, true) {
				<-semaphore
				releaseCount.Add(1)
			}
		}

		var wg sync.WaitGroup
		wg.Add(goroutines)
		for g := 0; g < goroutines; g++ {
			go func() {
				defer wg.Done()
				releaseHandshake()
			}()
		}
		wg.Wait()

		if c := releaseCount.Load(); c != 1 {
			t.Fatalf("iter %d: semaphore released %d times, expected exactly 1", iter, c)
		}
	}
}

func TestIdempotentRelease_DeferAndExplicit_ExactlyOnce(t *testing.T) {
	// Simulate the exact control flow from hub.go's goroutine:
	// defer releaseHandshake() at top, explicit releaseHandshake() before addConn.
	semaphore := make(chan struct{}, 1)
	semaphore <- struct{}{} // acquire

	var handshakeReleased atomic.Bool
	var releaseCount atomic.Int32

	releaseHandshake := func() {
		if handshakeReleased.CompareAndSwap(false, true) {
			<-semaphore
			releaseCount.Add(1)
		}
	}

	func() {
		defer releaseHandshake() // this is the defer in hub.go

		// ... simulate handshake work ...
		time.Sleep(time.Microsecond)

		// Explicit release before session begins (line 275 in hub.go).
		releaseHandshake()

		// ... simulate addConn ...
	}()

	if c := releaseCount.Load(); c != 1 {
		t.Fatalf("semaphore released %d times, expected exactly 1", c)
	}
}

func TestIdempotentRelease_NeverReleased_DeferCatchesIt(t *testing.T) {
	// Simulate early return (e.g., handshake failure) where only defer fires.
	semaphore := make(chan struct{}, 1)
	semaphore <- struct{}{} // acquire

	var handshakeReleased atomic.Bool
	var releaseCount atomic.Int32

	releaseHandshake := func() {
		if handshakeReleased.CompareAndSwap(false, true) {
			<-semaphore
			releaseCount.Add(1)
		}
	}

	func() {
		defer releaseHandshake()
		// Early return -- explicit releaseHandshake() never called.
		return
	}()

	if c := releaseCount.Load(); c != 1 {
		t.Fatalf("defer-only release: count=%d, expected 1", c)
	}
}

func TestSemaphoreCapacity_ExactLimit(t *testing.T) {
	// Verify the semaphore pattern correctly limits concurrency.
	const limit = 5
	semaphore := make(chan struct{}, limit)

	// Fill to capacity.
	for i := 0; i < limit; i++ {
		select {
		case semaphore <- struct{}{}:
		default:
			t.Fatalf("could not acquire semaphore at position %d", i)
		}
	}

	// Next acquire must fail (non-blocking).
	select {
	case semaphore <- struct{}{}:
		t.Fatal("semaphore accepted beyond capacity")
	default:
		// correct: at capacity
	}

	// Release one and re-acquire.
	<-semaphore
	select {
	case semaphore <- struct{}{}:
	default:
		t.Fatal("could not re-acquire after release")
	}
}
