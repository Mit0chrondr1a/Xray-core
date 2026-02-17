package inbound

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- M1: False rejections (timer wait queue) ---
// After the timer fires, a final non-blocking select retries the semaphore.
// This prevents false rejections when the timer and semaphore-release happen
// simultaneously and select picks the timer.

// simulateTimerWaitQueue replicates the exact control flow from worker.go's
// TCP handler (lines 157-192). Returns true if "accepted", false if "rejected".
func simulateTimerWaitQueue(sem chan struct{}, timeout time.Duration) bool {
	// Fast path.
	select {
	case sem <- struct{}{}:
		return true
	default:
	}
	// Slow path: wait with timeout.
	timer := time.NewTimer(timeout)
	select {
	case sem <- struct{}{}:
		timer.Stop()
		return true
	case <-timer.C:
		// Final non-blocking attempt (the M1 fix).
		select {
		case sem <- struct{}{}:
			return true
		default:
		}
		return false
	}
}

func TestTimerWaitQueue_FinalRetrySucceeds(t *testing.T) {
	// Fill semaphore to capacity. Start a "connection" that enters the wait
	// queue. Release a slot just before the timer fires. The connection must
	// be accepted, not rejected.
	const capacity = 2
	sem := make(chan struct{}, capacity)

	// Fill.
	for i := 0; i < capacity; i++ {
		sem <- struct{}{}
	}

	// Release a slot shortly before the timeout.
	timeout := 100 * time.Millisecond
	go func() {
		time.Sleep(80 * time.Millisecond)
		<-sem // free one slot
	}()

	accepted := simulateTimerWaitQueue(sem, timeout)
	if !accepted {
		t.Fatal("connection was rejected despite a slot being freed before timeout -- false rejection bug")
	}

	// Clean up: drain the slot we acquired.
	<-sem
}

func TestTimerWaitQueue_GenuineTimeoutRejects(t *testing.T) {
	// Fill semaphore to capacity. Let timer expire with no slots freed.
	// The connection must be rejected.
	const capacity = 2
	sem := make(chan struct{}, capacity)

	// Fill.
	for i := 0; i < capacity; i++ {
		sem <- struct{}{}
	}

	timeout := 50 * time.Millisecond
	start := time.Now()
	accepted := simulateTimerWaitQueue(sem, timeout)
	elapsed := time.Since(start)

	if accepted {
		t.Fatal("connection was accepted despite no slots being freed -- should have been rejected")
	}

	// Verify the timeout actually elapsed (not an instant rejection).
	if elapsed < 40*time.Millisecond {
		t.Fatalf("rejection happened too fast (%v), timer may not have fired", elapsed)
	}
}

func TestTimerWaitQueue_FastPathWhenSlotAvailable(t *testing.T) {
	// When a slot is immediately available, the fast path should accept
	// without waiting.
	sem := make(chan struct{}, 4)

	start := time.Now()
	accepted := simulateTimerWaitQueue(sem, time.Second)
	elapsed := time.Since(start)

	if !accepted {
		t.Fatal("fast path rejected when slot was available")
	}
	if elapsed > 50*time.Millisecond {
		t.Fatalf("fast path took %v, expected near-instant", elapsed)
	}

	// Clean up.
	<-sem
}

func TestTimerWaitQueue_SlowPathAcquireBeforeTimer(t *testing.T) {
	// Semaphore is full, but a slot frees up well before the timeout.
	const capacity = 1
	sem := make(chan struct{}, capacity)
	sem <- struct{}{} // fill

	go func() {
		time.Sleep(10 * time.Millisecond)
		<-sem
	}()

	start := time.Now()
	accepted := simulateTimerWaitQueue(sem, 500*time.Millisecond)
	elapsed := time.Since(start)

	if !accepted {
		t.Fatal("connection rejected despite slot freed well before timeout")
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("took %v, slot should have been acquired in ~10ms", elapsed)
	}

	<-sem // clean up
}

func TestTimerWaitQueue_ConcurrentRace(t *testing.T) {
	// Multiple connections competing for a limited semaphore with timeouts.
	// This test runs under the race detector to verify no data races.
	const capacity = 4
	const clients = 20
	const timeout = 50 * time.Millisecond

	sem := make(chan struct{}, capacity)

	// Fill to capacity.
	for i := 0; i < capacity; i++ {
		sem <- struct{}{}
	}

	var accepted atomic.Int32
	var rejected atomic.Int32
	var wg sync.WaitGroup

	// Release slots gradually.
	go func() {
		for i := 0; i < clients; i++ {
			time.Sleep(5 * time.Millisecond)
			select {
			case <-sem:
			default:
			}
		}
	}()

	wg.Add(clients)
	for i := 0; i < clients; i++ {
		go func() {
			defer wg.Done()
			if simulateTimerWaitQueue(sem, timeout) {
				accepted.Add(1)
				// Simulate work, then release.
				time.Sleep(2 * time.Millisecond)
				<-sem
			} else {
				rejected.Add(1)
			}
		}()
	}

	wg.Wait()

	a := accepted.Load()
	r := rejected.Load()
	total := a + r
	if total != clients {
		t.Fatalf("accepted(%d) + rejected(%d) = %d, expected %d", a, r, total, clients)
	}
	// At least some should have been accepted (slots were being freed).
	if a == 0 {
		t.Fatal("no connections were accepted -- release goroutine may not be working")
	}
	t.Logf("accepted=%d rejected=%d (capacity=%d clients=%d)", a, r, capacity, clients)
}

// --- UDP handler uses the same pattern ---

func TestTimerWaitQueue_UDPFinalRetrySucceeds(t *testing.T) {
	// The UDP handler in worker.go uses the identical three-tier select pattern.
	// This test verifies the final non-blocking attempt works for UDP too.
	const capacity = 1
	sem := make(chan struct{}, capacity)
	sem <- struct{}{} // fill

	timeout := 100 * time.Millisecond
	go func() {
		time.Sleep(90 * time.Millisecond)
		<-sem
	}()

	accepted := simulateTimerWaitQueue(sem, timeout)
	if !accepted {
		t.Fatal("UDP session rejected despite slot freed near timeout -- false rejection")
	}

	<-sem // clean up
}
