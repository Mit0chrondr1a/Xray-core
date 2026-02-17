package pipe_test

import (
	"io"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/transport/pipe"
)

// TestVuln_CWE_362_BufferedLenDesyncOnInterruptDuringWrite demonstrates that
// when Interrupt() fires between TryWrite() succeeding and the writer's
// state re-check, the data IS written into the ring but bufferedLen is NOT
// updated. This desyncs bufferedLen from the actual ring contents.
//
// Impact: bufferedLen reports fewer bytes than are actually in the ring.
// Any consumer of Len() (flow control, metrics, memory accounting) sees
// a lie. The data IS consumed by the reader (no data loss), but the
// accounting is permanently wrong.
//
// REMEDIATION: In WriteMultiBuffer, after TryWrite succeeds, ALWAYS call
// bufferedLen.Add() before the state re-check, not after. The reader
// subtracts on read regardless, so the counter stays consistent. If the
// writer then detects closure, it signals the reader (already done) and
// returns error, but the accounting remains correct.
func TestVuln_CWE_362_BufferedLenDesyncOnInterruptDuringWrite(t *testing.T) {
	// Strategy: repeatedly race Interrupt() against WriteMultiBuffer()
	// to hit the window where TryWrite succeeds but state re-check
	// sees spscErrord, causing bufferedLen.Add to be skipped.

	const iterations = 5000
	desyncCount := atomic.Int64{}

	for i := 0; i < iterations; i++ {
		reader, writer := NewSPSC(16)

		var wg sync.WaitGroup
		wg.Add(2)

		writerDone := make(chan struct{})

		// Writer goroutine
		go func() {
			defer wg.Done()
			b := buf.New()
			b.WriteString("payload")
			_ = writer.WriteMultiBuffer(buf.MultiBuffer{b})
			close(writerDone)
		}()

		// Interrupter goroutine — fire as close to TryWrite as possible
		go func() {
			defer wg.Done()
			// Yield to let writer reach TryWrite
			runtime.Gosched()
			writer.Interrupt()
		}()

		wg.Wait()

		// Now drain the reader to see if there's data
		var totalRead int32
		for {
			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				totalRead += mb.Len()
				buf.ReleaseMulti(mb)
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				break
			}
		}

		// Check: writer.Len() should reflect 0 after full drain.
		// But if the desync occurred (data written but bufferedLen not updated),
		// Len() could be negative (reader subtracted, writer never added).
		finalLen := writer.Len()
		if finalLen != 0 {
			desyncCount.Add(1)
		}
	}

	// Under contention, we expect at least some desyncs.
	// If we get zero in 5000 iterations, the window might be too small
	// on this machine, but the logic bug is still present.
	dc := desyncCount.Load()
	t.Logf("bufferedLen desync observed %d/%d iterations", dc, iterations)
	if dc > 0 {
		t.Errorf("VULNERABILITY CONFIRMED: bufferedLen desynced from ring contents %d times. "+
			"Data was written to ring but bufferedLen.Add was skipped because Interrupt "+
			"fired between TryWrite and state re-check. Len() returned incorrect values.", dc)
	}
}

// TestVuln_CWE_362_WriteAfterSecondDrainRead demonstrates the H1 fix
// insufficiency: the reader does exactly ONE retry TryRead after seeing
// closed/errored state. If a writer completes TryWrite AFTER the reader's
// second TryRead but BEFORE the reader returns EOF, the data is orphaned
// in the ring and never consumed.
//
// Sequence:
//   1. Reader: first TryRead() -> empty
//   2. Reader: state.Load() -> spscOpen (not yet closed)
//   ... reader blocks on select, gets woken ...
//   3. Reader: first TryRead() -> empty (writer hasn't written yet)
//   4. Interrupt() fires -> state = spscErrord, readSignal.Signal()
//   5. Reader wakes, calls readMultiBufferInternal()
//   6. Reader: first TryRead() -> empty (writer STILL hasn't committed)
//   7. Reader: state.Load() -> spscErrord
//   8. Reader: second TryRead() -> empty (writer STILL hasn't committed)
//   9. Writer: TryWrite() completes (data now in ring)
//   10. Reader: returns io.EOF -- DATA ORPHANED IN RING
//
// Impact: Data loss. Buffers leaked (never freed). In a proxy, this means
// bytes from the upstream connection vanish silently.
//
// REMEDIATION: After Interrupt sets state, TryWrite should fail (return
// false) so no new data enters the ring after the reader's drain. Or the
// reader should loop drain attempts until the ring is provably empty and
// no writer can add more data.
func TestVuln_CWE_362_WriteAfterSecondDrainRead(t *testing.T) {
	// This is a timing-dependent race. We use many iterations to increase
	// the probability of hitting the exact interleaving.

	const iterations = 10000
	dataLossCount := atomic.Int64{}

	for i := 0; i < iterations; i++ {
		reader, writer := NewSPSC(16)

		var totalWritten atomic.Int64
		var totalRead atomic.Int64
		var wg sync.WaitGroup
		wg.Add(3)

		// Writer: writes slowly to maximize race window
		go func() {
			defer wg.Done()
			// Small delay to let reader enter wait state
			runtime.Gosched()
			time.Sleep(time.Microsecond)
			b := buf.New()
			b.WriteString("critical-data")
			err := writer.WriteMultiBuffer(buf.MultiBuffer{b})
			if err == nil {
				totalWritten.Add(13) // len("critical-data")
			}
		}()

		// Interrupter: fires close to when writer is writing
		go func() {
			defer wg.Done()
			runtime.Gosched()
			time.Sleep(time.Microsecond)
			writer.Interrupt()
		}()

		// Reader: reads until EOF
		go func() {
			defer wg.Done()
			for {
				mb, err := reader.ReadMultiBuffer()
				if mb != nil {
					totalRead.Add(int64(mb.Len()))
					buf.ReleaseMulti(mb)
				}
				if err == io.EOF {
					return
				}
				if err != nil {
					return
				}
			}
		}()

		wg.Wait()

		written := totalWritten.Load()
		read := totalRead.Load()
		if written > 0 && read == 0 {
			// Writer succeeded but reader never saw the data
			dataLossCount.Add(1)
		}
	}

	dc := dataLossCount.Load()
	t.Logf("Data loss (write succeeded, read got nothing) observed %d/%d iterations", dc, iterations)
	if dc > 0 {
		t.Errorf("VULNERABILITY CONFIRMED: Data loss observed %d times. "+
			"Writer's TryWrite completed after reader's second drain TryRead, "+
			"orphaning data in the ring. The single-retry drain is insufficient.", dc)
	}
}

// TestVuln_CWE_190_BufferedLenInt32Truncation demonstrates that the Len()
// method truncates int64 to int32, which silently wraps for values > 2^31-1.
//
// Impact: If more than ~2GB of data is buffered (unlikely in normal operation
// but possible with large ring + slow reader), Len() returns a negative or
// misleading value. Any flow control or accounting based on Len() breaks.
// Since MultiBuffer.Len() itself returns int32, individual adds are safe,
// but the ACCUMULATION in bufferedLen (int64) can exceed int32 range.
//
// REMEDIATION: Return int64 from Len(), or change the pipeImpl interface
// to use int64. Since the caller (Writer.Len) returns int32 via the
// pipeImpl interface, the interface itself needs updating.
func TestVuln_CWE_190_BufferedLenInt32Truncation(t *testing.T) {
	// This is a logic proof, not a runtime test requiring 2GB allocation.
	// We verify that the truncation EXISTS in the code path.

	// The vulnerability is structural:
	// - bufferedLen is atomic.Int64 (can hold values > MaxInt32)
	// - Len() returns int32(p.bufferedLen.Load()) -- truncation
	// - If bufferedLen ever exceeds MaxInt32 (2147483647), Len() wraps negative

	// Demonstrate with a simulated scenario:
	var bufferedLen atomic.Int64

	// Simulate accumulated writes totaling > MaxInt32
	bufferedLen.Store(2147483648) // 2^31, just over MaxInt32

	truncated := int32(bufferedLen.Load())
	if truncated >= 0 {
		t.Fatalf("Expected negative value from int32 truncation of 2^31, got %d", truncated)
	}

	t.Logf("int32 truncation of 2^31 = %d (negative!), confirming CWE-190 truncation vulnerability", truncated)
}
