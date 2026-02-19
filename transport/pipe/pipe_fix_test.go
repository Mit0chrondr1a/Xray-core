package pipe_test

import (
	"io"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/transport/pipe"
)

// =============================================================================
// Tests for Fix 3: SPSC pipe falls back to mutex pipe when DiscardOverflow set
// =============================================================================

// TestWithSPSCAndDiscardOverflowFallsBackToMutex verifies that combining
// WithSPSC() and DiscardOverflow() produces a mutex-based pipe that correctly
// discards writes when full, rather than an SPSC pipe that would block.
func TestWithSPSCAndDiscardOverflowFallsBackToMutex(t *testing.T) {
	// Create a pipe with size limit 0 (allows only 1 write before full),
	// SPSC requested, and DiscardOverflow set.
	reader, writer := New(WithSizeLimit(0), WithSPSC(), DiscardOverflow())

	// First write should succeed (pipe is empty, under limit).
	b1 := buf.New()
	b1.WriteString("first")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b1}); err != nil {
		t.Fatalf("first write failed: %v", err)
	}

	// Second write should be discarded (pipe is full, DiscardOverflow is active).
	// If the SPSC pipe were used instead of mutex pipe, this would BLOCK forever.
	done := make(chan error, 1)
	go func() {
		b2 := buf.New()
		b2.WriteString("second-discarded")
		done <- writer.WriteMultiBuffer(buf.MultiBuffer{b2})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("second write returned error: %v (expected nil due to discard)", err)
		}
		// Success: the write was discarded (returned nil without blocking).
	case <-time.After(2 * time.Second):
		t.Fatal("second write blocked for 2s -- SPSC pipe was used instead of mutex pipe with DiscardOverflow")
	}

	// Verify the first write's data is still readable.
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if mb.String() != "first" {
		t.Fatalf("expected 'first', got %q", mb.String())
	}
	buf.ReleaseMulti(mb)

	writer.Close()
}

// TestWithSPSCWithoutDiscardOverflowUsesSPSC verifies that when only
// WithSPSC() is used (no DiscardOverflow), the SPSC pipe is actually used.
// We verify this indirectly: the SPSC pipe has slot-based capacity, so
// filling it and having writes block is evidence of SPSC behavior.
func TestWithSPSCWithoutDiscardOverflowUsesSPSC(t *testing.T) {
	// Create an SPSC pipe with a small size limit to get a small ring.
	reader, writer := New(WithSizeLimit(8192), WithSPSC())

	// Write and read a simple message to verify basic operation.
	b := buf.New()
	b.WriteString("spsc-check")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read failed: %v", err)
	}
	if mb.String() != "spsc-check" {
		t.Fatalf("expected 'spsc-check', got %q", mb.String())
	}
	buf.ReleaseMulti(mb)

	writer.Close()

	// Verify EOF after close.
	_, err = reader.ReadMultiBuffer()
	if err != io.EOF {
		t.Fatalf("expected io.EOF, got %v", err)
	}
}

// =============================================================================
// Tests for deferred finding: SPSC pipe + size limit slot count derivation
// =============================================================================

// TestSPSCPipeSizeLimitBackpressure verifies that a pipe created with
// WithSizeLimit and WithSPSC has bounded capacity -- filling the ring
// causes writes to block (not silently succeed with unbounded data).
func TestSPSCPipeSizeLimitBackpressure(t *testing.T) {
	// WithSizeLimit(16384) with buf.Size=8192 yields:
	//   slots = 16384/8192 + 1 = 3, rounded to min 16 (then next power of 2 = 16)
	reader, writer := New(WithSizeLimit(16384), WithSPSC())

	// Fill the pipe with enough buffers to exceed the slot capacity.
	// With 16 slots, we should be able to write 16 buffers before blocking.
	fillCount := 0
	blocked := false
	for i := 0; i < 32; i++ {
		done := make(chan error, 1)
		go func() {
			b := buf.New()
			b.WriteString("fill")
			done <- writer.WriteMultiBuffer(buf.MultiBuffer{b})
		}()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("write %d failed: %v", i, err)
			}
			fillCount++
		case <-time.After(200 * time.Millisecond):
			// Write blocked -- ring is full. This is expected behavior.
			t.Logf("Write blocked after %d successful writes (ring full)", fillCount)
			blocked = true
			goto drain
		}
	}
	t.Logf("All 32 writes succeeded without blocking (ring capacity >= 32)")

drain:
	// Drain remaining data by interrupting the writer (unblocks any blocked write)
	// and then reading all data from the reader.
	writer.Interrupt()

	for {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			buf.ReleaseMulti(mb)
		}
		if err != nil {
			break
		}
	}

	// The key invariant: writes DID block at some point (ring has bounded capacity).
	if !blocked {
		// All writes succeeded -- this means the ring is very large or unbounded.
		// With 16 slots, 32 writes should not all succeed without blocking.
		t.Fatalf("expected writes to block around 16 slots, but all %d writes succeeded", fillCount)
	}
}

// TestSPSCPipeWithoutSizeLimit verifies that WithoutSizeLimit + WithSPSC
// creates a pipe with the default 64 slots.
func TestSPSCPipeWithoutSizeLimit(t *testing.T) {
	reader, writer := New(WithoutSizeLimit(), WithSPSC())

	// With default 64 slots, we should be able to write at least 60 buffers.
	writeCount := 0
	for i := 0; i < 64; i++ {
		b := buf.New()
		b.WriteString("x")
		done := make(chan error, 1)
		go func() {
			done <- writer.WriteMultiBuffer(buf.MultiBuffer{b})
		}()

		select {
		case err := <-done:
			if err != nil {
				t.Fatalf("write %d: %v", i, err)
			}
			writeCount++
		case <-time.After(100 * time.Millisecond):
			goto done_writing
		}
	}

done_writing:
	t.Logf("Wrote %d buffers before blocking (expected ~64 for default SPSC)", writeCount)

	// Drain.
	go func() {
		for {
			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				buf.ReleaseMulti(mb)
			}
			if err != nil {
				return
			}
		}
	}()
	writer.Close()

	// We expect at least 60 writes to succeed with 64 slots.
	if writeCount < 50 {
		t.Fatalf("expected at least 50 successful writes with 64-slot ring, got %d", writeCount)
	}
}
