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

// --- H1: Interrupt drain race ---
// Interrupt() must NOT drain the ring itself. Only the reader drains.
// Data written before Interrupt() must be visible to the reader before EOF.

func TestSPSCPipe_H1_ConcurrentInterruptWrite_NoDataloss(t *testing.T) {
	// Launch a writer goroutine doing rapid writes; call Interrupt() concurrently.
	// The reader must see AT LEAST all data from writes that returned nil.
	//
	// Due to the TOCTOU fix (H3), a write whose TryWrite succeeded but whose
	// post-write state re-check found the pipe interrupted will return
	// io.ErrClosedPipe even though the data landed in the ring. This means
	// the reader may see MORE bytes than the writer counted as "successful".
	// The invariant is: readBytes >= successfulWriteBytes. Strict data loss
	// (readBytes < successfulWriteBytes) must never happen.
	const iterations = 500
	for iter := 0; iter < iterations; iter++ {
		reader, writer := NewSPSC(16)

		var successBytes atomic.Int64
		var writerDone sync.WaitGroup
		writerDone.Add(1)

		go func() {
			defer writerDone.Done()
			for i := 0; i < 50; i++ {
				b := buf.New()
				b.WriteString("ABCD") // 4 bytes each
				err := writer.WriteMultiBuffer(buf.MultiBuffer{b})
				if err == nil {
					successBytes.Add(4)
				} else {
					// Write returned error (pipe closed/interrupted).
					// If error is io.ErrClosedPipe from TOCTOU re-check,
					// data may still be in the ring. That is by design.
					break
				}
			}
		}()

		// Let the writer get some writes in, then interrupt.
		runtime.Gosched()
		writer.Interrupt()

		writerDone.Wait()

		// Reader drains everything.
		var readBytes int64
		for {
			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				readBytes += int64(mb.Len())
				buf.ReleaseMulti(mb)
			}
			if err != nil {
				if err != io.EOF {
					t.Fatalf("iter %d: unexpected read error: %v", iter, err)
				}
				break
			}
		}

		// Every byte from a write that returned nil must appear on the read side.
		// readBytes may exceed successBytes due to TOCTOU writes that landed
		// in the ring but returned io.ErrClosedPipe to the writer.
		success := successBytes.Load()
		if readBytes < success {
			t.Fatalf("iter %d: data loss: writer reported %d successful bytes, reader got only %d",
				iter, success, readBytes)
		}
	}
}

func TestSPSCPipe_H1_InterruptDuringBlockedWrite(t *testing.T) {
	// Fill the ring to capacity, then start a writer that will block.
	// Fire Interrupt() while the writer is blocked.
	// The writer must get io.ErrClosedPipe. The reader must drain
	// whatever was in the ring before getting EOF.
	reader, writer := NewSPSC(4) // 4 slots

	// Fill all 4 slots.
	for i := 0; i < 4; i++ {
		b := buf.New()
		b.WriteString("FULL")
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("fill write %d: %v", i, err)
		}
	}

	// Writer will block because ring is full.
	writeErr := make(chan error, 1)
	go func() {
		b := buf.New()
		b.WriteString("BLOCKED")
		writeErr <- writer.WriteMultiBuffer(buf.MultiBuffer{b})
	}()

	// Give the writer time to enter the blocking path.
	time.Sleep(10 * time.Millisecond)

	// Interrupt while writer is blocked.
	writer.Interrupt()

	err := <-writeErr
	if err != io.ErrClosedPipe {
		t.Fatalf("blocked writer: expected io.ErrClosedPipe, got %v", err)
	}

	// Reader must drain the 4 items that were in the ring.
	var readCount int
	for {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			readCount += len(mb)
			buf.ReleaseMulti(mb)
		}
		if err != nil {
			if err != io.EOF {
				t.Fatalf("reader: unexpected error: %v", err)
			}
			break
		}
	}

	if readCount < 4 {
		t.Fatalf("reader drained only %d items, expected at least 4", readCount)
	}
}

// --- H3: WriteMultiBuffer TOCTOU ---
// After TryWrite succeeds, the writer re-checks state. If Interrupt() fired
// between the initial state check and TryWrite, the writer signals the reader
// and returns io.ErrClosedPipe. The reader must still see the data.

func TestSPSCPipe_H3_TOCTOU_WriteThenImmediateInterrupt(t *testing.T) {
	// Write data, then immediately Interrupt(). The reader must get the data
	// before EOF. This tests the TOCTOU re-check: even if Write returns
	// io.ErrClosedPipe (because it detected the state change after TryWrite),
	// the data is in the ring and the reader must drain it.
	const iterations = 1000
	for iter := 0; iter < iterations; iter++ {
		reader, writer := NewSPSC(16)

		// Write one buffer.
		b := buf.New()
		b.WriteString("TOCTOU")
		writeErr := writer.WriteMultiBuffer(buf.MultiBuffer{b})

		// Immediately interrupt.
		writer.Interrupt()

		// If write succeeded, reader must see the data before EOF.
		// If write returned io.ErrClosedPipe (TOCTOU detected), reader
		// should still see the data (it was written to the ring).
		if writeErr != nil && writeErr != io.ErrClosedPipe {
			t.Fatalf("iter %d: unexpected write error: %v", iter, writeErr)
		}

		var readData string
		for {
			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				readData += mb.String()
				buf.ReleaseMulti(mb)
			}
			if err != nil {
				if err != io.EOF {
					t.Fatalf("iter %d: unexpected read error: %v", iter, err)
				}
				break
			}
		}

		if writeErr == nil && readData != "TOCTOU" {
			// Write succeeded without error -- reader MUST see the data.
			t.Fatalf("iter %d: write succeeded but reader got %q, expected %q",
				iter, readData, "TOCTOU")
		}
		// If writeErr == io.ErrClosedPipe, the data may or may not be readable
		// depending on exact timing, but it must not crash.
	}
}

// --- Close then read drains ---

func TestSPSCPipe_CloseThenRead_DrainsBeforeEOF(t *testing.T) {
	reader, writer := NewSPSC(16)

	// Write data.
	b := buf.New()
	b.WriteString("drain-me")
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
		t.Fatalf("write: %v", err)
	}

	// Close (not interrupt).
	writer.Close()

	// First read must return the data.
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("first read: unexpected error: %v", err)
	}
	if mb.String() != "drain-me" {
		t.Fatalf("first read: got %q, expected %q", mb.String(), "drain-me")
	}
	buf.ReleaseMulti(mb)

	// Second read must return EOF.
	mb2, err := reader.ReadMultiBuffer()
	if err != io.EOF {
		t.Fatalf("second read: expected io.EOF, got %v (data: %q)", err, mb2.String())
	}
}

func TestSPSCPipe_CloseThenRead_MultipleBuffers(t *testing.T) {
	reader, writer := NewSPSC(16)

	// Write multiple buffers.
	for i := 0; i < 5; i++ {
		b := buf.New()
		b.WriteString("item")
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	writer.Close()

	// Read all. Each ReadMultiBuffer returns one ring slot.
	var totalRead int
	for {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			totalRead += len(mb)
			buf.ReleaseMulti(mb)
		}
		if err != nil {
			if err != io.EOF {
				t.Fatalf("unexpected error: %v", err)
			}
			break
		}
	}

	if totalRead != 5 {
		t.Fatalf("expected 5 items drained before EOF, got %d", totalRead)
	}
}

// --- M4: bufferedLen int32 -> int64 overflow ---

func TestSPSCPipe_M4_BufferedLenAccuracy(t *testing.T) {
	reader, writer := NewSPSC(16)

	// Write known sizes and verify Len() tracks correctly.
	b1 := buf.New()
	b1.WriteString("12345") // 5 bytes
	writer.WriteMultiBuffer(buf.MultiBuffer{b1})

	if l := writer.Len(); l != 5 {
		t.Fatalf("after write 5 bytes: Len()=%d, expected 5", l)
	}

	b2 := buf.New()
	b2.WriteString("6789012345") // 10 bytes
	writer.WriteMultiBuffer(buf.MultiBuffer{b2})

	if l := writer.Len(); l != 15 {
		t.Fatalf("after write 15 total bytes: Len()=%d, expected 15", l)
	}

	// Read one buffer (the first one, 5 bytes).
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	buf.ReleaseMulti(mb)

	if l := writer.Len(); l != 10 {
		t.Fatalf("after reading 5 bytes: Len()=%d, expected 10", l)
	}

	// Read the second buffer.
	mb2, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	buf.ReleaseMulti(mb2)

	if l := writer.Len(); l != 0 {
		t.Fatalf("after reading all: Len()=%d, expected 0", l)
	}

	writer.Close()
}

func TestSPSCPipe_M4_BufferedLenRealisticValues(t *testing.T) {
	// Verify that Len() returns correct values for amounts that fit in int32.
	// The internal counter is int64 but Len() returns int32. For realistic
	// values (< 2GiB buffered), the truncation must not produce wrong results.
	reader, writer := NewSPSC(256)

	// Write 200 buffers of ~2000 bytes each = ~400KB total.
	// This is well within int32 range but large enough to exercise the counter.
	const numBufs = 200
	const payloadSize = 2000
	payload := make([]byte, payloadSize)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	var written int64
	for i := 0; i < numBufs; i++ {
		b := buf.New()
		b.Write(payload)
		size := int64(b.Len())
		if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
		written += size

		// Read some to prevent ring from filling.
		if i%2 == 0 {
			mb, err := reader.ReadMultiBuffer()
			if err != nil {
				t.Fatalf("read: %v", err)
			}
			written -= int64(mb.Len())
			buf.ReleaseMulti(mb)
		}
	}

	// Len() must match what we expect.
	l := int64(writer.Len())
	if l != written {
		t.Fatalf("Len() = %d, expected %d", l, written)
	}

	writer.Close()
	// Drain remaining.
	for {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			buf.ReleaseMulti(mb)
		}
		if err != nil {
			break
		}
	}
}

// --- Concurrent stress: Interrupt + Write race (run with -race) ---

func TestSPSCPipe_RaceDetector_InterruptDuringWrites(t *testing.T) {
	// This test is designed to trigger the race detector if the SPSC pipe
	// has data races between Interrupt() and WriteMultiBuffer().
	const iterations = 200
	for iter := 0; iter < iterations; iter++ {
		reader, writer := NewSPSC(8)

		var wg sync.WaitGroup
		wg.Add(2)

		// Writer goroutine.
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				b := buf.New()
				b.WriteString("race")
				if err := writer.WriteMultiBuffer(buf.MultiBuffer{b}); err != nil {
					return
				}
			}
		}()

		// Interrupter goroutine.
		go func() {
			defer wg.Done()
			runtime.Gosched()
			writer.Interrupt()
		}()

		// Reader: drain to completion.
		for {
			mb, err := reader.ReadMultiBuffer()
			if mb != nil {
				buf.ReleaseMulti(mb)
			}
			if err != nil {
				break
			}
		}

		wg.Wait()
	}
}

// --- Double Close / Double Interrupt (idempotency) ---

func TestSPSCPipe_DoubleClose_NoError(t *testing.T) {
	_, writer := NewSPSC(16)
	if err := writer.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	// Second Close must not panic.
	if err := writer.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

func TestSPSCPipe_DoubleInterrupt_NoPanic(t *testing.T) {
	_, writer := NewSPSC(16)
	// Must not panic.
	writer.Interrupt()
	writer.Interrupt()
}

func TestSPSCPipe_CloseAfterInterrupt(t *testing.T) {
	_, writer := NewSPSC(16)
	writer.Interrupt()
	// Close after Interrupt must not panic.
	if err := writer.Close(); err != nil {
		t.Fatalf("Close after Interrupt: %v", err)
	}
}

func TestSPSCPipe_InterruptAfterClose(t *testing.T) {
	reader, writer := NewSPSC(16)

	// Write some data.
	b := buf.New()
	b.WriteString("data")
	writer.WriteMultiBuffer(buf.MultiBuffer{b})

	writer.Close()
	writer.Interrupt() // Must not panic, and must upgrade state to errored.

	// Reader must still drain or get EOF.
	for {
		mb, err := reader.ReadMultiBuffer()
		if mb != nil {
			buf.ReleaseMulti(mb)
		}
		if err != nil {
			if err != io.EOF {
				t.Fatalf("unexpected error: %v", err)
			}
			break
		}
	}
}

// --- WriteMultiBuffer on empty MultiBuffer is a no-op ---

func TestSPSCPipe_WriteEmptyMultiBuffer_NoOp(t *testing.T) {
	_, writer := NewSPSC(16)
	err := writer.WriteMultiBuffer(buf.MultiBuffer{})
	if err != nil {
		t.Fatalf("empty write: %v", err)
	}
	if writer.Len() != 0 {
		t.Fatalf("Len()=%d after empty write, expected 0", writer.Len())
	}
	writer.Close()
}

// --- ReadMultiBufferTimeout with data available returns immediately ---

func TestSPSCPipe_ReadTimeoutWithDataAvailable(t *testing.T) {
	reader, writer := NewSPSC(16)

	b := buf.New()
	b.WriteString("fast")
	writer.WriteMultiBuffer(buf.MultiBuffer{b})

	start := time.Now()
	mb, err := reader.ReadMultiBufferTimeout(5 * time.Second)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("read with data: %v", err)
	}
	if mb.String() != "fast" {
		t.Fatalf("read data: %q", mb.String())
	}
	buf.ReleaseMulti(mb)

	if elapsed > 500*time.Millisecond {
		t.Fatalf("read took %v, expected near-instant", elapsed)
	}
	writer.Close()
}
