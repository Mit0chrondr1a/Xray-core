package pipe

import (
	"bytes"
	"io"
	"sync"
	"testing"
	"time"
)

// --- SPSCRingBuffer Unit Tests ---

func TestNewSPSCRingBufferMinCapacity(t *testing.T) {
	r := NewSPSCRingBuffer(0)
	if r.capacity < 16 {
		t.Fatalf("expected capacity >= 16, got %d", r.capacity)
	}
}

func TestNewSPSCRingBufferPowerOfTwo(t *testing.T) {
	tests := []struct {
		input    int
		expected uint64
	}{
		{1, 16},   // clamped to 16
		{15, 16},  // clamped to 16
		{16, 16},  // exact
		{17, 32},  // next power of 2
		{100, 128},
		{256, 256},
		{1000, 1024},
	}
	for _, tt := range tests {
		r := NewSPSCRingBuffer(tt.input)
		if r.capacity != tt.expected {
			t.Errorf("NewSPSCRingBuffer(%d): capacity=%d, want %d", tt.input, r.capacity, tt.expected)
		}
	}
}

func TestSPSCRingBufferWriteReadBasic(t *testing.T) {
	r := NewSPSCRingBuffer(64)
	data := []byte("hello, world!")
	n := r.write(data)
	if n != len(data) {
		t.Fatalf("write: n=%d, want %d", n, len(data))
	}
	if r.AvailableRead() != len(data) {
		t.Fatalf("AvailableRead()=%d, want %d", r.AvailableRead(), len(data))
	}

	buf := make([]byte, 64)
	n = r.read(buf)
	if n != len(data) {
		t.Fatalf("read: n=%d, want %d", n, len(data))
	}
	if !bytes.Equal(buf[:n], data) {
		t.Fatalf("read data mismatch: got %q, want %q", buf[:n], data)
	}
	if r.AvailableRead() != 0 {
		t.Fatalf("AvailableRead()=%d after drain, want 0", r.AvailableRead())
	}
}

func TestSPSCRingBufferWrapAround(t *testing.T) {
	r := NewSPSCRingBuffer(16) // capacity=16
	// Write 12 bytes to get near the end.
	data1 := bytes.Repeat([]byte("A"), 12)
	n := r.write(data1)
	if n != 12 {
		t.Fatalf("write1: n=%d, want 12", n)
	}
	// Read 12 to advance readPos.
	buf := make([]byte, 16)
	n = r.read(buf)
	if n != 12 {
		t.Fatalf("read1: n=%d, want 12", n)
	}

	// Now write 10 bytes -- should wrap around.
	data2 := []byte("0123456789")
	n = r.write(data2)
	if n != 10 {
		t.Fatalf("wrap write: n=%d, want 10", n)
	}

	readBuf := make([]byte, 16)
	n = r.read(readBuf)
	if n != 10 {
		t.Fatalf("wrap read: n=%d, want 10", n)
	}
	if !bytes.Equal(readBuf[:n], data2) {
		t.Fatalf("wrap read data mismatch: got %q, want %q", readBuf[:n], data2)
	}
}

func TestSPSCRingBufferFull(t *testing.T) {
	r := NewSPSCRingBuffer(16) // capacity=16
	data := bytes.Repeat([]byte("F"), 16)
	n := r.write(data)
	if n != 16 {
		t.Fatalf("full write: n=%d, want 16", n)
	}
	if r.AvailableWrite() != 0 {
		t.Fatalf("AvailableWrite()=%d after full, want 0", r.AvailableWrite())
	}
	// Write more should return 0.
	n = r.write([]byte("X"))
	if n != 0 {
		t.Fatalf("write on full buffer: n=%d, want 0", n)
	}
}

func TestSPSCRingBufferEmpty(t *testing.T) {
	r := NewSPSCRingBuffer(16)
	buf := make([]byte, 16)
	n := r.read(buf)
	if n != 0 {
		t.Fatalf("read on empty: n=%d, want 0", n)
	}
}

func TestSPSCRingBufferBlockingWrite(t *testing.T) {
	r := NewSPSCRingBuffer(16)
	// Fill buffer.
	data := bytes.Repeat([]byte("X"), 16)
	r.write(data)

	// Blocking Write should eventually complete when reader drains.
	done := make(chan int)
	go func() {
		n, err := r.Write([]byte("hello"))
		if err != nil {
			t.Errorf("blocking Write: %v", err)
		}
		done <- n
	}()

	// Let the writer block briefly.
	time.Sleep(10 * time.Millisecond)
	// Drain the buffer.
	buf := make([]byte, 16)
	r.Read(buf)

	select {
	case n := <-done:
		if n != 5 {
			t.Fatalf("blocking Write: n=%d, want 5", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking Write timed out")
	}
	r.Close()
}

func TestSPSCRingBufferBlockingRead(t *testing.T) {
	r := NewSPSCRingBuffer(16)

	done := make(chan int)
	go func() {
		buf := make([]byte, 5)
		n, err := r.Read(buf)
		if err != nil {
			t.Errorf("blocking Read: %v", err)
		}
		done <- n
	}()

	time.Sleep(10 * time.Millisecond)
	r.Write([]byte("hello"))

	select {
	case n := <-done:
		if n != 5 {
			t.Fatalf("blocking Read: n=%d, want 5", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking Read timed out")
	}
	r.Close()
}

func TestSPSCRingBufferCloseWrite(t *testing.T) {
	r := NewSPSCRingBuffer(16)
	r.Close()
	_, err := r.Write([]byte("hello"))
	if err != io.ErrClosedPipe {
		t.Fatalf("Write after Close: got %v, want io.ErrClosedPipe", err)
	}
}

func TestSPSCRingBufferCloseRead(t *testing.T) {
	r := NewSPSCRingBuffer(16)
	r.Close()
	buf := make([]byte, 16)
	_, err := r.Read(buf)
	if err != io.EOF {
		t.Fatalf("Read after Close: got %v, want io.EOF", err)
	}
}

func TestSPSCRingBufferCloseReadDrainFirst(t *testing.T) {
	r := NewSPSCRingBuffer(16)
	r.write([]byte("drain"))
	r.Close()
	buf := make([]byte, 16)
	n, err := r.Read(buf)
	if err != nil {
		t.Fatalf("Read of buffered data after Close: %v", err)
	}
	if n != 5 || string(buf[:n]) != "drain" {
		t.Fatalf("Read: n=%d data=%q, want 5 'drain'", n, buf[:n])
	}
	// Next read should return EOF.
	_, err = r.Read(buf)
	if err != io.EOF {
		t.Fatalf("second Read after Close: got %v, want io.EOF", err)
	}
}

func TestSPSCRingBufferEmptyReadWrite(t *testing.T) {
	r := NewSPSCRingBuffer(16)
	n, err := r.Write(nil)
	if n != 0 || err != nil {
		t.Fatalf("Write(nil): n=%d err=%v", n, err)
	}
	buf := make([]byte, 0)
	n, err = r.Read(buf)
	if n != 0 || err != nil {
		t.Fatalf("Read(empty): n=%d err=%v", n, err)
	}
	r.Close()
}

// --- Concurrency: Single Producer Single Consumer ---

func TestSPSCRingBufferConcurrentTransfer(t *testing.T) {
	const totalBytes = 1 << 20 // 1 MiB
	r := NewSPSCRingBuffer(4096)

	var wg sync.WaitGroup
	wg.Add(2)

	// Producer
	go func() {
		defer wg.Done()
		data := bytes.Repeat([]byte("P"), 1024)
		remaining := totalBytes
		for remaining > 0 {
			toWrite := min(1024, remaining)
			n, err := r.Write(data[:toWrite])
			if err != nil {
				t.Errorf("producer Write: %v", err)
				return
			}
			remaining -= n
		}
		r.Close()
	}()

	// Consumer
	var totalRead int
	go func() {
		defer wg.Done()
		buf := make([]byte, 2048)
		for {
			n, err := r.Read(buf)
			totalRead += n
			if err == io.EOF {
				return
			}
			if err != nil {
				t.Errorf("consumer Read: %v", err)
				return
			}
		}
	}()

	wg.Wait()
	if totalRead != totalBytes {
		t.Fatalf("transferred %d bytes, want %d", totalRead, totalBytes)
	}
}

// --- nextPowerOf2 ---

func TestNextPowerOf2(t *testing.T) {
	tests := []struct {
		input    uint64
		expected uint64
	}{
		{0, 1},
		{1, 1},
		{2, 2},
		{3, 4},
		{4, 4},
		{5, 8},
		{7, 8},
		{8, 8},
		{9, 16},
		{1023, 1024},
		{1024, 1024},
		{1025, 2048},
	}
	for _, tt := range tests {
		got := nextPowerOf2(tt.input)
		if got != tt.expected {
			t.Errorf("nextPowerOf2(%d)=%d, want %d", tt.input, got, tt.expected)
		}
	}
}

// --- Edge Cases ---

func TestSPSCRingBufferNegativeCapacity(t *testing.T) {
	// After the fix, negative capacity is clamped to minimum (16 bytes).
	rb := NewSPSCRingBuffer(-1)
	if rb.capacity != 16 {
		t.Fatalf("negative capacity: got capacity=%d, want 16", rb.capacity)
	}
	// Buffer should be fully functional.
	n := rb.write([]byte("test"))
	if n != 4 {
		t.Fatalf("write on clamped buffer: n=%d, want 4", n)
	}
}

func TestSPSCRingBufferWritePartialThenClose(t *testing.T) {
	// Write some data, close, then read. Should get data then EOF.
	r := NewSPSCRingBuffer(64)
	data := []byte("partial data")
	n, err := r.Write(data)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if n != len(data) {
		t.Fatalf("Write: n=%d, want %d", n, len(data))
	}
	r.Close()

	readBuf := make([]byte, 64)
	n, err = r.Read(readBuf)
	if err != nil {
		t.Fatalf("Read after close: %v", err)
	}
	if n != len(data) || !bytes.Equal(readBuf[:n], data) {
		t.Fatalf("Read data: got %q, want %q", readBuf[:n], data)
	}

	// Next read should return EOF.
	_, err = r.Read(readBuf)
	if err != io.EOF {
		t.Fatalf("second Read: got %v, want io.EOF", err)
	}
}

func TestSPSCRingBufferAvailableReadWrite(t *testing.T) {
	r := NewSPSCRingBuffer(32)
	if r.AvailableRead() != 0 {
		t.Fatalf("initial AvailableRead=%d, want 0", r.AvailableRead())
	}
	if r.AvailableWrite() != 32 {
		t.Fatalf("initial AvailableWrite=%d, want 32", r.AvailableWrite())
	}

	r.write([]byte("12345678")) // 8 bytes
	if r.AvailableRead() != 8 {
		t.Fatalf("after write 8: AvailableRead=%d, want 8", r.AvailableRead())
	}
	if r.AvailableWrite() != 24 {
		t.Fatalf("after write 8: AvailableWrite=%d, want 24", r.AvailableWrite())
	}

	buf := make([]byte, 4)
	r.read(buf)
	if r.AvailableRead() != 4 {
		t.Fatalf("after read 4: AvailableRead=%d, want 4", r.AvailableRead())
	}
	if r.AvailableWrite() != 28 {
		t.Fatalf("after read 4: AvailableWrite=%d, want 28", r.AvailableWrite())
	}
	r.Close()
}

func TestSPSCRingBufferDoubleClose(t *testing.T) {
	r := NewSPSCRingBuffer(16)
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}
