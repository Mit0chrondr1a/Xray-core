package pipe

import (
	"sync"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
)

// --- SPSCSlotRing Unit Tests ---

func TestNewSPSCSlotRingMinCapacity(t *testing.T) {
	r := NewSPSCSlotRing(0)
	if r.capacity < 4 {
		t.Fatalf("expected capacity >= 4, got %d", r.capacity)
	}
}

func TestNewSPSCSlotRingPowerOfTwo(t *testing.T) {
	tests := []struct {
		input    int
		expected uint64
	}{
		{1, 4},   // clamped to 4
		{3, 4},   // clamped to 4
		{4, 4},   // exact
		{5, 8},   // next power of 2
		{9, 16},  // next power of 2
		{16, 16}, // exact
		{17, 32},
	}
	for _, tt := range tests {
		r := NewSPSCSlotRing(tt.input)
		if r.capacity != tt.expected {
			t.Errorf("NewSPSCSlotRing(%d): capacity=%d, want %d", tt.input, r.capacity, tt.expected)
		}
	}
}

func TestSPSCSlotRingWriteReadBasic(t *testing.T) {
	r := NewSPSCSlotRing(8)

	b := buf.New()
	b.WriteString("hello slot ring")
	mb := buf.MultiBuffer{b}

	if !r.TryWrite(mb) {
		t.Fatal("TryWrite failed on empty ring")
	}
	if r.Len() != 1 {
		t.Fatalf("Len()=%d, want 1", r.Len())
	}

	got, ok := r.TryRead()
	if !ok {
		t.Fatal("TryRead failed")
	}
	if got.String() != "hello slot ring" {
		t.Fatalf("read data mismatch: got %q", got.String())
	}
	buf.ReleaseMulti(got)
	if r.Len() != 0 {
		t.Fatalf("Len()=%d after drain, want 0", r.Len())
	}
}

func TestSPSCSlotRingFull(t *testing.T) {
	r := NewSPSCSlotRing(4) // capacity=4

	for i := 0; i < 4; i++ {
		b := buf.New()
		b.WriteString("x")
		if !r.TryWrite(buf.MultiBuffer{b}) {
			t.Fatalf("TryWrite %d failed", i)
		}
	}

	if r.Available() != 0 {
		t.Fatalf("Available()=%d, want 0", r.Available())
	}

	// Write on full ring should return false.
	b := buf.New()
	b.WriteString("overflow")
	if r.TryWrite(buf.MultiBuffer{b}) {
		t.Fatal("TryWrite succeeded on full ring")
	}
	b.Release()

	// Drain all
	for i := 0; i < 4; i++ {
		mb, ok := r.TryRead()
		if !ok {
			t.Fatalf("TryRead %d failed", i)
		}
		buf.ReleaseMulti(mb)
	}
}

func TestSPSCSlotRingEmpty(t *testing.T) {
	r := NewSPSCSlotRing(4)
	_, ok := r.TryRead()
	if ok {
		t.Fatal("TryRead succeeded on empty ring")
	}
}

func TestSPSCSlotRingBlockingWrite(t *testing.T) {
	r := NewSPSCSlotRing(4)

	// Fill ring.
	for i := 0; i < 4; i++ {
		b := buf.New()
		b.WriteString("fill")
		r.TryWrite(buf.MultiBuffer{b})
	}

	// Blocking Write should complete when reader drains.
	done := make(chan bool, 1)
	go func() {
		b := buf.New()
		b.WriteString("blocked")
		ok := r.Write(buf.MultiBuffer{b})
		done <- ok
	}()

	time.Sleep(10 * time.Millisecond)
	// Drain one slot.
	mb, _ := r.Read()
	buf.ReleaseMulti(mb)

	select {
	case ok := <-done:
		if !ok {
			t.Fatal("blocking Write returned false")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking Write timed out")
	}
	r.Close()
}

func TestSPSCSlotRingBlockingRead(t *testing.T) {
	r := NewSPSCSlotRing(4)

	done := make(chan string, 1)
	go func() {
		mb, ok := r.Read()
		if !ok {
			done <- ""
			return
		}
		done <- mb.String()
		buf.ReleaseMulti(mb)
	}()

	time.Sleep(10 * time.Millisecond)
	b := buf.New()
	b.WriteString("wakeup")
	r.Write(buf.MultiBuffer{b})

	select {
	case s := <-done:
		if s != "wakeup" {
			t.Fatalf("blocking Read: got %q, want %q", s, "wakeup")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("blocking Read timed out")
	}
	r.Close()
}

func TestSPSCSlotRingCloseRead(t *testing.T) {
	r := NewSPSCSlotRing(4)
	r.Close()
	_, ok := r.TryRead()
	if ok {
		t.Fatal("TryRead succeeded after Close on empty ring")
	}
}

func TestSPSCSlotRingCloseReadDrainFirst(t *testing.T) {
	r := NewSPSCSlotRing(4)
	b := buf.New()
	b.WriteString("drain")
	r.TryWrite(buf.MultiBuffer{b})
	r.Close()

	mb, ok := r.TryRead()
	if !ok {
		t.Fatal("TryRead failed for buffered data after Close")
	}
	if mb.String() != "drain" {
		t.Fatalf("read data: got %q, want %q", mb.String(), "drain")
	}
	buf.ReleaseMulti(mb)

	// Next read should fail.
	_, ok = r.TryRead()
	if ok {
		t.Fatal("second TryRead succeeded after Close+drain")
	}
}

func TestSPSCSlotRingConcurrentTransfer(t *testing.T) {
	const totalItems = 10000
	r := NewSPSCSlotRing(64)

	var wg sync.WaitGroup
	wg.Add(2)

	// Producer
	go func() {
		defer wg.Done()
		for i := 0; i < totalItems; i++ {
			b := buf.New()
			b.WriteString("P")
			r.Write(buf.MultiBuffer{b})
		}
		r.Close()
	}()

	// Consumer
	var totalRead int
	go func() {
		defer wg.Done()
		for {
			mb, ok := r.Read()
			if !ok {
				return
			}
			totalRead += len(mb)
			buf.ReleaseMulti(mb)
		}
	}()

	wg.Wait()
	if totalRead != totalItems {
		t.Fatalf("transferred %d items, want %d", totalRead, totalItems)
	}
}

func TestSPSCSlotRingDoubleClose(t *testing.T) {
	r := NewSPSCSlotRing(4)
	if err := r.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := r.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
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
