package buf_test

import (
	"context"
	"testing"

	. "github.com/xtls/xray-core/common/buf"
)

// --- Arena Allocator Tests ---

func TestArenaNewMinimumSize(t *testing.T) {
	// Requesting less than 4096 should clamp to 4096.
	a := NewArena(0)
	if a == nil {
		t.Fatal("NewArena(0) returned nil")
	}
	// Should be able to allocate at least 4096 bytes without overflow.
	slice := a.Alloc(4096)
	if len(slice) != 4096 {
		t.Fatalf("Alloc(4096) returned len=%d, want 4096", len(slice))
	}
	a.Close()
}

func TestArenaNewSmallClampedTo4096(t *testing.T) {
	a := NewArena(100)
	// Even though 100 < 4096, arena should still accept allocations.
	slice := a.Alloc(4000)
	if len(slice) != 4000 {
		t.Fatalf("Alloc(4000) returned len=%d, want 4000", len(slice))
	}
	a.Close()
}

func TestArenaAllocAlignment(t *testing.T) {
	a := NewArena(8192)
	// Alloc 1 byte: should align offset to 8.
	s1 := a.Alloc(1)
	if len(s1) != 1 {
		t.Fatalf("Alloc(1) returned len=%d", len(s1))
	}
	// Next alloc should start at offset 8 (aligned).
	s2 := a.Alloc(1)
	if len(s2) != 1 {
		t.Fatalf("second Alloc(1) returned len=%d", len(s2))
	}
	// Verify the two slices do not overlap by checking addresses.
	if &s1[0] == &s2[0] {
		t.Fatal("two consecutive allocations returned the same pointer")
	}
	a.Close()
}

func TestArenaAllocOverflow(t *testing.T) {
	a := NewArena(4096)
	// Fill the arena main buffer.
	s1 := a.Alloc(4096)
	if len(s1) != 4096 {
		t.Fatalf("Alloc(4096) returned len=%d", len(s1))
	}
	// Allocate more -- should go to overflow.
	s2 := a.Alloc(100)
	if len(s2) != 100 {
		t.Fatalf("overflow Alloc(100) returned len=%d", len(s2))
	}
	if a.BytesUsed() != 4196 {
		t.Fatalf("BytesUsed() = %d, want 4196", a.BytesUsed())
	}
	a.Close()
}

func TestArenaAllocZeroBytes(t *testing.T) {
	a := NewArena(4096)
	s := a.Alloc(0)
	if len(s) != 0 {
		t.Fatalf("Alloc(0) returned len=%d, want 0", len(s))
	}
	a.Close()
}

func TestArenaAllocLargerThanBuffer(t *testing.T) {
	a := NewArena(4096)
	// Request more than the initial buffer size.
	s := a.Alloc(8192)
	if len(s) != 8192 {
		t.Fatalf("Alloc(8192) returned len=%d, want 8192", len(s))
	}
	if a.BytesUsed() != 8192 {
		t.Fatalf("BytesUsed() = %d, want 8192", a.BytesUsed())
	}
	a.Close()
}

func TestArenaReset(t *testing.T) {
	a := NewArena(4096)
	a.Alloc(1000)
	a.Alloc(2000)
	if a.BytesUsed() != 3000 {
		t.Fatalf("BytesUsed() = %d before reset, want 3000", a.BytesUsed())
	}
	a.Reset()
	if a.BytesUsed() != 0 {
		t.Fatalf("BytesUsed() = %d after reset, want 0", a.BytesUsed())
	}
	// Should be able to reuse after reset.
	s := a.Alloc(4096)
	if len(s) != 4096 {
		t.Fatalf("Alloc(4096) after reset returned len=%d", len(s))
	}
	a.Close()
}

func TestArenaNewBuffer(t *testing.T) {
	a := NewArena(Size * 4) // big enough for several buffers
	b := a.NewBuffer()
	if b == nil {
		t.Fatal("NewBuffer() returned nil")
	}
	if b.Len() != 0 {
		t.Fatalf("new buffer should be empty, got Len()=%d", b.Len())
	}
	// Write something.
	n, err := b.WriteString("hello arena")
	if err != nil {
		t.Fatal(err)
	}
	if n != 11 {
		t.Fatalf("wrote %d bytes, want 11", n)
	}
	a.Close()
}

func TestArenaClose(t *testing.T) {
	a := NewArena(4096)
	a.Alloc(100)
	a.Close()
	// After close, BytesUsed() still returns whatever was accumulated.
	// But the backing buffer is nil.
}

func TestArenaMultipleOverflows(t *testing.T) {
	a := NewArena(4096)
	// Fill main buffer.
	a.Alloc(4096)
	// Multiple overflows.
	for i := 0; i < 10; i++ {
		s := a.Alloc(1024)
		if len(s) != 1024 {
			t.Fatalf("overflow alloc %d: len=%d, want 1024", i, len(s))
		}
	}
	expected := 4096 + 10*1024
	if a.BytesUsed() != expected {
		t.Fatalf("BytesUsed() = %d, want %d", a.BytesUsed(), expected)
	}
	a.Close()
}

// --- Arena Context Tests ---

func TestArenaFromContextNil(t *testing.T) {
	a := ArenaFromContext(context.Background())
	if a != nil {
		t.Fatal("ArenaFromContext on empty context should return nil")
	}
}

func TestContextWithArenaRoundTrip(t *testing.T) {
	arena := NewArena(4096)
	defer arena.Close()

	ctx := ContextWithArena(context.Background(), arena)
	got := ArenaFromContext(ctx)
	if got != arena {
		t.Fatal("ArenaFromContext did not return the stored arena")
	}
}

func TestContextWithArenaNested(t *testing.T) {
	a1 := NewArena(4096)
	a2 := NewArena(8192)
	defer a1.Close()
	defer a2.Close()

	ctx1 := ContextWithArena(context.Background(), a1)
	ctx2 := ContextWithArena(ctx1, a2)

	// Inner context should shadow outer.
	if ArenaFromContext(ctx2) != a2 {
		t.Fatal("inner context should shadow outer arena")
	}
	// Outer should still have a1.
	if ArenaFromContext(ctx1) != a1 {
		t.Fatal("outer context should retain original arena")
	}
}
