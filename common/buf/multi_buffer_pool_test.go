package buf_test

import (
	"testing"

	. "github.com/xtls/xray-core/common/buf"
)

func TestGetMultiBufferReturnsUsableSlice(t *testing.T) {
	mb := GetMultiBuffer()
	if mb == nil {
		t.Fatal("GetMultiBuffer returned nil")
	}
	if len(mb) != 0 {
		t.Fatalf("GetMultiBuffer should return empty slice, got len=%d", len(mb))
	}
	if cap(mb) == 0 {
		t.Fatal("GetMultiBuffer should provide non-zero capacity")
	}
}

func TestReleaseMultiReturnsEmptySlice(t *testing.T) {
	b1 := New()
	b1.Extend(1)
	b2 := New()
	b2.Extend(1)

	mb := MultiBuffer{b1, b2}
	released := ReleaseMulti(mb)
	if len(released) != 0 {
		t.Fatalf("ReleaseMulti should return empty slice, got len=%d", len(released))
	}
}
