package native

import (
	"bytes"
	"testing"
	"unsafe"

	"lukechampine.com/blake3"
)

func TestVisionFilterStateLayout(t *testing.T) {
	var s VisionFilterState
	if got := unsafe.Sizeof(s); got != 16 {
		t.Fatalf("VisionFilterState size = %d, want 16", got)
	}
	if got := VisionFilterStateSizeC(); got != 16 {
		t.Fatalf("VisionFilterState C size = %d, want 16", got)
	}
	if got := unsafe.Offsetof(s.RemainingServerHello); got != 0 {
		t.Fatalf("RemainingServerHello offset = %d, want 0", got)
	}
	if got := unsafe.Offsetof(s.NumberOfPacketsToFilter); got != 4 {
		t.Fatalf("NumberOfPacketsToFilter offset = %d, want 4", got)
	}
	if got := unsafe.Offsetof(s.Cipher); got != 8 {
		t.Fatalf("Cipher offset = %d, want 8", got)
	}
	if got := unsafe.Offsetof(s.IsTLS); got != 10 {
		t.Fatalf("IsTLS offset = %d, want 10", got)
	}
	if got := unsafe.Offsetof(s.IsTLS12orAbove); got != 11 {
		t.Fatalf("IsTLS12orAbove offset = %d, want 11", got)
	}
	if got := unsafe.Offsetof(s.EnableXtls); got != 12 {
		t.Fatalf("EnableXtls offset = %d, want 12", got)
	}
}

func TestBlake3DeriveKeyInvalidUTF8Context(t *testing.T) {
	ctx := string([]byte{0xff, 0xfe, 'x'})
	key := []byte("test-key-material")

	got := make([]byte, 64)
	Blake3DeriveKey(got, ctx, key)

	want := make([]byte, 64)
	blake3.DeriveKey(want, ctx, key)

	if !bytes.Equal(got, want) {
		t.Fatalf("derive key mismatch for invalid UTF-8 context")
	}
}
