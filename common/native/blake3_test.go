package native

import (
	"bytes"
	"testing"

	"lukechampine.com/blake3"
)

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
