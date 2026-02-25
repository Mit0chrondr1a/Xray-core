package proxy

import (
	"context"
	"math"
	"testing"

	"github.com/xtls/xray-core/common/buf"
)

// ---------------------------------------------------------------------------
// cryptoRandIntn: direct tests
// ---------------------------------------------------------------------------

func TestCryptoRandIntn_ZeroReturnsZero(t *testing.T) {
	// n=0 is the most critical edge case. The old code using big.Int would
	// panic here (crypto/rand.Int panics on max<=0). The new code must
	// return 0 without panic.
	for i := 0; i < 100; i++ {
		got := cryptoRandIntn(0)
		if got != 0 {
			t.Fatalf("cryptoRandIntn(0) = %d, want 0", got)
		}
	}
}

func TestCryptoRandIntn_OneAlwaysReturnsZero(t *testing.T) {
	// n=1: the only valid result is 0 (the range [0, 1) contains only 0).
	for i := 0; i < 100; i++ {
		got := cryptoRandIntn(1)
		if got != 0 {
			t.Fatalf("cryptoRandIntn(1) = %d, want 0", got)
		}
	}
}

func TestCryptoRandIntn_ResultInRange(t *testing.T) {
	// For several values of n, verify that results are in [0, n).
	testValues := []uint32{2, 3, 10, 100, 256, 500, 900, 1000, 65535, math.MaxUint16, math.MaxUint32}
	for _, n := range testValues {
		for i := 0; i < 200; i++ {
			got := cryptoRandIntn(n)
			if got < 0 || got >= int64(n) {
				t.Fatalf("cryptoRandIntn(%d) = %d, out of range [0, %d)", n, got, n)
			}
		}
	}
}

func TestCryptoRandIntn_ReturnTypeIsInt64(t *testing.T) {
	// The return type must be int64 to match the contract expected by
	// xtlsPaddingGoFallback (which casts to int32).
	var result int64 = cryptoRandIntn(256)
	_ = result // compile-time type check
}

func TestCryptoRandIntn_SmallN_NotAlwaysSameValue(t *testing.T) {
	// For n=256, over 100 calls we should see more than one distinct value.
	// This is a statistical test; failure probability is (1/256)^99 which
	// is effectively zero.
	seen := make(map[int64]bool)
	for i := 0; i < 100; i++ {
		seen[cryptoRandIntn(256)] = true
	}
	if len(seen) < 2 {
		t.Fatalf("cryptoRandIntn(256) returned only %d distinct values over 100 calls; RNG appears stuck", len(seen))
	}
}

func TestCryptoRandIntn_LargeN_NotAlwaysZero(t *testing.T) {
	// For n=MaxUint32, results should not all be zero.
	allZero := true
	for i := 0; i < 50; i++ {
		if cryptoRandIntn(math.MaxUint32) != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("cryptoRandIntn(MaxUint32) returned 0 for 50 consecutive calls; RNG appears broken")
	}
}

func TestCryptoRandIntn_MaxUint32(t *testing.T) {
	// n = MaxUint32: result must be in [0, MaxUint32).
	for i := 0; i < 100; i++ {
		got := cryptoRandIntn(math.MaxUint32)
		if got < 0 || got >= math.MaxUint32 {
			t.Fatalf("cryptoRandIntn(MaxUint32) = %d, out of range", got)
		}
	}
}

// ---------------------------------------------------------------------------
// xtlsPaddingGoFallback: edge case tests
// ---------------------------------------------------------------------------

func TestXtlsPaddingGoFallback_NilBuffer_CommandEnd(t *testing.T) {
	uuid := []byte("0123456789ABCDEF")
	testseed := []uint32{900, 500, 900, 256}
	result := xtlsPaddingGoFallback(nil, CommandPaddingEnd, &uuid, false, context.Background(), testseed)
	if result == nil {
		t.Fatal("xtlsPaddingGoFallback returned nil for nil input buffer")
	}
	// With nil buffer, contentLen=0. For longPadding=false, paddingLen = rand(256).
	// The output should contain: 5 header bytes + 0 content bytes + paddingLen bytes.
	// Minimum possible: 5 bytes (paddingLen=0).
	if result.Len() < 5 {
		t.Fatalf("result too short: %d bytes, minimum 5 (header)", result.Len())
	}
	// UUID was consumed (set to nil).
	if uuid != nil {
		t.Fatal("userUUID should be nil after xtlsPaddingGoFallback")
	}
	// Verify header: command byte at offset 0 (after UUID was written)
	// Since uuid was nil-check passed and written, header starts after UUID.
	result.Release()
}

func TestXtlsPaddingGoFallback_NilUUID(t *testing.T) {
	b := buf.New()
	b.Write([]byte("test"))
	testseed := []uint32{900, 500, 900, 256}
	result := xtlsPaddingGoFallback(b, CommandPaddingEnd, nil, false, context.Background(), testseed)
	if result == nil {
		t.Fatal("xtlsPaddingGoFallback returned nil with nil UUID pointer")
	}
	// Without UUID, first 5 bytes should be the header.
	if result.Len() < 5+4 { // 5 header + 4 content minimum
		t.Fatalf("result too short: %d", result.Len())
	}
	result.Release()
}

func TestXtlsPaddingGoFallback_LongPadding_ShortContent(t *testing.T) {
	// When contentLen < testseed[0] and longPadding=true, the padding formula is:
	//   paddingLen = rand(testseed[1]) + testseed[2] - contentLen
	// With testseed = {900, 500, 900, 256} and contentLen=10:
	//   paddingLen = rand(500) + 900 - 10 = rand(500) + 890
	// So paddingLen should be in [890, 1389].
	b := buf.New()
	content := make([]byte, 10)
	b.Write(content)
	testseed := []uint32{900, 500, 900, 256}
	result := xtlsPaddingGoFallback(b, CommandPaddingContinue, nil, true, context.Background(), testseed)
	if result == nil {
		t.Fatal("returned nil")
	}
	// Total = 5 (header) + 10 (content) + paddingLen
	// paddingLen in [890, 1389], but capped at buf.Size-21-contentLen = 8192-21-10 = 8161
	totalLen := result.Len()
	minExpected := int32(5 + 10 + 890)
	maxExpected := int32(5 + 10 + 1389)
	if totalLen < minExpected || totalLen > maxExpected {
		t.Fatalf("total length %d not in expected range [%d, %d]", totalLen, minExpected, maxExpected)
	}
	result.Release()
}

func TestXtlsPaddingGoFallback_LongPadding_ContentAtThreshold(t *testing.T) {
	// When contentLen == testseed[0] (900), longPadding branch should NOT fire.
	// Instead: paddingLen = rand(testseed[3]) = rand(256).
	b := buf.New()
	content := make([]byte, 900)
	b.Write(content)
	testseed := []uint32{900, 500, 900, 256}
	result := xtlsPaddingGoFallback(b, CommandPaddingEnd, nil, true, context.Background(), testseed)
	if result == nil {
		t.Fatal("returned nil")
	}
	// Total = 5 + 900 + paddingLen, where paddingLen in [0, 255]
	totalLen := result.Len()
	minExpected := int32(5 + 900 + 0)
	maxExpected := int32(5 + 900 + 255)
	if totalLen < minExpected || totalLen > maxExpected {
		t.Fatalf("total length %d not in expected range [%d, %d] (threshold boundary)", totalLen, minExpected, maxExpected)
	}
	result.Release()
}

func TestXtlsPaddingGoFallback_PaddingCappedAtBufferLimit(t *testing.T) {
	// Fill a buffer near buf.Size to force the padding cap.
	// buf.Size = 8192. The cap is: buf.Size - 21 - contentLen.
	// If contentLen = 8100, cap = 8192 - 21 - 8100 = 71.
	// With longPadding=false, paddingLen = rand(256), which could be > 71.
	// After capping: paddingLen should be <= 71.
	b := buf.New()
	content := make([]byte, buf.Size-100) // 8092 bytes
	b.Write(content)
	testseed := []uint32{900, 500, 900, 256}
	result := xtlsPaddingGoFallback(b, CommandPaddingEnd, nil, false, context.Background(), testseed)
	if result == nil {
		t.Fatal("returned nil")
	}
	cap := buf.Size - 21 - int32(len(content))
	maxAllowed := int32(5) + int32(len(content)) + cap
	if result.Len() > maxAllowed {
		t.Fatalf("result length %d exceeds buffer cap %d", result.Len(), maxAllowed)
	}
	result.Release()
}

func TestXtlsPaddingGoFallback_HeaderEncoding(t *testing.T) {
	// Verify the 5-byte header is correctly encoded as:
	//   [command, contentLen_hi, contentLen_lo, paddingLen_hi, paddingLen_lo]
	// Use a known content length and parse the header.
	content := make([]byte, 300) // 0x012C
	for i := range content {
		content[i] = byte(i % 256)
	}
	b := buf.New()
	b.Write(content)
	testseed := []uint32{900, 500, 900, 256}
	result := xtlsPaddingGoFallback(b, CommandPaddingDirect, nil, false, context.Background(), testseed)
	if result == nil {
		t.Fatal("returned nil")
	}

	raw := result.Bytes()
	// Header at bytes [0..4]
	if raw[0] != CommandPaddingDirect {
		t.Fatalf("header[0] = 0x%02x, want 0x%02x (CommandPaddingDirect)", raw[0], CommandPaddingDirect)
	}
	contentLenEncoded := int32(raw[1])<<8 | int32(raw[2])
	if contentLenEncoded != 300 {
		t.Fatalf("header content length = %d, want 300", contentLenEncoded)
	}
	paddingLenEncoded := int32(raw[3])<<8 | int32(raw[4])
	if paddingLenEncoded < 0 || paddingLenEncoded >= 256 {
		t.Fatalf("header padding length = %d, expected in [0, 256)", paddingLenEncoded)
	}
	// Verify total length matches header claims.
	expectedTotal := int32(5) + 300 + paddingLenEncoded
	if result.Len() != expectedTotal {
		t.Fatalf("total length %d != 5 + %d + %d = %d", result.Len(), 300, paddingLenEncoded, expectedTotal)
	}
	// Verify content is preserved after header.
	for i := 0; i < 300; i++ {
		if raw[5+i] != byte(i%256) {
			t.Fatalf("content byte %d = 0x%02x, want 0x%02x", i, raw[5+i], byte(i%256))
		}
	}
	result.Release()
}

func TestXtlsPaddingGoFallback_RoundTrip_AllCommands(t *testing.T) {
	// Verify pad/unpad round-trip for each command type.
	commands := []struct {
		cmd  byte
		name string
	}{
		{CommandPaddingContinue, "Continue"},
		{CommandPaddingEnd, "End"},
		{CommandPaddingDirect, "Direct"},
	}
	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			uuid := []byte("0123456789ABCDEF")
			uuidForUnpad := make([]byte, 16)
			copy(uuidForUnpad, uuid)

			plaintext := []byte("payload-for-" + tc.name)
			b := buf.New()
			b.Write(plaintext)

			uuidCopy := make([]byte, 16)
			copy(uuidCopy, uuid)
			testseed := []uint32{900, 500, 900, 256}
			padded := xtlsPaddingGoFallback(b, tc.cmd, &uuidCopy, false, context.Background(), testseed)
			if padded == nil {
				t.Fatal("padding returned nil")
			}

			ts := NewTrafficState(uuidForUnpad)
			unpadded := XtlsUnpadding(padded, ts, true, context.Background())
			if unpadded == nil {
				t.Fatal("unpadding returned nil")
			}
			got := string(unpadded.Bytes())
			if got != string(plaintext) {
				t.Fatalf("round-trip failed for command %s:\n  got:  %q\n  want: %q", tc.name, got, string(plaintext))
			}
			unpadded.Release()
		})
	}
}

func TestXtlsPaddingGoFallback_EmptyContent(t *testing.T) {
	// Empty buffer (not nil) should still produce valid padded output.
	b := buf.New() // 0 bytes written
	testseed := []uint32{900, 500, 900, 256}
	result := xtlsPaddingGoFallback(b, CommandPaddingEnd, nil, false, context.Background(), testseed)
	if result == nil {
		t.Fatal("returned nil for empty buffer")
	}
	if result.Len() < 5 {
		t.Fatalf("result too short for empty content: %d", result.Len())
	}
	// Verify content length in header is 0.
	raw := result.Bytes()
	contentLen := int32(raw[0+1])<<8 | int32(raw[0+2]) // skip command byte
	if contentLen != 0 {
		t.Fatalf("header content length = %d, want 0 for empty buffer", contentLen)
	}
	result.Release()
}

func TestXtlsPaddingGoFallback_ZeroSeed(t *testing.T) {
	// If testseed[3] = 0, cryptoRandIntn(0) returns 0, so paddingLen = 0.
	b := buf.New()
	b.Write([]byte("data"))
	testseed := []uint32{900, 500, 900, 0}
	result := xtlsPaddingGoFallback(b, CommandPaddingEnd, nil, false, context.Background(), testseed)
	if result == nil {
		t.Fatal("returned nil")
	}
	// paddingLen should be 0 (since n=0 for cryptoRandIntn).
	// Total = 5 (header) + 4 (content) + 0 (padding) = 9.
	if result.Len() != 9 {
		raw := result.Bytes()
		paddingLen := int32(raw[3])<<8 | int32(raw[4])
		t.Fatalf("expected total length 9 (no padding), got %d (paddingLen=%d)", result.Len(), paddingLen)
	}
	result.Release()
}

func TestXtlsPaddingGoFallback_ZeroSeed_LongPadding(t *testing.T) {
	// testseed = {900, 0, 900, 256}, contentLen < 900, longPadding=true.
	// Formula: paddingLen = rand(0) + 900 - contentLen = 0 + 900 - 4 = 896.
	b := buf.New()
	b.Write([]byte("data"))
	testseed := []uint32{900, 0, 900, 256}
	result := xtlsPaddingGoFallback(b, CommandPaddingContinue, nil, true, context.Background(), testseed)
	if result == nil {
		t.Fatal("returned nil")
	}
	// paddingLen = 0 + 900 - 4 = 896. Total = 5 + 4 + 896 = 905.
	if result.Len() != 905 {
		t.Fatalf("expected total length 905, got %d", result.Len())
	}
	result.Release()
}

// ---------------------------------------------------------------------------
// Benchmark: cryptoRandIntn vs old approach
// ---------------------------------------------------------------------------

func BenchmarkCryptoRandIntn_256(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRandIntn(256)
	}
}

func BenchmarkCryptoRandIntn_500(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRandIntn(500)
	}
}

func BenchmarkCryptoRandIntn_MaxUint32(b *testing.B) {
	for i := 0; i < b.N; i++ {
		cryptoRandIntn(math.MaxUint32)
	}
}
