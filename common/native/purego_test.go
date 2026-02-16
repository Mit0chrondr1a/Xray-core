// Tests for the pure-Go fallback implementations in native package.
// These tests must pass with CGO_ENABLED=0.
package native

import (
	"bytes"
	"testing"

	"lukechampine.com/blake3"
)

// --- Available / EbpfAvailable ---

func TestAvailable(t *testing.T) {
	// On non-CGO builds, Available() should be false.
	// On CGO builds, it should be true.
	// Either way, it must not panic.
	_ = Available()
}

func TestEbpfAvailable(t *testing.T) {
	// Must not panic regardless of build mode.
	_ = EbpfAvailable()
}

// --- Blake3 Fallback Verification ---

func TestBlake3Sum256MatchesPureGo(t *testing.T) {
	data := []byte("The quick brown fox jumps over the lazy dog")
	got := Blake3Sum256(data)
	want := blake3.Sum256(data)
	if got != want {
		t.Fatalf("Blake3Sum256 mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestBlake3Sum256Empty(t *testing.T) {
	got := Blake3Sum256(nil)
	want := blake3.Sum256(nil)
	if got != want {
		t.Fatalf("Blake3Sum256(nil) mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestBlake3DeriveKeyMatchesPureGo(t *testing.T) {
	ctx := "xray-core test context"
	key := []byte("test-key-material-1234567890")

	got := make([]byte, 32)
	Blake3DeriveKey(got, ctx, key)

	want := make([]byte, 32)
	blake3.DeriveKey(want, ctx, key)

	if !bytes.Equal(got, want) {
		t.Fatalf("Blake3DeriveKey mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestBlake3DeriveKeyEmptyOutput(t *testing.T) {
	// Should not panic.
	Blake3DeriveKey(nil, "ctx", []byte("key"))
	Blake3DeriveKey([]byte{}, "ctx", []byte("key"))
}

func TestBlake3DeriveKeyEmptyKey(t *testing.T) {
	got := make([]byte, 32)
	Blake3DeriveKey(got, "test-ctx", nil)

	want := make([]byte, 32)
	blake3.DeriveKey(want, "test-ctx", nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("Blake3DeriveKey(nil key) mismatch")
	}
}

func TestBlake3KeyedHash(t *testing.T) {
	key := [32]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
		17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32}
	data := []byte("test keyed hash data")

	got := Blake3KeyedHash(&key, data, 32)

	h := blake3.New(32, key[:])
	h.Write(data)
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("Blake3KeyedHash mismatch:\n  got:  %x\n  want: %x", got, want)
	}
}

func TestBlake3KeyedHashZeroLen(t *testing.T) {
	key := [32]byte{}
	got := Blake3KeyedHash(&key, []byte("data"), 0)
	if got != nil {
		t.Fatalf("Blake3KeyedHash(outLen=0) should return nil, got %v", got)
	}
}

func TestBlake3KeyedHashNegativeLen(t *testing.T) {
	key := [32]byte{}
	got := Blake3KeyedHash(&key, []byte("data"), -1)
	if got != nil {
		t.Fatalf("Blake3KeyedHash(outLen=-1) should return nil, got %v", got)
	}
}

func TestBlake3KeyedHashEmptyData(t *testing.T) {
	key := [32]byte{0xFF}
	got := Blake3KeyedHash(&key, nil, 16)

	h := blake3.New(16, key[:])
	want := h.Sum(nil)

	if !bytes.Equal(got, want) {
		t.Fatalf("Blake3KeyedHash(nil data) mismatch")
	}
}

// --- TlsResult.ZeroSecrets ---

func TestTlsResultZeroSecrets(t *testing.T) {
	r := &TlsResult{
		TxSecret: []byte{0x01, 0x02, 0x03},
		RxSecret: []byte{0x04, 0x05, 0x06},
	}
	// Save copies to check zeroing.
	txCopy := append([]byte(nil), r.TxSecret...)
	rxCopy := append([]byte(nil), r.RxSecret...)
	_ = txCopy
	_ = rxCopy

	r.ZeroSecrets()

	if r.TxSecret != nil {
		t.Fatal("TxSecret should be nil after ZeroSecrets")
	}
	if r.RxSecret != nil {
		t.Fatal("RxSecret should be nil after ZeroSecrets")
	}
}

func TestTlsResultZeroSecretsEmpty(t *testing.T) {
	r := &TlsResult{}
	r.ZeroSecrets() // Should not panic with nil slices.
	if r.TxSecret != nil || r.RxSecret != nil {
		t.Fatal("secrets should remain nil")
	}
}

// --- VisionUnpadState ---

func TestNewVisionUnpadState(t *testing.T) {
	s := NewVisionUnpadState()
	if s == nil {
		t.Fatal("NewVisionUnpadState returned nil")
	}
	if s.RemainingCommand != -1 {
		t.Fatalf("RemainingCommand=%d, want -1", s.RemainingCommand)
	}
	if s.RemainingContent != -1 {
		t.Fatalf("RemainingContent=%d, want -1", s.RemainingContent)
	}
	if s.RemainingPadding != -1 {
		t.Fatalf("RemainingPadding=%d, want -1", s.RemainingPadding)
	}
	if s.CurrentCommand != 0 {
		t.Fatalf("CurrentCommand=%d, want 0", s.CurrentCommand)
	}
}

// --- Stub Functions (should return errors on non-CGO) ---

func TestMphStubsReturnNil(t *testing.T) {
	if !Available() {
		// Pure Go: stubs should return nil/false.
		h := MphNew()
		if h != nil {
			t.Fatal("MphNew should return nil in pure Go mode")
		}
		// These should not panic on nil handle.
		MphAddPattern(h, "test", 0)
		MphBuild(h)
		if MphMatch(h, "test") {
			t.Fatal("MphMatch should return false in pure Go mode")
		}
		MphFree(h)
	}
}

func TestIpSetStubsReturnNil(t *testing.T) {
	if !Available() {
		h := IpSetNew()
		if h != nil {
			t.Fatal("IpSetNew should return nil in pure Go mode")
		}
		IpSetAddPrefix(h, []byte{1, 2, 3, 4}, 24)
		IpSetBuild(h)
		if IpSetContains(h, []byte{1, 2, 3, 4}) {
			t.Fatal("IpSetContains should return false in pure Go mode")
		}
		IpSetFree(h)
	}
}

func TestAeadStubsReturnNil(t *testing.T) {
	if !Available() {
		h := AeadNew(AeadAes128Gcm, []byte("0123456789abcdef"))
		if h != nil {
			t.Fatal("AeadNew should return nil in pure Go mode")
		}
		_, err := AeadSeal(h, nil, nil, nil)
		if err == nil {
			t.Fatal("AeadSeal should return error for nil handle")
		}
		_, err = AeadOpen(h, nil, nil, nil)
		if err == nil {
			t.Fatal("AeadOpen should return error for nil handle")
		}
	}
}

func TestEbpfStubsReturnError(t *testing.T) {
	if !Available() {
		if err := EbpfSetup("/tmp/test", 1024, 0); err == nil {
			t.Fatal("EbpfSetup should return error in pure Go mode")
		}
		if err := EbpfTeardown(); err == nil {
			t.Fatal("EbpfTeardown should return error in pure Go mode")
		}
		if err := EbpfRegisterPair(0, 1, 0, 1, 0); err == nil {
			t.Fatal("EbpfRegisterPair should return error in pure Go mode")
		}
		if err := EbpfUnregisterPair(0, 1); err == nil {
			t.Fatal("EbpfUnregisterPair should return error in pure Go mode")
		}
	}
}

func TestVMessHeaderStubs(t *testing.T) {
	if !Available() {
		_, err := VMessSealHeader([16]byte{}, []byte("header"))
		if err == nil {
			t.Fatal("VMessSealHeader should return error in pure Go mode")
		}
		_, err = VMessOpenHeader([16]byte{}, [16]byte{}, []byte("data1234567890123456789012345678901234567890123456"))
		if err == nil {
			t.Fatal("VMessOpenHeader should return error in pure Go mode")
		}
	}
}

func TestGeoDataStubs(t *testing.T) {
	if !Available() {
		_, err := GeoIPLoad("/nonexistent/geoip.dat", []string{"US"})
		if err == nil {
			t.Fatal("GeoIPLoad should return error in pure Go mode")
		}
		_, err = GeoSiteLoad("/nonexistent/geosite.dat", []string{"google"})
		if err == nil {
			t.Fatal("GeoSiteLoad should return error in pure Go mode")
		}
	}
}

func TestVisionPadStub(t *testing.T) {
	if !Available() {
		out := make([]byte, 1024)
		_, err := VisionPad([]byte("data"), 0x01, []byte("uuid1234567890AB"), false, [4]uint32{}, out)
		if err == nil {
			t.Fatal("VisionPad should return error in pure Go mode")
		}
	}
}

func TestVisionUnpadStub(t *testing.T) {
	if !Available() {
		state := NewVisionUnpadState()
		out := make([]byte, 1024)
		_, err := VisionUnpad([]byte("data"), state, []byte("uuid1234567890AB"), out)
		if err == nil {
			t.Fatal("VisionUnpad should return error in pure Go mode")
		}
	}
}

// --- AEAD Constants ---

func TestAeadConstants(t *testing.T) {
	if AeadAes128Gcm != 0 {
		t.Fatalf("AeadAes128Gcm=%d, want 0", AeadAes128Gcm)
	}
	if AeadAes256Gcm != 1 {
		t.Fatalf("AeadAes256Gcm=%d, want 1", AeadAes256Gcm)
	}
	if AeadChacha20Poly1305 != 2 {
		t.Fatalf("AeadChacha20Poly1305=%d, want 2", AeadChacha20Poly1305)
	}
}
