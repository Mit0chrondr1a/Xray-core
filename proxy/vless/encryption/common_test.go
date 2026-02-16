package encryption

import (
	"bytes"
	"testing"
)

// --- EncodeHeader / DecodeHeader ---

func TestEncodeDecodeHeaderRoundTrip(t *testing.T) {
	tests := []struct {
		name   string
		length int
		valid  bool
	}{
		{"min valid", 17, true},
		{"typical", 1024, true},
		{"max valid", 17000, true},
		{"too small", 16, false},
		{"too large", 17001, false},
		{"zero", 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := make([]byte, 5)
			EncodeHeader(h, tt.length)
			l, err := DecodeHeader(h)
			if tt.valid {
				if err != nil {
					t.Fatalf("expected no error for length %d, got %v", tt.length, err)
				}
				if l != tt.length {
					t.Fatalf("DecodeHeader: got %d, want %d", l, tt.length)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error for length %d", tt.length)
				}
			}
		})
	}
}

func TestDecodeHeaderInvalidPrefix(t *testing.T) {
	// Valid header prefix is [23, 3, 3, ...]
	h := []byte{22, 3, 3, 0, 100}
	_, err := DecodeHeader(h)
	if err == nil {
		t.Fatal("expected error for invalid header prefix byte 0")
	}
	h = []byte{23, 4, 3, 0, 100}
	_, err = DecodeHeader(h)
	if err == nil {
		t.Fatal("expected error for invalid header prefix byte 1")
	}
	h = []byte{23, 3, 4, 0, 100}
	_, err = DecodeHeader(h)
	if err == nil {
		t.Fatal("expected error for invalid header prefix byte 2")
	}
}

// --- EncodeLength / DecodeLength ---

func TestEncodeLengthRoundTrip(t *testing.T) {
	tests := []int{0, 1, 255, 256, 1024, 65535}
	for _, l := range tests {
		encoded := EncodeLength(l)
		got := DecodeLength(encoded)
		if got != l {
			t.Errorf("DecodeLength(EncodeLength(%d)) = %d", l, got)
		}
	}
}

// --- IncreaseNonce ---

func TestIncreaseNonce(t *testing.T) {
	nonce := make([]byte, 12)
	IncreaseNonce(nonce)
	if nonce[11] != 1 {
		t.Fatalf("first increment: got %x, want ...01", nonce)
	}
	IncreaseNonce(nonce)
	if nonce[11] != 2 {
		t.Fatalf("second increment: got %x, want ...02", nonce)
	}
}

func TestIncreaseNonceOverflow(t *testing.T) {
	nonce := make([]byte, 12)
	nonce[11] = 0xff
	IncreaseNonce(nonce)
	if nonce[11] != 0 || nonce[10] != 1 {
		t.Fatalf("overflow increment: got %x, expected carry", nonce)
	}
}

func TestIncreaseNonceMaxNonce(t *testing.T) {
	nonce := make([]byte, 12)
	copy(nonce, MaxNonce)
	IncreaseNonce(nonce)
	// All bytes should be 0 after wrapping from MaxNonce.
	expected := make([]byte, 12)
	if !bytes.Equal(nonce, expected) {
		t.Fatalf("max nonce wrap: got %x, want all zeros", nonce)
	}
}

// --- MaxNonce ---

func TestMaxNonce(t *testing.T) {
	if len(MaxNonce) != 12 {
		t.Fatalf("MaxNonce len=%d, want 12", len(MaxNonce))
	}
	for i, b := range MaxNonce {
		if b != 0xff {
			t.Fatalf("MaxNonce[%d]=%d, want 255", i, b)
		}
	}
}

// --- NewAEAD ---

func TestNewAEADChacha20(t *testing.T) {
	aead := NewAEAD([]byte("test context"), []byte("test key material 1234567890abc"), false)
	if aead == nil {
		t.Fatal("NewAEAD(chacha20) returned nil")
	}
	if aead.NonceSize() != 12 {
		t.Fatalf("nonce size=%d, want 12", aead.NonceSize())
	}
}

func TestNewAEADAES(t *testing.T) {
	aead := NewAEAD([]byte("test context"), []byte("test key material 1234567890abc"), true)
	if aead == nil {
		t.Fatal("NewAEAD(aes) returned nil")
	}
	if aead.NonceSize() != 12 {
		t.Fatalf("nonce size=%d, want 12", aead.NonceSize())
	}
}

// --- AEAD Seal / Open Round Trip ---

func TestAEADSealOpenRoundTrip(t *testing.T) {
	aead := NewAEAD([]byte("ctx"), []byte("key1234567890abcdef"), false)
	peerAEAD := NewAEAD([]byte("ctx"), []byte("key1234567890abcdef"), false)

	plaintext := []byte("secret message payload")
	aad := []byte{23, 3, 3, 0, 38}

	ciphertext := aead.Seal(nil, nil, plaintext, aad)
	decrypted, err := peerAEAD.Open(nil, nil, ciphertext, aad)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestAEADSealOpenAES(t *testing.T) {
	aead := NewAEAD([]byte("ctx"), []byte("key1234567890abcdef"), true)
	peerAEAD := NewAEAD([]byte("ctx"), []byte("key1234567890abcdef"), true)

	plaintext := []byte("aes gcm payload")
	ciphertext := aead.Seal(nil, nil, plaintext, nil)
	decrypted, err := peerAEAD.Open(nil, nil, ciphertext, nil)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("decrypted data mismatch")
	}
}

func TestAEADTamperedCiphertextFails(t *testing.T) {
	aead := NewAEAD([]byte("ctx"), []byte("key"), false)
	peerAEAD := NewAEAD([]byte("ctx"), []byte("key"), false)

	plaintext := []byte("important data")
	ciphertext := aead.Seal(nil, nil, plaintext, nil)
	// Tamper with one byte.
	ciphertext[0] ^= 0xff
	_, err := peerAEAD.Open(nil, nil, ciphertext, nil)
	if err == nil {
		t.Fatal("Open should fail on tampered ciphertext")
	}
}

// --- ParsePadding ---

func TestParsePaddingEmpty(t *testing.T) {
	var lens, gaps [][3]int
	err := ParsePadding("", &lens, &gaps)
	if err != nil {
		t.Fatalf("empty padding should not error: %v", err)
	}
	if len(lens) != 0 || len(gaps) != 0 {
		t.Fatal("empty padding should produce no lens/gaps")
	}
}

func TestParsePaddingValid(t *testing.T) {
	var lens, gaps [][3]int
	err := ParsePadding("100-111-1111.75-0-111.50-0-3333", &lens, &gaps)
	if err != nil {
		t.Fatalf("valid padding: %v", err)
	}
	if len(lens) != 2 {
		t.Fatalf("expected 2 padding lengths, got %d", len(lens))
	}
	if len(gaps) != 1 {
		t.Fatalf("expected 1 padding gap, got %d", len(gaps))
	}
}

func TestParsePaddingInvalid(t *testing.T) {
	var lens, gaps [][3]int
	err := ParsePadding("invalid", &lens, &gaps)
	if err == nil {
		t.Fatal("expected error for invalid padding string")
	}
}

func TestParsePaddingFirstTooSmall(t *testing.T) {
	var lens, gaps [][3]int
	// First padding length minimum is 35 (18+17).
	err := ParsePadding("100-10-10", &lens, &gaps)
	if err == nil {
		t.Fatal("expected error when first padding length < 35")
	}
}

// --- CreatPadding ---

func TestCreatPaddingDefault(t *testing.T) {
	length, lens, gaps := CreatPadding(nil, nil)
	// With default parameters, length should be non-negative.
	if length < 0 {
		t.Fatalf("negative padding length: %d", length)
	}
	if len(lens) == 0 {
		t.Fatal("expected non-empty padding lens from default")
	}
	_ = gaps
}
