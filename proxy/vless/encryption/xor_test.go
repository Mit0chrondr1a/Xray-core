package encryption

import (
	"bytes"
	"net"
	"testing"
)

// connPair creates a pair of connected net.Conn using net.Pipe.
func connPair() (net.Conn, net.Conn) {
	return net.Pipe()
}

func TestNewCTR(t *testing.T) {
	key := []byte("test-key-material-for-ctr")
	iv := make([]byte, aesBlockSize())
	stream := NewCTR(key, iv)
	if stream == nil {
		t.Fatal("NewCTR returned nil")
	}
}

func aesBlockSize() int {
	return 16 // AES block size is always 16
}

func TestXorConnWriteReadRoundTrip(t *testing.T) {
	client, server := connPair()
	defer client.Close()
	defer server.Close()

	// Create matching CTR streams for both ends
	key := []byte("shared-secret-key-material-12345")
	iv := make([]byte, 16)

	// Client write CTR = Server read CTR (peerCTR)
	clientWriteCTR := NewCTR(key, iv)
	serverReadCTR := NewCTR(key, iv)

	// Server write CTR = Client read CTR
	key2 := []byte("shared-secret-key-material-67890")
	serverWriteCTR := NewCTR(key2, iv)
	clientReadCTR := NewCTR(key2, iv)

	xorClient := NewXorConn(client, clientWriteCTR, clientReadCTR, 0, 0)
	xorServer := NewXorConn(server, serverWriteCTR, serverReadCTR, 0, 0)

	// Build a valid TLS record header for the XOR conn to process
	payload := []byte("hello xor conn")
	record := make([]byte, 0, 5+len(payload))
	record = append(record, 23, 3, 3, byte(len(payload)>>8), byte(len(payload)))
	record = append(record, payload...)

	type readResult struct {
		data []byte
		err  error
	}
	resCh := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 1024)
		n, err := xorServer.Read(buf)
		resCh <- readResult{data: buf[:n], err: err}
	}()

	// Save a copy before writing — XorConn.Write modifies the buffer in-place.
	original := make([]byte, len(record))
	copy(original, record)

	_, err := xorClient.Write(record)
	if err != nil {
		t.Fatalf("Write: %v", err)
	}

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Read: %v", res.err)
	}
	if len(res.data) != len(original) {
		t.Fatalf("Read length: got %d, want %d", len(res.data), len(original))
	}
	// Verify the decrypted content matches the original record.
	if !bytes.Equal(res.data, original) {
		t.Fatalf("Read data mismatch: got %x, want %x", res.data[:min(16, len(res.data))], original[:min(16, len(original))])
	}
}

func TestXorConnWriteEmpty(t *testing.T) {
	client, server := connPair()
	defer client.Close()
	defer server.Close()

	key := []byte("key-material")
	iv := make([]byte, 16)
	ctr := NewCTR(key, iv)
	peerCTR := NewCTR(key, iv)

	xc := NewXorConn(client, ctr, peerCTR, 0, 0)
	n, err := xc.Write(nil)
	if err != nil {
		t.Fatalf("Write(nil): %v", err)
	}
	if n != 0 {
		t.Fatalf("Write(nil) returned %d, want 0", n)
	}

	n, err = xc.Write([]byte{})
	if err != nil {
		t.Fatalf("Write(empty): %v", err)
	}
	if n != 0 {
		t.Fatalf("Write(empty) returned %d, want 0", n)
	}
}

func TestXorConnReadEmpty(t *testing.T) {
	client, server := connPair()
	defer client.Close()
	defer server.Close()

	key := []byte("key-material")
	iv := make([]byte, 16)
	ctr := NewCTR(key, iv)
	peerCTR := NewCTR(key, iv)

	xc := NewXorConn(client, ctr, peerCTR, 0, 0)
	n, err := xc.Read(nil)
	if err != nil {
		t.Fatalf("Read(nil): %v", err)
	}
	if n != 0 {
		t.Fatalf("Read(nil) returned %d, want 0", n)
	}

	n, err = xc.Read([]byte{})
	if err != nil {
		t.Fatalf("Read(empty): %v", err)
	}
	if n != 0 {
		t.Fatalf("Read(empty) returned %d, want 0", n)
	}
}

func TestNewXorConnDefaults(t *testing.T) {
	client, server := connPair()
	defer client.Close()
	defer server.Close()

	key := []byte("key-material")
	iv := make([]byte, 16)
	ctr := NewCTR(key, iv)
	peerCTR := NewCTR(key, iv)

	xc := NewXorConn(client, ctr, peerCTR, 10, 20)
	if xc.OutSkip != 10 {
		t.Fatalf("OutSkip=%d, want 10", xc.OutSkip)
	}
	if xc.InSkip != 20 {
		t.Fatalf("InSkip=%d, want 20", xc.InSkip)
	}
	if cap(xc.OutHeader) != 5 {
		t.Fatalf("OutHeader cap=%d, want 5", cap(xc.OutHeader))
	}
	if cap(xc.InHeader) != 5 {
		t.Fatalf("InHeader cap=%d, want 5", cap(xc.InHeader))
	}
}

func TestEncodeLengthDecodeLength(t *testing.T) {
	// Test EncodeLength/DecodeLength round trip for various values
	tests := []int{0, 1, 255, 256, 1024, 65535}
	for _, l := range tests {
		encoded := EncodeLength(l)
		got := DecodeLength(encoded)
		if got != l {
			t.Errorf("DecodeLength(EncodeLength(%d)) = %d", l, got)
		}
	}
}

func TestCommonConnType(t *testing.T) {
	// Verify CommonConn wraps net.Conn
	client, server := connPair()
	defer client.Close()
	defer server.Close()

	cc := &CommonConn{Conn: client}
	if cc.Conn != client {
		t.Fatal("CommonConn.Conn not set correctly")
	}
}

func TestOutBytesPoolReturnsCorrectSize(t *testing.T) {
	b := OutBytesPool.Get().([]byte)
	expectedSize := 5 + 8192 + 16
	if len(b) != expectedSize {
		t.Fatalf("pool buffer len=%d, want %d", len(b), expectedSize)
	}
	OutBytesPool.Put(b)
}

func TestEncodeDecodeHeaderRoundTripBoundary(t *testing.T) {
	// Test exact boundary values
	tests := []struct {
		name   string
		length int
		valid  bool
	}{
		{"exactly 17", 17, true},
		{"exactly 17000", 17000, true},
		{"16 (below minimum)", 16, false},
		{"17001 (above maximum)", 17001, false},
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

// Ensure the AEAD returned by NewAEAD is usable for encrypt/decrypt
func TestNewAEADConsistency(t *testing.T) {
	ctx := []byte("test-context")
	key := []byte("test-key-material-1234567890abc")

	a1 := NewAEAD(ctx, key, false) // ChaCha20
	a2 := NewAEAD(ctx, key, true)  // AES-GCM

	if a1 == nil || a2 == nil {
		t.Fatal("NewAEAD returned nil")
	}

	// They should produce different ciphertexts for the same plaintext
	plaintext := []byte("test data")
	ct1 := a1.Seal(nil, nil, plaintext, nil)
	ct2 := a2.Seal(nil, nil, plaintext, nil)

	if bytes.Equal(ct1, ct2) {
		t.Fatal("ChaCha20 and AES-GCM produced identical ciphertexts")
	}
}
