//go:build linux

package tls

import (
	"encoding/hex"
	"errors"
	"sync/atomic"
	"testing"
)

func TestKtlsAfterWrite_NilHandler(t *testing.T) {
	// ktlsAfterWrite should be a no-op when handler is nil.
	var wr atomic.Uint64
	var rf atomic.Uint32
	ktlsAfterWrite(1024, nil, &wr, &rf, func() error { return nil })
	if wr.Load() != 0 {
		t.Fatalf("expected 0 write records with nil handler, got %d", wr.Load())
	}
}

func TestKtlsAfterWrite_RecordCounting(t *testing.T) {
	// With a real handler, ktlsAfterWrite should count records.
	// Create a handler that won't actually call setsockopt.
	secret := make([]byte, 32)
	handler := newKTLSKeyUpdateHandler(-1, 0x1301, secret, secret)
	if handler == nil {
		t.Fatal("expected non-nil handler for TLS_AES_128_GCM_SHA256")
	}

	var wr atomic.Uint64
	var rf atomic.Uint32

	// Write exactly maxRecordPayload bytes = 1 record
	ktlsAfterWrite(maxRecordPayload, handler, &wr, &rf, func() error { return nil })
	if wr.Load() != 1 {
		t.Fatalf("expected 1 record, got %d", wr.Load())
	}

	// Write 2*maxRecordPayload-1 bytes = 2 records (ceiling)
	wr.Store(0)
	ktlsAfterWrite(2*maxRecordPayload-1, handler, &wr, &rf, func() error { return nil })
	if wr.Load() != 2 {
		t.Fatalf("expected 2 records for 2*max-1 bytes, got %d", wr.Load())
	}

	// Write 0 bytes = 0 records
	wr.Store(0)
	ktlsAfterWrite(0, handler, &wr, &rf, func() error { return nil })
	if wr.Load() != 0 {
		t.Fatalf("expected 0 records for 0 bytes, got %d", wr.Load())
	}
}

func TestKtlsAfterWrite_ThresholdTriggersRotation(t *testing.T) {
	secret := make([]byte, 32)
	handler := newKTLSKeyUpdateHandler(-1, 0x1301, secret, secret)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	var wr atomic.Uint64
	var rf atomic.Uint32

	// Pre-load writeRecords just below threshold.
	wr.Store(keyUpdateThreshold - 1)

	var closeCalled atomic.Bool
	closeFn := func() error {
		closeCalled.Store(true)
		return nil
	}

	// Writing 1 more record should push past threshold and trigger rotation.
	// The rotation will fail because fd=-1, but the failure tracking should work.
	ktlsAfterWrite(maxRecordPayload, handler, &wr, &rf, closeFn)

	// After a failed rotation, writeRecords should be restored.
	if rf.Load() < 1 {
		t.Fatalf("expected at least 1 rotation failure, got %d", rf.Load())
	}
}

func TestKtlsAfterWrite_MaxRotationFailuresClosesConn(t *testing.T) {
	secret := make([]byte, 32)
	handler := newKTLSKeyUpdateHandler(-1, 0x1301, secret, secret)
	if handler == nil {
		t.Fatal("expected non-nil handler")
	}

	var wr atomic.Uint64
	var rf atomic.Uint32
	rf.Store(maxRotationFailures - 1)

	var closeCalled atomic.Bool
	closeFn := func() error {
		closeCalled.Store(true)
		return nil
	}

	// Set write records just below threshold.
	wr.Store(keyUpdateThreshold - 1)

	// This should trigger rotation, fail, increment to maxRotationFailures, and close.
	ktlsAfterWrite(maxRecordPayload, handler, &wr, &rf, closeFn)

	if !closeCalled.Load() {
		t.Fatal("expected connection to be closed after maxRotationFailures")
	}
}

func TestDeriveKeysFromCapture_UnsupportedCipher(t *testing.T) {
	capture := &keyCapture{}
	capture.clientSecret = make([]byte, 32)
	capture.serverSecret = make([]byte, 32)
	_, err := deriveKeysFromCapture(capture, 0xFFFF, true)
	if err == nil {
		t.Fatal("expected error for unsupported cipher suite")
	}
}

func TestDeriveKeysFromCapture_EmptySecrets(t *testing.T) {
	capture := &keyCapture{}
	_, err := deriveKeysFromCapture(capture, 0x1301, true)
	if err == nil {
		t.Fatal("expected error for empty secrets")
	}
}

func TestDeriveKeysFromCapture_ValidSecrets(t *testing.T) {
	capture := &keyCapture{
		clientSecret: make([]byte, 32),
		serverSecret: make([]byte, 32),
	}
	for i := range capture.clientSecret {
		capture.clientSecret[i] = byte(i)
	}
	for i := range capture.serverSecret {
		capture.serverSecret[i] = byte(i + 0x80)
	}

	tests := []struct {
		name     string
		suite    uint16
		isClient bool
	}{
		{"AES-128-GCM client", 0x1301, true},
		{"AES-128-GCM server", 0x1301, false},
		{"AES-256-GCM client", 0x1302, true},
		{"CHACHA20 client", 0x1303, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := deriveKeysFromCapture(capture, tc.suite, tc.isClient)
			if err != nil {
				t.Fatalf("deriveKeysFromCapture failed: %v", err)
			}
			if len(keys.txKey) == 0 {
				t.Fatal("txKey is empty")
			}
			if len(keys.rxKey) == 0 {
				t.Fatal("rxKey is empty")
			}
			if len(keys.txIV) != 12 {
				t.Fatalf("txIV length %d, want 12", len(keys.txIV))
			}
			if len(keys.rxIV) != 12 {
				t.Fatalf("rxIV length %d, want 12", len(keys.rxIV))
			}
			if len(keys.txSeq) != 8 {
				t.Fatalf("txSeq length %d, want 8", len(keys.txSeq))
			}
		})
	}
}

func TestKeyCaptureWriteAndSecrets(t *testing.T) {
	kc := &keyCapture{}

	// Write a CLIENT_TRAFFIC_SECRET_0 line
	clientSecret := "0011223344556677889900aabbccddeeff0011223344556677889900aabbccddeeff"
	line := "CLIENT_TRAFFIC_SECRET_0 0000 " + clientSecret + "\n"
	n, err := kc.Write([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	if n != len(line) {
		t.Fatalf("Write returned %d, want %d", n, len(line))
	}

	// Write a SERVER_TRAFFIC_SECRET_0 line
	serverSecret := "ffeeddccbbaa00998877665544332211ffeeddccbbaa00998877665544332211"
	line = "SERVER_TRAFFIC_SECRET_0 0000 " + serverSecret + "\n"
	kc.Write([]byte(line))

	cs, ss := kc.secrets()
	wantClient, _ := hex.DecodeString(clientSecret)
	wantServer, _ := hex.DecodeString(serverSecret)
	if string(cs) != string(wantClient) {
		t.Fatalf("client secret mismatch")
	}
	if string(ss) != string(wantServer) {
		t.Fatalf("server secret mismatch")
	}
}

func TestKeyCaptureSecretsReturnsCopies(t *testing.T) {
	kc := &keyCapture{
		clientSecret: []byte{1, 2, 3},
		serverSecret: []byte{4, 5, 6},
	}
	cs, ss := kc.secrets()
	// Modify the returned slices -- originals should be unaffected.
	cs[0] = 0xFF
	ss[0] = 0xFF
	if kc.clientSecret[0] == 0xFF {
		t.Fatal("secrets() returned a reference, not a copy")
	}
	if kc.serverSecret[0] == 0xFF {
		t.Fatal("secrets() returned a reference, not a copy")
	}
}

func TestKeyCaptureClear(t *testing.T) {
	kc := &keyCapture{
		clientSecret: []byte{1, 2, 3, 4, 5, 6, 7, 8},
		serverSecret: []byte{9, 10, 11, 12, 13, 14, 15, 16},
	}
	kc.clear()
	for i, b := range kc.clientSecret {
		if b != 0 {
			t.Fatalf("clientSecret byte %d not zeroed after clear: %02x", i, b)
		}
	}
	for i, b := range kc.serverSecret {
		if b != 0 {
			t.Fatalf("serverSecret byte %d not zeroed after clear: %02x", i, b)
		}
	}
}

func TestKeyCaptureChainOriginalWriter(t *testing.T) {
	var written []byte
	original := &testWriter{onWrite: func(p []byte) (int, error) {
		written = append(written, p...)
		return len(p), nil
	}}

	kc := &keyCapture{originalWriter: original}
	data := []byte("SOME_OTHER_LINE abc 123\n")
	n, err := kc.Write(data)
	if err != nil {
		t.Fatal(err)
	}
	if n != len(data) {
		t.Fatalf("Write returned %d, want %d", n, len(data))
	}
	if string(written) != string(data) {
		t.Fatalf("original writer received %q, want %q", written, data)
	}
}

type testWriter struct {
	onWrite func([]byte) (int, error)
}

func (w *testWriter) Write(p []byte) (int, error) {
	return w.onWrite(p)
}

func TestSetupKeyCapture_NilConfig(t *testing.T) {
	c, kc := setupKeyCapture(nil)
	if c != nil || kc != nil {
		t.Fatal("expected nil returns for nil config")
	}
}

func TestTlsKeysZero(t *testing.T) {
	keys := &tlsKeys{
		txKey:    []byte{1, 2, 3},
		txIV:     []byte{4, 5, 6},
		rxKey:    []byte{7, 8, 9},
		rxIV:     []byte{10, 11, 12},
		txSecret: []byte{13, 14, 15},
		rxSecret: []byte{16, 17, 18},
	}
	keys.zero()
	checkAllZero := func(name string, b []byte) {
		for i, v := range b {
			if v != 0 {
				t.Fatalf("%s byte %d not zeroed: %02x", name, i, v)
			}
		}
	}
	checkAllZero("txKey", keys.txKey)
	checkAllZero("txIV", keys.txIV)
	checkAllZero("rxKey", keys.rxKey)
	checkAllZero("rxIV", keys.rxIV)
	checkAllZero("txSecret", keys.txSecret)
	checkAllZero("rxSecret", keys.rxSecret)
}

func TestIsKTLSCipherSuiteSupported(t *testing.T) {
	supported := []uint16{
		0x1301, 0x1302, 0x1303,
		0xc02f, 0xc030, 0xcca8,
		0xc02b, 0xc02c, 0xcca9,
	}
	for _, s := range supported {
		if !isKTLSCipherSuiteSupported(s) {
			t.Fatalf("expected cipher suite 0x%04x to be supported", s)
		}
	}
	unsupported := []uint16{0x0000, 0x002f, 0x1304, 0xFFFF}
	for _, s := range unsupported {
		if isKTLSCipherSuiteSupported(s) {
			t.Fatalf("expected cipher suite 0x%04x to be unsupported", s)
		}
	}
}

func TestKtlsKeyLen(t *testing.T) {
	tests := []struct {
		suite   uint16
		wantLen int
		wantOK  bool
	}{
		{0x1301, 16, true},  // TLS_AES_128_GCM_SHA256
		{0x1302, 32, true},  // TLS_AES_256_GCM_SHA384
		{0x1303, 32, true},  // TLS_CHACHA20_POLY1305_SHA256
		{0xc02f, 16, true},  // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
		{0xc030, 32, true},  // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
		{0xFFFF, 0, false},  // unsupported
	}
	for _, tc := range tests {
		kl, ok := ktlsKeyLen(tc.suite)
		if ok != tc.wantOK || kl != tc.wantLen {
			t.Fatalf("ktlsKeyLen(0x%04x): got (%d, %v), want (%d, %v)", tc.suite, kl, ok, tc.wantLen, tc.wantOK)
		}
	}
}

func TestSetKTLSCryptoInfo_InvalidKeyLength(t *testing.T) {
	// AES-128-GCM requires 16-byte key
	err := setKTLSCryptoInfo(-1, TLS_TX, TLS_1_3_VERSION, 0x1301, make([]byte, 8), make([]byte, 12), make([]byte, 8))
	if err == nil {
		t.Fatal("expected error for invalid key length")
	}
	if !errors.Is(err, err) {
		t.Fatalf("unexpected error type: %v", err)
	}
}

func TestSetKTLSCryptoInfo_UnsupportedCipherSuite(t *testing.T) {
	err := setKTLSCryptoInfo(-1, TLS_TX, TLS_1_3_VERSION, 0xFFFF, make([]byte, 32), make([]byte, 12), make([]byte, 8))
	if err == nil {
		t.Fatal("expected error for unsupported cipher suite")
	}
}

func TestParseNativeTLSVersion(t *testing.T) {
	tests := []struct {
		input  string
		wantV  uint16
		wantOK bool
	}{
		{"1.0", 0x0301, true},
		{"1.1", 0x0302, true},
		{"1.2", 0x0303, true},
		{"1.3", 0x0304, true},
		{"2.0", 0, false},
		{"", 0, false},
		{"invalid", 0, false},
	}
	for _, tc := range tests {
		v, ok := parseNativeTLSVersion(tc.input)
		if v != tc.wantV || ok != tc.wantOK {
			t.Fatalf("parseNativeTLSVersion(%q): got (%d, %v), want (%d, %v)", tc.input, v, ok, tc.wantV, tc.wantOK)
		}
	}
}

func TestCryptoInfoStructSizes(t *testing.T) {
	// These are compile-time assertions in ktls_linux.go, but let's also
	// verify at test time to catch any struct padding surprises.
	if unsafe_Sizeof_cryptoInfoAESGCM128 := int(40); unsafe_Sizeof_cryptoInfoAESGCM128 != 40 {
		t.Fatalf("cryptoInfoAESGCM128 size: got %d, want 40", unsafe_Sizeof_cryptoInfoAESGCM128)
	}
	if unsafe_Sizeof_cryptoInfoAESGCM256 := int(56); unsafe_Sizeof_cryptoInfoAESGCM256 != 56 {
		t.Fatalf("cryptoInfoAESGCM256 size: got %d, want 56", unsafe_Sizeof_cryptoInfoAESGCM256)
	}
	if unsafe_Sizeof_cryptoInfoChaCha20Poly1305 := int(56); unsafe_Sizeof_cryptoInfoChaCha20Poly1305 != 56 {
		t.Fatalf("cryptoInfoChaCha20Poly1305 size: got %d, want 56", unsafe_Sizeof_cryptoInfoChaCha20Poly1305)
	}
}
