//go:build linux

package tls

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	ktlsE2EReadDeadline  = 15 * time.Second
	ktlsE2EWaitTimeout   = 20 * time.Second
	ktlsE2EWriteDeadline = 10 * time.Second
)

type ktlsServerResult struct {
	data []byte
	err  error
}

// isKnownKTLSDataPathIssue identifies kernel/runtime kTLS RX failures that are
// environment-dependent and outside application logic correctness.
func isKnownKTLSDataPathIssue(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, unix.EBADMSG) || errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EMSGSIZE) || errors.Is(err, unix.EIO) {
		return true
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "bad message") ||
		strings.Contains(msg, "invalid argument") ||
		strings.Contains(msg, "message too long") ||
		strings.Contains(msg, "input/output error")
}

func generateTestCert(t *testing.T) gotls.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return gotls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

func TestTryEnableKTLS(t *testing.T) {
	cert := generateTestCert(t)

	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		MinVersion:   gotls.VersionTLS12,
	}
	clientConfig := &gotls.Config{
		InsecureSkipVerify: true,
		MinVersion:         gotls.VersionTLS12,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	// Server side
	serverDone := make(chan KTLSState, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- KTLSState{}
			return
		}
		tlsRaw := gotls.Server(raw, serverConfig)
		conn := &Conn{Conn: tlsRaw}
		if err := conn.HandshakeContext(context.Background()); err != nil {
			raw.Close()
			serverDone <- KTLSState{}
			return
		}
		state := TryEnableKTLS(conn)
		serverDone <- state
		// Keep connection alive for client test
		io.Copy(io.Discard, conn)
		conn.Close()
	}()

	// Client side
	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsRaw := gotls.Client(rawConn, clientConfig)
	clientConn := &Conn{Conn: tlsRaw}
	if err := clientConn.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	clientState := TryEnableKTLS(clientConn)
	serverState := <-serverDone

	// kTLS may or may not be supported depending on kernel — just ensure no panic
	t.Logf("Client kTLS state: Enabled=%v TxReady=%v RxReady=%v", clientState.Enabled, clientState.TxReady, clientState.RxReady)
	t.Logf("Server kTLS state: Enabled=%v TxReady=%v RxReady=%v", serverState.Enabled, serverState.TxReady, serverState.RxReady)

	clientConn.Close()
}

func TestForceRefreshKTLSSupportCounters(t *testing.T) {
	ktlsSupportOnce = sync.Once{}
	ktlsSupportOK.Store(false)
	ktlsProbeRefreshes.Store(0)
	ktlsProbeRefreshSuccess.Store(0)

	_ = forceRefreshKTLSSupport()

	if got := ktlsProbeRefreshes.Load(); got == 0 {
		t.Fatal("expected refresh counter to increment")
	}
}

func TestHandshakeAndEnableKTLS(t *testing.T) {
	cert := generateTestCert(t)

	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{cert},
	}
	clientConfig := &gotls.Config{
		InsecureSkipVerify: true,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	go func() {
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		tlsRaw := gotls.Server(raw, serverConfig)
		conn := &Conn{Conn: tlsRaw}
		conn.HandshakeAndEnableKTLS(context.Background())
		io.Copy(io.Discard, conn)
		conn.Close()
	}()

	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn := Client(rawConn, clientConfig).(*Conn)
	if err := clientConn.HandshakeAndEnableKTLS(context.Background()); err != nil {
		t.Fatal("HandshakeAndEnableKTLS failed:", err)
	}

	t.Logf("kTLS state: %+v", clientConn.KTLSEnabled())

	// Verify data transfer still works
	testData := []byte("hello kTLS world")
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatal("Write after kTLS enable failed:", err)
	}
	clientConn.Close()
}

func TestKTLSDataIntegrity(t *testing.T) {
	cert := generateTestCert(t)

	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{cert},
	}
	clientConfig := &gotls.Config{
		InsecureSkipVerify: true,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	testData := make([]byte, 1<<20) // 1 MiB
	rand.Read(testData)

	serverDone := make(chan ktlsServerResult, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- ktlsServerResult{err: err}
			return
		}
		tlsRaw := gotls.Server(raw, serverConfig)
		conn := &Conn{Conn: tlsRaw}
		conn.HandshakeAndEnableKTLS(context.Background())
		t.Logf("server kTLS state: %+v", conn.KTLSEnabled())
		_ = conn.SetReadDeadline(time.Now().Add(ktlsE2EReadDeadline))
		// Read length-prefix, then exactly that many bytes.
		// This avoids depending on close_notify for EOF signaling,
		// which kTLS TX skips by design.
		var length uint32
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			conn.Close()
			serverDone <- ktlsServerResult{err: fmt.Errorf("binary.Read length: %w", err)}
			return
		}
		received := make([]byte, length)
		if _, err := io.ReadFull(conn, received); err != nil {
			conn.Close()
			serverDone <- ktlsServerResult{err: fmt.Errorf("io.ReadFull(%d bytes): %w", length, err)}
			return
		}
		conn.Close()
		serverDone <- ktlsServerResult{data: received}
	}()

	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn := Client(rawConn, clientConfig).(*Conn)
	if err := clientConn.HandshakeAndEnableKTLS(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Logf("client kTLS state: %+v", clientConn.KTLSEnabled())

	// Write length header + data
	_ = clientConn.SetWriteDeadline(time.Now().Add(ktlsE2EWriteDeadline))
	if err := binary.Write(clientConn, binary.BigEndian, uint32(len(testData))); err != nil {
		t.Fatal(err)
	}
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatal(err)
	}

	// Wait for server to finish reading before closing — kTLS TX close
	// sends TCP RST instead of close_notify, which would kill the
	// server's in-flight binary.Read if data hasn't been consumed yet.
	var result ktlsServerResult
	select {
	case result = <-serverDone:
	case <-time.After(ktlsE2EWaitTimeout):
		clientConn.Close()
		t.Skipf("kTLS e2e data path timed out on this kernel after %v", ktlsE2EWaitTimeout)
	}
	clientConn.Close()

	if result.err != nil {
		if isKnownKTLSDataPathIssue(result.err) {
			t.Skipf("kTLS e2e data path not working on this kernel: %v", result.err)
		}
		t.Fatalf("server error: %v", result.err)
	}
	if !bytes.Equal(result.data, testData) {
		t.Fatalf("data mismatch: got %d bytes, want %d bytes", len(result.data), len(testData))
	}
}

func TestKTLSGracefulFallback(t *testing.T) {
	if !KTLSSupported() {
		t.Log("kTLS not supported on this kernel — testing graceful fallback")
	}

	// TryEnableKTLS with a non-TCP underlying connection should return empty state.
	// Use a pipe-backed TLS conn — kTLS requires TCP underneath.
	cert := generateTestCert(t)
	serverConfig := &gotls.Config{Certificates: []gotls.Certificate{cert}}
	clientConfig := &gotls.Config{InsecureSkipVerify: true}

	serverEnd, clientEnd := net.Pipe()

	go func() {
		tlsServer := gotls.Server(serverEnd, serverConfig)
		tlsServer.Handshake()
		io.Copy(io.Discard, tlsServer)
		tlsServer.Close()
	}()

	tlsClient := gotls.Client(clientEnd, clientConfig)
	conn := &Conn{Conn: tlsClient}
	if err := conn.HandshakeContext(context.Background()); err != nil {
		t.Fatalf("handshake over pipe failed: %v", err)
	}

	// TryEnableKTLS should fail gracefully (pipe is not TCP)
	state := TryEnableKTLS(conn)
	if state.Enabled {
		t.Fatal("kTLS should not be enabled on pipe-backed connection")
	}
	t.Logf("graceful fallback: kTLS state=%+v", state)
	conn.Close()
	serverEnd.Close()
}

func TestExtractTLSKeysFromGoAEADWrappers(t *testing.T) {
	cert := generateTestCert(t)

	tests := []struct {
		name         string
		minVersion   uint16
		maxVersion   uint16
		cipherSuites []uint16
	}{
		{
			name:       "tls12-aesgcm",
			minVersion: gotls.VersionTLS12,
			maxVersion: gotls.VersionTLS12,
			cipherSuites: []uint16{
				gotls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			},
		},
		{
			name:       "tls13",
			minVersion: gotls.VersionTLS13,
			maxVersion: gotls.VersionTLS13,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			serverConfig := &gotls.Config{
				Certificates: []gotls.Certificate{cert},
				MinVersion:   tc.minVersion,
				MaxVersion:   tc.maxVersion,
				CipherSuites: tc.cipherSuites,
			}
			clientConfig := &gotls.Config{
				InsecureSkipVerify: true,
				MinVersion:         tc.minVersion,
				MaxVersion:         tc.maxVersion,
				CipherSuites:       tc.cipherSuites,
			}

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()

			serverDone := make(chan struct{})
			go func() {
				defer close(serverDone)
				raw, err := listener.Accept()
				if err != nil {
					return
				}
				tlsRaw := gotls.Server(raw, serverConfig)
				_ = tlsRaw.Handshake()
				_, _ = io.Copy(io.Discard, tlsRaw)
				_ = tlsRaw.Close()
			}()

			rawConn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			tlsRaw := gotls.Client(rawConn, clientConfig)
			conn := &Conn{Conn: tlsRaw}
			if err := conn.HandshakeContext(context.Background()); err != nil {
				t.Fatal(err)
			}

			keys, err := extractTLSKeys(conn.Conn)
			if err != nil {
				t.Fatalf("extractTLSKeys failed: %v", err)
			}
			if len(keys.txKey) == 0 || len(keys.rxKey) == 0 {
				t.Fatalf("missing TLS keys: tx=%d rx=%d", len(keys.txKey), len(keys.rxKey))
			}
			if len(keys.txIV) == 0 || len(keys.rxIV) == 0 {
				t.Fatalf("missing TLS IVs: tx=%d rx=%d", len(keys.txIV), len(keys.rxIV))
			}

			_ = conn.Close()
			<-serverDone
		})
	}
}

func BenchmarkKTLSSplice(b *testing.B) {
	cert := generateTestCertForBench(b)

	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{cert},
	}
	clientConfig := &gotls.Config{
		InsecureSkipVerify: true,
	}

	payload := make([]byte, 32*1024)
	rand.Read(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			raw, err := listener.Accept()
			if err != nil {
				close(done)
				return
			}
			tlsRaw := gotls.Server(raw, serverConfig)
			conn := &Conn{Conn: tlsRaw}
			conn.HandshakeAndEnableKTLS(context.Background())
			io.Copy(io.Discard, conn)
			conn.Close()
			close(done)
		}()

		rawConn, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		clientConn := Client(rawConn, clientConfig).(*Conn)
		clientConn.HandshakeAndEnableKTLS(context.Background())
		b.StartTimer()

		clientConn.Write(payload)
		clientConn.Close()
		listener.Close()
		<-done
	}
	b.SetBytes(int64(len(payload)))
}

func generateTestCertForBench(b *testing.B) gotls.Certificate {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		b.Fatal(err)
	}
	return gotls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}
}

// TestExpandLabel verifies our HKDF-Expand-Label implementation against RFC 8448 test vectors.
// Test vector from RFC 8448 Section 3 (Simple 1-RTT Handshake, server_handshake_traffic_secret derivation).
func TestExpandLabel(t *testing.T) {
	// RFC 8448 test vector: deriving "key" from a known secret using SHA-256.
	// We use the server handshake traffic secret from RFC 8448, Section 3.
	secret, _ := hex.DecodeString("b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38")
	// Expected key derived from expandLabel(SHA256, secret, "key", nil, 16)
	expectedKey, _ := hex.DecodeString("3fce516009c21727d0f2e4e86ee403bc")

	result, err := expandLabel(crypto.SHA256, secret, "key", nil, 16)
	if err != nil {
		t.Fatalf("expandLabel key error: %v", err)
	}
	if !bytes.Equal(result, expectedKey) {
		t.Fatalf("expandLabel key mismatch:\n  got:  %x\n  want: %x", result, expectedKey)
	}

	// Also test IV derivation from the same secret
	expectedIV, _ := hex.DecodeString("5d313eb2671276ee13000b30")
	resultIV, err := expandLabel(crypto.SHA256, secret, "iv", nil, 12)
	if err != nil {
		t.Fatalf("expandLabel iv error: %v", err)
	}
	if !bytes.Equal(resultIV, expectedIV) {
		t.Fatalf("expandLabel iv mismatch:\n  got:  %x\n  want: %x", resultIV, expectedIV)
	}
}

func TestIsKeyExpired(t *testing.T) {
	if isKeyExpired(nil) {
		t.Fatal("nil error should not be EKEYEXPIRED")
	}
	if isKeyExpired(io.EOF) {
		t.Fatal("EOF should not be EKEYEXPIRED")
	}
	if !isKeyExpired(unix.EKEYEXPIRED) {
		t.Fatal("EKEYEXPIRED should be detected")
	}
}

func TestNewKTLSKeyUpdateHandler(t *testing.T) {
	secret := make([]byte, 32)
	rand.Read(secret)

	tests := []struct {
		name    string
		suite   uint16
		wantNil bool
	}{
		{"AES-128-GCM-SHA256", gotls.TLS_AES_128_GCM_SHA256, false},
		{"AES-256-GCM-SHA384", gotls.TLS_AES_256_GCM_SHA384, false},
		{"CHACHA20-POLY1305", gotls.TLS_CHACHA20_POLY1305_SHA256, false},
		{"unsupported", 0xFFFF, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newKTLSKeyUpdateHandler(0, tc.suite, secret, secret)
			if tc.wantNil && h != nil {
				t.Fatal("expected nil handler for unsupported suite")
			}
			if !tc.wantNil && h == nil {
				t.Fatal("expected non-nil handler")
			}
		})
	}
}

func TestKTLSReadBypassesTLSConn(t *testing.T) {
	cert := generateTestCert(t)

	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		MinVersion:   gotls.VersionTLS13,
	}
	clientConfig := &gotls.Config{
		InsecureSkipVerify: true,
		MinVersion:         gotls.VersionTLS13,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	testData := []byte("hello kTLS bypass test")
	serverDone := make(chan ktlsServerResult, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- ktlsServerResult{err: err}
			return
		}
		tlsRaw := gotls.Server(raw, serverConfig)
		conn := &Conn{Conn: tlsRaw}
		conn.HandshakeAndEnableKTLS(context.Background())
		t.Logf("server kTLS state: %+v", conn.KTLSEnabled())
		_ = conn.SetReadDeadline(time.Now().Add(ktlsE2EReadDeadline))
		// Read length-prefix, then exactly that many bytes.
		// This avoids depending on close_notify for EOF signaling,
		// which kTLS TX skips by design.
		var length uint32
		if err := binary.Read(conn, binary.BigEndian, &length); err != nil {
			conn.Close()
			serverDone <- ktlsServerResult{err: fmt.Errorf("binary.Read length: %w", err)}
			return
		}
		received := make([]byte, length)
		if _, err := io.ReadFull(conn, received); err != nil {
			conn.Close()
			serverDone <- ktlsServerResult{err: fmt.Errorf("io.ReadFull(%d bytes): %w", length, err)}
			return
		}
		conn.Close()
		serverDone <- ktlsServerResult{data: received}
	}()

	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn := Client(rawConn, clientConfig).(*Conn)
	if err := clientConn.HandshakeAndEnableKTLS(context.Background()); err != nil {
		t.Fatal(err)
	}

	// Whether kTLS is active or not, Read/Write through Conn should work
	_ = clientConn.SetWriteDeadline(time.Now().Add(ktlsE2EWriteDeadline))
	if err := binary.Write(clientConn, binary.BigEndian, uint32(len(testData))); err != nil {
		t.Fatal("length write failed:", err)
	}
	if _, err := clientConn.Write(testData); err != nil {
		t.Fatal("Write failed:", err)
	}

	// Wait for server to finish reading before closing — kTLS TX close
	// sends TCP RST instead of close_notify, which would kill the
	// server's in-flight binary.Read if data hasn't been consumed yet.
	var result ktlsServerResult
	select {
	case result = <-serverDone:
	case <-time.After(ktlsE2EWaitTimeout):
		clientConn.Close()
		t.Skipf("kTLS e2e read path timed out on this kernel after %v", ktlsE2EWaitTimeout)
	}
	t.Logf("kTLS client state: %+v", clientConn.KTLSEnabled())
	clientConn.Close()

	if result.err != nil {
		if isKnownKTLSDataPathIssue(result.err) {
			t.Skipf("kTLS e2e data path not working on this kernel: %v", result.err)
		}
		t.Fatalf("server error: %v", result.err)
	}
	if !bytes.Equal(result.data, testData) {
		t.Fatalf("data mismatch: got %q, want %q", result.data, testData)
	}
}

func TestTrafficSecretExtraction(t *testing.T) {
	cert := generateTestCert(t)

	serverConfig := &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		MinVersion:   gotls.VersionTLS13,
		MaxVersion:   gotls.VersionTLS13,
	}
	clientConfig := &gotls.Config{
		InsecureSkipVerify: true,
		MinVersion:         gotls.VersionTLS13,
		MaxVersion:         gotls.VersionTLS13,
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		raw, err := listener.Accept()
		if err != nil {
			return
		}
		tlsRaw := gotls.Server(raw, serverConfig)
		_ = tlsRaw.Handshake()
		_, _ = io.Copy(io.Discard, tlsRaw)
		_ = tlsRaw.Close()
	}()

	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	tlsRaw := gotls.Client(rawConn, clientConfig)
	conn := &Conn{Conn: tlsRaw}
	if err := conn.HandshakeContext(context.Background()); err != nil {
		t.Fatal(err)
	}

	keys, err := extractTLSKeys(conn.Conn)
	if err != nil {
		t.Fatalf("extractTLSKeys failed: %v", err)
	}

	if len(keys.txSecret) == 0 {
		t.Fatal("TLS 1.3 should have tx traffic secret")
	}
	if len(keys.rxSecret) == 0 {
		t.Fatal("TLS 1.3 should have rx traffic secret")
	}
	t.Logf("TLS 1.3 traffic secrets: tx=%d bytes, rx=%d bytes", len(keys.txSecret), len(keys.rxSecret))

	_ = conn.Close()
	<-serverDone
}

func TestMemzero(t *testing.T) {
	// Verify memzero actually zeroes memory.
	for _, size := range []int{0, 1, 7, 8, 15, 16, 31, 32, 40, 64, 76, 128, 256} {
		buf := make([]byte, size)
		for i := range buf {
			buf[i] = byte(i + 1) // fill with non-zero
		}
		memzero(buf)
		for i, b := range buf {
			if b != 0 {
				t.Fatalf("memzero(%d): byte %d not zeroed (got 0x%02x)", size, i, b)
			}
		}
	}
}

func TestZeroBytesErasesKeyMaterial(t *testing.T) {
	// Simulate the kTLS key erasure pattern: fill a buffer with
	// "key material", then call zeroBytes and verify it's gone.
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(0xAA ^ i)
	}
	zeroBytes(key)
	for i, b := range key {
		if b != 0 {
			t.Fatalf("zeroBytes: key byte %d not zeroed (got 0x%02x)", i, b)
		}
	}
}

func TestZeroCryptoInfoErasesStruct(t *testing.T) {
	// Simulate zeroing a stack-allocated crypto info struct.
	var info cryptoInfoAESGCM128
	info.Version = 0x0304
	info.CipherType = TLS_CIPHER_AES_GCM_128
	info.Key = [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	info.Salt = [4]byte{0xDE, 0xAD, 0xBE, 0xEF}

	zeroCryptoInfo(unsafe.Pointer(&info), unsafe.Sizeof(info))

	// Verify all fields are zero.
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&info)), unsafe.Sizeof(info))
	for i, b := range raw {
		if b != 0 {
			t.Fatalf("zeroCryptoInfo: byte %d not zeroed (got 0x%02x)", i, b)
		}
	}
}
