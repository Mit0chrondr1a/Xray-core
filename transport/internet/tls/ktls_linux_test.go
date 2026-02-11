//go:build linux

package tls

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

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

	serverDone := make(chan []byte, 1)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- nil
			return
		}
		tlsRaw := gotls.Server(raw, serverConfig)
		conn := &Conn{Conn: tlsRaw}
		conn.HandshakeAndEnableKTLS(context.Background())
		received, err := io.ReadAll(conn)
		conn.Close()
		if err != nil {
			serverDone <- nil
			return
		}
		serverDone <- received
	}()

	rawConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientConn := Client(rawConn, clientConfig).(*Conn)
	if err := clientConn.HandshakeAndEnableKTLS(context.Background()); err != nil {
		t.Fatal(err)
	}

	if _, err := clientConn.Write(testData); err != nil {
		t.Fatal(err)
	}
	clientConn.Close()

	received := <-serverDone
	if received == nil {
		t.Fatal("server received nil")
	}
	if len(received) != len(testData) {
		t.Fatalf("data length mismatch: got %d, want %d", len(received), len(testData))
	}
	for i := range testData {
		if received[i] != testData[i] {
			t.Fatalf("data mismatch at byte %d", i)
		}
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
