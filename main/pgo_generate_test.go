package main

// This file generates a PGO profile for production builds.
// Run: go test -bench=BenchmarkPGOWorkload -benchtime=10s -cpuprofile=default.pgo ./main/
//
// The profile exercises the hot paths that dominate proxy runtime:
// - TLS handshake (client + server)
// - Buffered data copy (buf.Copy / readV path)
// - Multi-buffer allocation and release
// - Raw TCP connection splice path setup

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

	"github.com/xtls/xray-core/common/buf"
)

func pgoCert(b *testing.B) gotls.Certificate {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "localhost"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		b.Fatal(err)
	}
	return gotls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// BenchmarkPGOWorkload_TLSHandshake exercises TLS handshake hot paths.
func BenchmarkPGOWorkload_TLSHandshake(b *testing.B) {
	cert := pgoCert(b)
	serverCfg := &gotls.Config{Certificates: []gotls.Certificate{cert}}
	clientCfg := &gotls.Config{InsecureSkipVerify: true}

	for i := 0; i < b.N; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			srv := gotls.Server(raw, serverCfg)
			srv.Handshake()
			io.Copy(io.Discard, srv)
			srv.Close()
		}()

		raw, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		cli := gotls.Client(raw, clientCfg)
		cli.Handshake()
		cli.Close()
		listener.Close()
		<-done
	}
}

// BenchmarkPGOWorkload_BufferCopy exercises buf.Copy and multi-buffer paths.
func BenchmarkPGOWorkload_BufferCopy(b *testing.B) {
	payload := make([]byte, 64*1024)
	rand.Read(payload)

	for i := 0; i < b.N; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			reader := buf.NewReader(raw)
			buf.Copy(reader, buf.Discard)
			raw.Close()
		}()

		raw, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		raw.Write(payload)
		raw.Close()
		listener.Close()
		<-done
	}
	b.SetBytes(int64(len(payload)))
}

// BenchmarkPGOWorkload_TLSDataTransfer exercises TLS encrypt/decrypt with buf.Copy.
func BenchmarkPGOWorkload_TLSDataTransfer(b *testing.B) {
	cert := pgoCert(b)
	serverCfg := &gotls.Config{Certificates: []gotls.Certificate{cert}}
	clientCfg := &gotls.Config{InsecureSkipVerify: true}

	payload := make([]byte, 256*1024)
	rand.Read(payload)

	for i := 0; i < b.N; i++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		done := make(chan struct{})
		go func() {
			defer close(done)
			raw, err := listener.Accept()
			if err != nil {
				return
			}
			srv := gotls.Server(raw, serverCfg)
			reader := buf.NewReader(srv)
			buf.Copy(reader, buf.Discard)
			srv.Close()
		}()

		raw, err := net.Dial("tcp", listener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		cli := gotls.Client(raw, clientCfg)
		cli.Handshake()
		cli.Write(payload)
		cli.Close()
		listener.Close()
		<-done
	}
	b.SetBytes(int64(len(payload)))
}

// BenchmarkPGOWorkload_MultiBuffer exercises multi-buffer alloc/release.
func BenchmarkPGOWorkload_MultiBuffer(b *testing.B) {
	for i := 0; i < b.N; i++ {
		mb := make(buf.MultiBuffer, 0, 16)
		for j := 0; j < 16; j++ {
			buffer := buf.New()
			buffer.Extend(buf.Size)
			mb = append(mb, buffer)
		}
		buf.ReleaseMulti(mb)
	}
}

// BenchmarkPGOWorkload_SplicePath exercises the splice setup path (TCP ReadFrom).
func BenchmarkPGOWorkload_SplicePath(b *testing.B) {
	payload := make([]byte, 128*1024)
	rand.Read(payload)

	for i := 0; i < b.N; i++ {
		// reader side
		rListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}
		// writer side
		wListener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			b.Fatal(err)
		}

		done := make(chan struct{})
		go func() {
			defer close(done)
			rConn, err := rListener.Accept()
			if err != nil {
				return
			}
			wConn, err := net.Dial("tcp", wListener.Addr().String())
			if err != nil {
				rConn.Close()
				return
			}
			tc := wConn.(*net.TCPConn)
			tc.ReadFrom(rConn)
			rConn.Close()
			wConn.Close()
		}()

		go func() {
			wPeer, err := wListener.Accept()
			if err != nil {
				return
			}
			io.Copy(io.Discard, wPeer)
			wPeer.Close()
		}()

		rConn, err := net.Dial("tcp", rListener.Addr().String())
		if err != nil {
			b.Fatal(err)
		}
		rConn.Write(payload)
		rConn.Close()
		rListener.Close()
		wListener.Close()
		<-done
	}
	b.SetBytes(int64(len(payload)))
}

// BenchmarkPGOWorkload_ContextAlloc exercises context creation which is hot in the proxy path.
func BenchmarkPGOWorkload_ContextAlloc(b *testing.B) {
	bg := context.Background()
	for i := 0; i < b.N; i++ {
		ctx, cancel := context.WithCancel(bg)
		ctx, cancel2 := context.WithTimeout(ctx, time.Minute)
		_ = ctx
		cancel2()
		cancel()
	}
}
