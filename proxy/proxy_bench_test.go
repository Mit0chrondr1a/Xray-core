package proxy

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
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/transport/internet/tls"
)

func benchCert(b *testing.B) gotls.Certificate {
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

func makeConnPair(b *testing.B) (client, server net.Conn) {
	b.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	ch := make(chan net.Conn, 1)
	go func() { c, _ := l.Accept(); ch <- c }()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		b.Fatal(err)
	}
	s := <-ch
	l.Close()
	return c, s
}

func makeSpliceCopyCtx() context.Context {
	ctx := context.Background()
	inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGateEligible)}
	ctx = session.ContextWithInbound(ctx, inbound)
	outbound := &session.Outbound{CanSpliceCopy: int32(session.CopyGateEligible)}
	ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
	return ctx
}

func BenchmarkCopyRawConn_Splice(b *testing.B) {
	payload := make([]byte, 64*1024)
	rand.Read(payload)

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		reader, readerPeer := makeConnPair(b)
		writer, writerPeer := makeConnPair(b)
		ctx := makeSpliceCopyCtx()
		timer := signal.CancelAfterInactivity(ctx, func() {}, 30*time.Second)

		go func() {
			readerPeer.Write(payload)
			readerPeer.Close()
		}()
		go func() {
			io.Copy(io.Discard, writerPeer)
			writerPeer.Close()
		}()

		b.StartTimer()
		CopyRawConnIfExist(ctx, reader, writer, buf.Discard, timer, nil)
		b.StopTimer()

		reader.Close()
		writer.Close()
	}
	b.SetBytes(int64(len(payload)))
}

func BenchmarkCopyRawConn_ReadVWriteV(b *testing.B) {
	payload := make([]byte, 64*1024)
	rand.Read(payload)

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		reader, readerPeer := makeConnPair(b)
		writer, writerPeer := makeConnPair(b)
		// CopyGateForcedUserspace forces readV path
		ctx := context.Background()
		inbound := &session.Inbound{CanSpliceCopy: int32(session.CopyGateForcedUserspace)}
		ctx = session.ContextWithInbound(ctx, inbound)
		outbound := &session.Outbound{CanSpliceCopy: int32(session.CopyGateForcedUserspace)}
		ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{outbound})
		timer := signal.CancelAfterInactivity(ctx, func() {}, 30*time.Second)

		go func() {
			readerPeer.Write(payload)
			readerPeer.Close()
		}()
		go func() {
			io.Copy(io.Discard, writerPeer)
			writerPeer.Close()
		}()

		b.StartTimer()
		CopyRawConnIfExist(ctx, reader, writer, buf.Discard, timer, nil)
		b.StopTimer()

		reader.Close()
		writer.Close()
	}
	b.SetBytes(int64(len(payload)))
}

func BenchmarkCopyRawConn_KTLSSplice(b *testing.B) {
	cert := benchCert(b)
	payload := make([]byte, 64*1024)
	rand.Read(payload)

	serverCfg := &gotls.Config{Certificates: []gotls.Certificate{cert}}
	clientCfg := &gotls.Config{InsecureSkipVerify: true}

	for i := 0; i < b.N; i++ {
		b.StopTimer()
		// reader side: TLS-wrapped conn
		readerRaw, readerPeer := makeConnPair(b)
		// writer side: plain TCP
		writer, writerPeer := makeConnPair(b)

		// Wrap reader side in TLS
		tlsServer := gotls.Server(readerPeer, serverCfg)
		tlsClient := tls.Client(readerRaw, clientCfg).(*tls.Conn)
		serverErr := make(chan error, 1)
		go func() {
			if err := tlsServer.Handshake(); err != nil {
				serverErr <- err
				return
			}
			if _, err := tlsServer.Write(payload); err != nil {
				serverErr <- err
				return
			}
			if err := tlsServer.Close(); err != nil {
				serverErr <- err
				return
			}
			serverErr <- nil
		}()
		if err := tlsClient.HandshakeAndEnableKTLS(context.Background()); err != nil {
			b.Fatal(err)
		}

		ctx := makeSpliceCopyCtx()
		timer := signal.CancelAfterInactivity(ctx, func() {}, 30*time.Second)

		go func() {
			io.Copy(io.Discard, writerPeer)
			writerPeer.Close()
		}()

		// UnwrapRawConn will peel the TLS to get the raw TCP conn
		b.StartTimer()
		err := CopyRawConnIfExist(ctx, tlsClient, writer, buf.Discard, timer, nil)
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		select {
		case err := <-serverErr:
			if err != nil {
				b.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			b.Fatal("timeout waiting for TLS server benchmark goroutine")
		}

		readerRaw.Close()
		writer.Close()
	}
	b.SetBytes(int64(len(payload)))
}
