package xudp_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	gotls "crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	gonet "net"
	"os"
	"sync"
	"testing"
	"time"

	quic "github.com/apernet/quic-go"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/mux"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/xudp"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/proxy/freedom"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	istats "github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

func newLinkPair() (*transport.Link, *transport.Link) {
	opt := pipe.WithoutSizeLimit()
	uplinkReader, uplinkWriter := pipe.New(opt)
	downlinkReader, downlinkWriter := pipe.New(opt)

	uplink := &transport.Link{
		Reader: uplinkReader,
		Writer: downlinkWriter,
	}

	downlink := &transport.Link{
		Reader: downlinkReader,
		Writer: uplinkWriter,
	}

	return uplink, downlink
}

type testDispatcher struct {
	onDispatch func(ctx context.Context, dest net.Destination) (*transport.Link, error)
}

func (d *testDispatcher) Dispatch(ctx context.Context, dest net.Destination) (*transport.Link, error) {
	return d.onDispatch(ctx, dest)
}

func (*testDispatcher) DispatchLink(context.Context, net.Destination, *transport.Link) error {
	return nil
}
func (*testDispatcher) Start() error      { return nil }
func (*testDispatcher) Close() error      { return nil }
func (*testDispatcher) Type() interface{} { return routing.DispatcherType() }

type testDialer struct{}

func (testDialer) Dial(ctx context.Context, destination net.Destination) (istats.Connection, error) {
	return internet.DialSystem(ctx, destination, nil)
}

func (testDialer) DestIpAddress() net.IP { return nil }

func (testDialer) SetOutboundGateway(context.Context, *session.Outbound) {}

type xudpPacketConn struct {
	reader       *buf.TimeoutWrapperReader
	writer       buf.Writer
	localAddr    gonet.Addr
	defaultAddr  gonet.Addr
	closeWriter  func()
	closeReader  func()
	mu           sync.RWMutex
	readDeadline time.Time
}

func newXUDPPacketConn(reader buf.Reader, writer buf.Writer, localAddr, defaultAddr gonet.Addr, closeWriter, closeReader func()) *xudpPacketConn {
	return &xudpPacketConn{
		reader:      &buf.TimeoutWrapperReader{Reader: reader},
		writer:      writer,
		localAddr:   localAddr,
		defaultAddr: defaultAddr,
		closeWriter: closeWriter,
		closeReader: closeReader,
	}
}

func (c *xudpPacketConn) ReadFrom(p []byte) (int, gonet.Addr, error) {
	c.mu.RLock()
	deadline := c.readDeadline
	c.mu.RUnlock()

	var (
		mb  buf.MultiBuffer
		err error
	)
	if deadline.IsZero() {
		mb, err = c.reader.ReadMultiBuffer()
	} else {
		timeout := time.Until(deadline)
		if timeout <= 0 {
			return 0, nil, os.ErrDeadlineExceeded
		}
		mb, err = c.reader.ReadMultiBufferTimeout(timeout)
		if err == nil && mb == nil {
			return 0, nil, os.ErrDeadlineExceeded
		}
	}
	if err != nil {
		return 0, nil, err
	}
	defer buf.ReleaseMulti(mb)
	if len(mb) == 0 || mb[0] == nil {
		return 0, nil, os.ErrDeadlineExceeded
	}

	b := mb[0]
	n := copy(p, b.Bytes())
	addr := c.defaultAddr
	if b.UDP != nil && b.UDP.RawNetAddr() != nil {
		addr = b.UDP.RawNetAddr()
	}
	return n, addr, nil
}

func (c *xudpPacketConn) WriteTo(p []byte, addr gonet.Addr) (int, error) {
	buffer := buf.FromBytes(p)
	if addr != nil {
		dest := net.DestinationFromAddr(addr)
		buffer.UDP = &dest
	}
	if err := c.writer.WriteMultiBuffer(buf.MultiBuffer{buffer}); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *xudpPacketConn) Close() error {
	if c.closeWriter != nil {
		c.closeWriter()
	}
	if c.closeReader != nil {
		c.closeReader()
	}
	return nil
}

func (c *xudpPacketConn) LocalAddr() gonet.Addr { return c.localAddr }

func (c *xudpPacketConn) SetDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *xudpPacketConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.readDeadline = t
	return nil
}

func (c *xudpPacketConn) SetWriteDeadline(time.Time) error { return nil }

func generateQUICServerTLS(t *testing.T) *gotls.Config {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey() failed: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          new(big.Int).SetInt64(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              []string{"localhost"},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, priv)
	if err != nil {
		t.Fatalf("CreateCertificate() failed: %v", err)
	}

	cert := gotls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
	}
	return &gotls.Config{
		Certificates: []gotls.Certificate{cert},
		NextProtos:   []string{"xudp-quic-test"},
	}
}

func readPacketWithTimeout(t *testing.T, reader buf.Reader) buf.MultiBuffer {
	t.Helper()

	type result struct {
		mb  buf.MultiBuffer
		err error
	}

	done := make(chan result, 1)
	go func() {
		mb, err := reader.ReadMultiBuffer()
		done <- result{mb: mb, err: err}
	}()

	select {
	case got := <-done:
		if got.err != nil {
			t.Fatalf("ReadMultiBuffer() failed: %v", got.err)
		}
		return got.mb
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for packet")
		return nil
	}
}

func TestMuxPacketResponseCompatibleWithXUDPReader(t *testing.T) {
	var wire bytes.Buffer
	writer := mux.NewResponseWriter(0, buf.NewWriter(&wire), protocol.TransferTypePacket)

	source := net.UDPDestination(net.IPAddress([]byte{1, 0, 0, 1}), net.Port(853))
	payload := buf.FromBytes([]byte("pong"))
	payload.UDP = &source
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{payload}); err != nil {
		t.Fatalf("WriteMultiBuffer() failed: %v", err)
	}

	reader := xudp.NewPacketReader(bytes.NewReader(wire.Bytes()))
	mb, err := reader.ReadMultiBuffer()
	if err != nil {
		t.Fatalf("ReadMultiBuffer() failed: %v", err)
	}
	if got := mb.String(); got != "pong" {
		t.Fatalf("payload=%q, want %q", got, "pong")
	}
	if mb[0].UDP == nil {
		t.Fatal("response packet lost UDP source metadata")
	}
	if *mb[0].UDP != source {
		t.Fatalf("udp=%v, want %v", *mb[0].UDP, source)
	}
}

func TestXUDPPacketRoundTripThroughMuxServerWithoutGlobalID(t *testing.T) {
	serverCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})
	target := net.UDPDestination(net.IPAddress([]byte{1, 0, 0, 1}), net.Port(853))

	echoUplink, echoDownlink := newLinkPair()
	dispatcher := &testDispatcher{
		onDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			if dest != target {
				t.Fatalf("dispatch target=%v, want %v", dest, target)
			}
			return echoDownlink, nil
		},
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	_, err := mux.NewServerWorker(serverCtx, dispatcher, muxServerUplink)
	if err != nil {
		t.Fatalf("NewServerWorker() failed: %v", err)
	}

	go func() {
		for {
			mb, err := echoUplink.Reader.ReadMultiBuffer()
			if err != nil {
				return
			}
			if len(mb) > 0 && mb[0] != nil && mb[0].UDP == nil {
				mb[0].UDP = &target
			}
			_ = echoUplink.Writer.WriteMultiBuffer(mb)
		}
	}()

	writer := xudp.NewPacketWriter(muxServerDownlink.Writer, target, [8]byte{})
	reader := xudp.NewPacketReader(&buf.BufferedReader{Reader: muxServerDownlink.Reader})

	firstPayload := bytes.Repeat([]byte{0xaa}, 1280)
	first := buf.FromBytes(firstPayload)
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{first}); err != nil {
		t.Fatalf("first WriteMultiBuffer() failed: %v", err)
	}
	firstResp := readPacketWithTimeout(t, reader)
	if got := firstResp[0].Bytes(); !bytes.Equal(got, firstPayload) {
		t.Fatalf("first payload mismatch: got %d bytes", len(got))
	}

	secondPayload := bytes.Repeat([]byte{0xbb}, 1280)
	second := buf.FromBytes(secondPayload)
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{second}); err != nil {
		t.Fatalf("second WriteMultiBuffer() failed: %v", err)
	}
	secondResp := readPacketWithTimeout(t, reader)
	if got := secondResp[0].Bytes(); !bytes.Equal(got, secondPayload) {
		t.Fatalf("second payload mismatch: got %d bytes", len(got))
	}

	common.Close(muxServerDownlink.Writer)
	common.Close(echoUplink.Writer)
}

func TestXUDPFreedomUDPRoundTripWithoutGlobalID(t *testing.T) {
	echoConn, err := gonet.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() failed: %v", err)
	}
	defer echoConn.Close()

	go func() {
		packet := make([]byte, 2048)
		for {
			n, addr, err := echoConn.ReadFrom(packet)
			if err != nil {
				return
			}
			_, _ = echoConn.WriteTo(packet[:n], addr)
		}
	}()

	udpAddr := echoConn.LocalAddr().(*gonet.UDPAddr)
	target := net.UDPDestination(net.IPAddress(udpAddr.IP), net.Port(udpAddr.Port))
	serverCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})

	var handler freedom.Handler
	if err := handler.Init(&freedom.Config{}, policy.DefaultManager{}); err != nil {
		t.Fatalf("freedom.Init() failed: %v", err)
	}

	dispatcher := &testDispatcher{
		onDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			if dest != target {
				t.Fatalf("dispatch target=%v, want %v", dest, target)
			}
			serverLink, freedomLink := newLinkPair()
			go func() {
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
				_ = handler.Process(ctx, freedomLink, testDialer{})
			}()
			return serverLink, nil
		},
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	_, err = mux.NewServerWorker(serverCtx, dispatcher, muxServerUplink)
	if err != nil {
		t.Fatalf("NewServerWorker() failed: %v", err)
	}

	writer := xudp.NewPacketWriter(muxServerDownlink.Writer, target, [8]byte{})
	reader := xudp.NewPacketReader(&buf.BufferedReader{Reader: muxServerDownlink.Reader})

	payload := bytes.Repeat([]byte{0xcc}, 1280)
	packet := buf.FromBytes(payload)
	if err := writer.WriteMultiBuffer(buf.MultiBuffer{packet}); err != nil {
		t.Fatalf("WriteMultiBuffer() failed: %v", err)
	}

	response := readPacketWithTimeout(t, reader)
	if got := response[0].Bytes(); !bytes.Equal(got, payload) {
		t.Fatalf("response payload mismatch: got %d bytes", len(got))
	}

	common.Close(muxServerDownlink.Writer)
}

func TestXUDPFreedomQUICRoundTripWithoutGlobalID(t *testing.T) {
	serverTLS := generateQUICServerTLS(t)
	listener, err := quic.ListenAddr("127.0.0.1:0", serverTLS, &quic.Config{
		HandshakeIdleTimeout: time.Second * 3,
		MaxIdleTimeout:       time.Second * 10,
	})
	if err != nil {
		t.Fatalf("ListenAddr() failed: %v", err)
	}
	defer listener.Close()

	serverDone := make(chan error, 1)
	serverMayClose := make(chan struct{})
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		conn, err := listener.Accept(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer func() {
			<-serverMayClose
			_ = conn.CloseWithError(0, "")
		}()

		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			serverDone <- err
			return
		}
		defer stream.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(stream, buf); err != nil {
			serverDone <- err
			return
		}
		if !bytes.Equal(buf, []byte("ping")) {
			serverDone <- fmt.Errorf("server got %q", string(buf))
			return
		}
		_, err = stream.Write([]byte("pong"))
		if err == nil {
			err = stream.Close()
		}
		serverDone <- err
	}()

	target := net.DestinationFromAddr(listener.Addr())
	serverCtx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{}})

	var handler freedom.Handler
	if err := handler.Init(&freedom.Config{}, policy.DefaultManager{}); err != nil {
		t.Fatalf("freedom.Init() failed: %v", err)
	}

	dispatcher := &testDispatcher{
		onDispatch: func(ctx context.Context, dest net.Destination) (*transport.Link, error) {
			if dest != target {
				t.Fatalf("dispatch target=%v, want %v", dest, target)
			}
			serverLink, freedomLink := newLinkPair()
			go func() {
				ctx = session.ContextWithOutbounds(ctx, []*session.Outbound{{Target: dest}})
				_ = handler.Process(ctx, freedomLink, testDialer{})
			}()
			return serverLink, nil
		},
	}

	muxServerUplink, muxServerDownlink := newLinkPair()
	_, err = mux.NewServerWorker(serverCtx, dispatcher, muxServerUplink)
	if err != nil {
		t.Fatalf("NewServerWorker() failed: %v", err)
	}

	packetConn := newXUDPPacketConn(
		xudp.NewPacketReader(&buf.BufferedReader{Reader: muxServerDownlink.Reader}),
		xudp.NewPacketWriter(muxServerDownlink.Writer, target, [8]byte{}),
		&gonet.UDPAddr{IP: gonet.ParseIP("127.0.0.1"), Port: 54321},
		listener.Addr(),
		func() { common.Close(muxServerDownlink.Writer) },
		nil,
	)
	defer packetConn.Close()

	clientTLS := &gotls.Config{
		InsecureSkipVerify: true,
		NextProtos:         []string{"xudp-quic-test"},
		ServerName:         "localhost",
	}
	conn, err := quic.Dial(context.Background(), packetConn, listener.Addr(), clientTLS, &quic.Config{
		HandshakeIdleTimeout: time.Second * 3,
		MaxIdleTimeout:       time.Second * 10,
	})
	if err != nil {
		t.Fatalf("quic.Dial() failed: %v", err)
	}
	defer conn.CloseWithError(0, "")

	stream, err := conn.OpenStreamSync(context.Background())
	if err != nil {
		t.Fatalf("OpenStreamSync() failed: %v", err)
	}
	defer stream.Close()

	if _, err := stream.Write([]byte("ping")); err != nil {
		t.Fatalf("stream.Write() failed: %v", err)
	}
	reply := make([]byte, 4)
	if _, err := io.ReadFull(stream, reply); err != nil {
		t.Fatalf("stream.ReadFull() failed: %v", err)
	}
	if !bytes.Equal(reply, []byte("pong")) {
		t.Fatalf("reply=%q, want %q", string(reply), "pong")
	}
	close(serverMayClose)

	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatalf("server side failed: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for quic server")
	}
}
