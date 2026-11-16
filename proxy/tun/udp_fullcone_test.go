package tun

import (
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
)

// BenchmarkUDPNewSession measures what one new UDP flow costs the
// inbound while it stays open: QUIC and DNS open many short flows, and each
// one lives until the connection idle timeout.
func BenchmarkUDPNewSession(b *testing.B) {
	u := newUdpConnectionHandler(func(conn net.Conn, dest net.Destination) {}, nil)
	dst := net.UDPDestination(net.ParseAddress("1.1.1.1"), 443)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		src := net.UDPDestination(net.IPAddress([]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), net.Port(1024+i%60000))
		u.HandlePacket(src, dst, &buf.Buffer{})
	}
}

func TestPacketQueueOrderAndClose(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 3; i++ {
		b := buf.New()
		b.WriteByte(byte(i))
		if !q.push(b) {
			t.Fatalf("push %d rejected", i)
		}
	}
	for i := 0; i < 3; i++ {
		b, ok := q.pop()
		if !ok || b.Byte(0) != byte(i) {
			t.Fatalf("pop %d: got %v, %v", i, b, ok)
		}
		b.Release()
	}
	q.close()
	if _, ok := q.pop(); ok {
		t.Fatal("pop after close returned a packet")
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push after close accepted")
	}
}

func TestPacketQueueLimit(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < udpQueueLimit; i++ {
		if !q.push(&buf.Buffer{}) {
			t.Fatalf("push %d rejected below the limit", i)
		}
	}
	if q.push(&buf.Buffer{}) {
		t.Fatal("push above the limit accepted")
	}
}

func TestPacketQueueCloseUnblocksReader(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	done := make(chan bool)
	go func() {
		_, ok := q.pop()
		done <- ok
	}()
	q.close()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("blocked pop returned a packet after close")
		}
	case <-time.After(time.Second):
		t.Fatal("close did not wake the reader")
	}
}

func TestPacketQueueDropsDrainedStorage(t *testing.T) {
	q := newPacketQueue(udpQueueLimit)
	for i := 0; i < 100; i++ {
		q.push(&buf.Buffer{})
	}
	for i := 0; i < 100; i++ {
		q.pop()
	}
	if q.items != nil {
		t.Fatalf("drained queue still holds %d slots", cap(q.items))
	}
}

func makeUDPDestination(lastOctet byte, port uint16) net.Destination {
	return net.UDPDestination(net.IPAddress([]byte{10, 0, 0, lastOctet}), net.Port(port))
}

func TestUDPConnectionHandlerConnectionLimit(t *testing.T) {
	handler := newUdpConnectionHandler(
		func(conn net.Conn, dest net.Destination) {},
		func(data []byte, src net.Destination, dst net.Destination) error { return nil },
	)
	handler.maxConns = 2

	src1 := makeUDPDestination(1, 1001)
	src2 := makeUDPDestination(2, 1002)
	src3 := makeUDPDestination(3, 1003)
	dst := makeUDPDestination(9, 2000)

	handler.HandlePacket(src1, dst, buf.New())
	handler.HandlePacket(src2, dst, buf.New())
	if got := len(handler.udpConns); got != 2 {
		t.Fatalf("expected 2 tracked connections, got %d", got)
	}

	// Overflow packets are dropped without creating a new session.
	handler.HandlePacket(src3, dst, buf.New())
	if got := len(handler.udpConns); got != 2 {
		t.Fatalf("connection limit should be enforced; got %d tracked connections", got)
	}
	if _, found := handler.udpConns[src3]; found {
		t.Fatal("overflow source should not be tracked")
	}

	handler.connectionFinished(handler.udpConns[src1])
	handler.HandlePacket(src3, dst, buf.New())
	if _, found := handler.udpConns[src3]; !found {
		t.Fatal("source should be tracked after capacity is available")
	}
}
