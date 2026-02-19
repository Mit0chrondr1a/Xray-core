package tun

import (
	"testing"

	"github.com/xtls/xray-core/common/net"
)

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

	if ok := handler.HandlePacket(src1, dst, []byte{1}); !ok {
		t.Fatal("first packet should be handled")
	}
	if ok := handler.HandlePacket(src2, dst, []byte{2}); !ok {
		t.Fatal("second packet should be handled")
	}
	if got := len(handler.udpConns); got != 2 {
		t.Fatalf("expected 2 tracked connections, got %d", got)
	}

	if ok := handler.HandlePacket(src3, dst, []byte{3}); !ok {
		t.Fatal("overflow packet should be handled (dropped) without failing the transport callback")
	}
	if got := len(handler.udpConns); got != 2 {
		t.Fatalf("connection limit should be enforced; got %d tracked connections", got)
	}
	if _, found := handler.udpConns[src3]; found {
		t.Fatal("overflow source should not be tracked")
	}

	handler.connectionFinished(src1)
	if ok := handler.HandlePacket(src3, dst, []byte{4}); !ok {
		t.Fatal("packet should be handled after a slot is released")
	}
	if _, found := handler.udpConns[src3]; !found {
		t.Fatal("source should be tracked after capacity is available")
	}
}
