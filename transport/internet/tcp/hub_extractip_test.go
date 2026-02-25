package tcp

import (
	"net"
	"testing"
)

func TestExtractIP_TCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 443}
	ip := extractIP(addr)
	if !ip.Equal(net.IPv4(10, 0, 0, 1)) {
		t.Fatalf("expected 10.0.0.1, got %v", ip)
	}
}

func TestExtractIP_UDPAddr(t *testing.T) {
	addr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 1), Port: 8080}
	ip := extractIP(addr)
	if !ip.Equal(net.IPv4(192, 168, 1, 1)) {
		t.Fatalf("expected 192.168.1.1, got %v", ip)
	}
}

type testStringAddr struct {
	network string
	addr    string
}

func (a testStringAddr) Network() string { return a.network }
func (a testStringAddr) String() string  { return a.addr }

func TestExtractIP_StringAddrHostPort(t *testing.T) {
	addr := testStringAddr{network: "tcp", addr: "1.2.3.4:443"}
	ip := extractIP(addr)
	if ip == nil {
		t.Fatal("expected non-nil IP for valid host:port string addr")
	}
	if !ip.Equal(net.IPv4(1, 2, 3, 4)) {
		t.Fatalf("expected 1.2.3.4, got %v", ip)
	}
}

func TestExtractIP_InvalidStringAddr(t *testing.T) {
	addr := testStringAddr{network: "tcp", addr: "not-a-host-port"}
	ip := extractIP(addr)
	if ip != nil {
		t.Fatalf("expected nil IP for invalid addr string, got %v", ip)
	}
}

func TestExtractIP_IPv6TCPAddr(t *testing.T) {
	addr := &net.TCPAddr{IP: net.IPv6loopback, Port: 443}
	ip := extractIP(addr)
	if !ip.Equal(net.IPv6loopback) {
		t.Fatalf("expected IPv6 loopback, got %v", ip)
	}
}

func TestExtractIP_NilTCPAddr(t *testing.T) {
	addr := &net.TCPAddr{Port: 443}
	ip := extractIP(addr)
	// TCPAddr with nil IP returns nil
	if ip != nil {
		t.Fatalf("expected nil IP for TCPAddr with nil IP field, got %v", ip)
	}
}

func TestEncodeRealityServerNames_NilInput(t *testing.T) {
	got := encodeRealityServerNames(nil)
	if got != nil {
		t.Fatalf("expected nil for nil input, got %v", got)
	}
}

func TestEncodeRealityServerNames_AllEmpty(t *testing.T) {
	got := encodeRealityServerNames([]string{"", "", ""})
	if got != nil {
		t.Fatalf("expected nil for all-empty input, got %v", got)
	}
}

func TestEncodeRealityServerNames_SingleEntry(t *testing.T) {
	got := encodeRealityServerNames([]string{"example.com"})
	want := []byte("example.com\x00")
	if string(got) != string(want) {
		t.Fatalf("single entry: got %q, want %q", got, want)
	}
}
