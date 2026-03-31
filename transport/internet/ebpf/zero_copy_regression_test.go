package ebpf

import (
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func newTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	serverCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, acceptErr := ln.Accept()
		if acceptErr != nil {
			errCh <- acceptErr
			return
		}
		serverCh <- c
	}()

	client, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial tcp: %v", err)
	}

	var server net.Conn
	select {
	case server = <-serverCh:
	case acceptErr := <-errCh:
		_ = client.Close()
		t.Fatalf("accept tcp: %v", acceptErr)
	case <-time.After(2 * time.Second):
		_ = client.Close()
		t.Fatal("timeout waiting for accepted TCP conn")
	}

	t.Cleanup(func() {
		_ = client.Close()
		_ = server.Close()
	})
	return client, server
}

func TestCanUseZeroCopyWithCrypto_IneligibleCandidatesSkipKTLSProbe(t *testing.T) {
	inbound, outbound := newTCPPair(t)

	saved := ktlsSockhashCompatFn
	defer func() { ktlsSockhashCompatFn = saved }()

	var probeCalls atomic.Int32
	ktlsSockhashCompatFn = func() bool {
		probeCalls.Add(1)
		return true
	}

	tests := []struct {
		name string
		in   CryptoHint
		out  CryptoHint
	}{
		{"userspace inbound", CryptoUserspaceTLS, CryptoNone},
		{"userspace outbound", CryptoNone, CryptoUserspaceTLS},
		{"partial tx only", CryptoKTLSTxOnly, CryptoNone},
		{"partial rx only", CryptoNone, CryptoKTLSRxOnly},
	}
	for _, tt := range tests {
		if CanUseZeroCopyWithCrypto(inbound, outbound, tt.in, tt.out) {
			t.Fatalf("%s: expected false for ineligible candidate", tt.name)
		}
	}
	if got := probeCalls.Load(); got != 0 {
		t.Fatalf("kTLS compatibility probe should not run for ineligible candidates, got %d calls", got)
	}
}

func TestCanUseZeroCopyWithCrypto_KTLSCandidatesAreRejectedWithoutProbe(t *testing.T) {
	inbound, outbound := newTCPPair(t)

	saved := ktlsSockhashCompatFn
	defer func() { ktlsSockhashCompatFn = saved }()

	var probeCalls atomic.Int32
	ktlsSockhashCompatFn = func() bool {
		probeCalls.Add(1)
		return true
	}

	if CanUseZeroCopyWithCrypto(inbound, outbound, CryptoKTLSBoth, CryptoNone) {
		t.Fatal("expected false for plain/kTLS candidate")
	}
	if CanUseZeroCopyWithCrypto(inbound, outbound, CryptoNone, CryptoKTLSBoth) {
		t.Fatal("expected false for kTLS/plain candidate")
	}
	if CanUseZeroCopyWithCrypto(inbound, outbound, CryptoKTLSBoth, CryptoKTLSBoth) {
		t.Fatal("expected false for kTLS/kTLS candidate")
	}
	if got := probeCalls.Load(); got != 0 {
		t.Fatalf("kTLS candidates should be rejected before probing compatibility, got %d probe calls", got)
	}
}

func TestCanUseZeroCopyWithCrypto_NonTCPAlwaysFalse(t *testing.T) {
	inbound, outbound := net.Pipe()
	defer inbound.Close()
	defer outbound.Close()

	if CanUseZeroCopyWithCrypto(inbound, outbound, CryptoNone, CryptoNone) {
		t.Fatal("non-TCP pair must not be eligible for zero-copy")
	}
}

func TestIncrementKTLSSpliceFallback_TrackedInStats(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.IncrementKTLSSpliceFallback()
	mgr.IncrementKTLSSpliceFallback()

	stats := mgr.GetSockmapStats()
	if stats.KTLSSpliceFallbacks != 2 {
		t.Fatalf("KTLSSpliceFallbacks=%d, want 2", stats.KTLSSpliceFallbacks)
	}
}
