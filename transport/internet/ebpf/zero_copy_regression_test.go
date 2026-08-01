package ebpf

import (
	stderrors "errors"
	"net"
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

func TestCanUseZeroCopyWithCrypto_IneligibleCandidatesAreRejected(t *testing.T) {
	inbound, outbound := newTCPPair(t)

	tests := []struct {
		name string
		in   CryptoHint
		out  CryptoHint
	}{
		{"userspace inbound", CryptoUserspaceTLS, CryptoNone},
		{"userspace outbound", CryptoNone, CryptoUserspaceTLS},
		{"partial tx only", CryptoKTLSTxOnly, CryptoNone},
		{"partial rx only", CryptoNone, CryptoKTLSRxOnly},
		{"unknown", CryptoUnknown, CryptoNone},
	}
	for _, tt := range tests {
		if CanUseZeroCopyWithCrypto(inbound, outbound, tt.in, tt.out) {
			t.Fatalf("%s: expected false for ineligible candidate", tt.name)
		}
	}
}

func TestCanUseZeroCopyWithCrypto_KTLSCandidatesAreRejected(t *testing.T) {
	inbound, outbound := newTCPPair(t)

	if CanUseZeroCopyWithCrypto(inbound, outbound, CryptoKTLSBoth, CryptoNone) {
		t.Fatal("expected false for plain/kTLS candidate")
	}
	if CanUseZeroCopyWithCrypto(inbound, outbound, CryptoNone, CryptoKTLSBoth) {
		t.Fatal("expected false for kTLS/plain candidate")
	}
	if CanUseZeroCopyWithCrypto(inbound, outbound, CryptoKTLSBoth, CryptoKTLSBoth) {
		t.Fatal("expected false for kTLS/kTLS candidate")
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

func TestRegisterPairWithCryptoRejectsNonRawBeforeManagerAndFDWork(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	before := mgr.GetSockmapStats()
	tests := []struct {
		name string
		in   CryptoHint
		out  CryptoHint
	}{
		{"full kTLS", CryptoKTLSBoth, CryptoKTLSBoth},
		{"raw to full kTLS", CryptoNone, CryptoKTLSBoth},
		{"full kTLS to raw", CryptoKTLSBoth, CryptoNone},
		{"TX-only", CryptoKTLSTxOnly, CryptoNone},
		{"RX-only", CryptoNone, CryptoKTLSRxOnly},
		{"userspace", CryptoUserspaceTLS, CryptoNone},
		{"unknown", CryptoUnknown, CryptoNone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := mgr.RegisterPairWithCrypto(nil, nil, tt.in, tt.out)
			if !stderrors.Is(err, ErrSockmapCryptoUnsupported) {
				t.Fatalf("error=%v, want ErrSockmapCryptoUnsupported", err)
			}
			if stderrors.Is(err, ErrSockmapNotEnabled) {
				t.Fatalf("error=%v reached manager state before crypto rejection", err)
			}
		})
	}

	if after := mgr.GetSockmapStats(); after != before {
		t.Fatalf("stats changed after rejected registrations: before=%+v after=%+v", before, after)
	}
	if mgr.lruList.Len() != 0 || len(mgr.lruIndex) != 0 {
		t.Fatalf("LRU changed after rejected registrations: list=%d index=%d", mgr.lruList.Len(), len(mgr.lruIndex))
	}

	if err := mgr.RegisterPairWithCrypto(nil, nil, CryptoNone, CryptoNone); !stderrors.Is(err, ErrSockmapNotEnabled) {
		t.Fatalf("raw registration error=%v, want ErrSockmapNotEnabled", err)
	}
}
