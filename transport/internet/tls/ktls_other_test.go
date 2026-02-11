//go:build !linux

package tls

import (
	"testing"
)

func TestKTLSNotSupported(t *testing.T) {
	if KTLSSupported() {
		t.Fatal("KTLSSupported should return false on non-Linux")
	}

	state := TryEnableKTLS(&Conn{})
	if state.Enabled || state.TxReady || state.RxReady {
		t.Fatal("TryEnableKTLS should return empty state on non-Linux")
	}
}
