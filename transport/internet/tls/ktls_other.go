//go:build !linux

package tls

import gotls "crypto/tls"

// KTLSState tracks the kTLS state for a connection.
type KTLSState struct {
	Enabled          bool
	TxReady          bool
	RxReady          bool
	keyUpdateHandler *KTLSKeyUpdateHandler
}

// keyCapture is unused on non-Linux platforms.
type keyCapture struct{}

// setupKeyCapture is a no-op on non-Linux platforms.
func setupKeyCapture(config *gotls.Config) (*gotls.Config, *keyCapture) {
	return config, nil
}

// TryEnableKTLS is a no-op on non-Linux platforms.
func TryEnableKTLS(conn *Conn) KTLSState {
	return KTLSState{}
}

// KTLSSupported returns false on non-Linux platforms.
func KTLSSupported() bool {
	return false
}
