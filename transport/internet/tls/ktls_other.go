//go:build !linux

package tls

// KTLSState tracks the kTLS state for a connection.
type KTLSState struct {
	Enabled bool
	TxReady bool
	RxReady bool
}

// TryEnableKTLS is a no-op on non-Linux platforms.
func TryEnableKTLS(conn *Conn) KTLSState {
	return KTLSState{}
}

// KTLSSupported returns false on non-Linux platforms.
func KTLSSupported() bool {
	return false
}
