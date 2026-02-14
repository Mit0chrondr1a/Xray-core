//go:build !linux

package tls

// KTLSKeyUpdateHandler is a no-op on non-Linux platforms.
type KTLSKeyUpdateHandler struct{}

// CipherSuiteID returns 0 on non-Linux platforms.
func (h *KTLSKeyUpdateHandler) CipherSuiteID() uint16 { return 0 }

// Handle is a no-op on non-Linux platforms.
func (h *KTLSKeyUpdateHandler) Handle() error { return nil }

// InitiateUpdate is a no-op on non-Linux platforms.
func (h *KTLSKeyUpdateHandler) InitiateUpdate() error { return nil }

// Close is a no-op on non-Linux platforms.
func (h *KTLSKeyUpdateHandler) Close() {}

func newKTLSKeyUpdateHandler(fd int, cipherSuiteID uint16, rxSecret, txSecret []byte) *KTLSKeyUpdateHandler {
	return nil
}

// IsKeyExpired always returns false on non-Linux platforms.
func IsKeyExpired(err error) bool { return false }

func isKeyExpired(err error) bool { return false }
