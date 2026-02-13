//go:build !linux

package tls

// KTLSKeyUpdateHandler is a no-op on non-Linux platforms.
type KTLSKeyUpdateHandler struct{}

// Handle is a no-op on non-Linux platforms.
func (h *KTLSKeyUpdateHandler) Handle() error { return nil }

// IsKeyExpired always returns false on non-Linux platforms.
func IsKeyExpired(err error) bool { return false }

func isKeyExpired(err error) bool { return false }
