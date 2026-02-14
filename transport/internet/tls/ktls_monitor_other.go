//go:build !linux

package tls

// KeyUpdateMonitor is a no-op on non-Linux platforms.
type KeyUpdateMonitor struct{}

func NewKeyUpdateMonitor(fd int, handler *KTLSKeyUpdateHandler) *KeyUpdateMonitor { return nil }
func (m *KeyUpdateMonitor) Start()                                                {}
func (m *KeyUpdateMonitor) Stop()                                                 {}
