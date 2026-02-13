//go:build !linux

package ebpf

import (
	"net"
)

// setupSockmapImpl is a no-op on non-Linux systems.
func setupSockmapImpl(config SockmapConfig) error {
	return ErrSockmapNotSupported
}

// teardownSockmapImpl is a no-op on non-Linux systems.
func teardownSockmapImpl() error {
	return nil
}

// setupForwardingImpl is a no-op on non-Linux systems.
func setupForwardingImpl(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	return ErrSockmapNotSupported
}

// removeForwardingImpl is a no-op on non-Linux systems.
func removeForwardingImpl(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	return nil
}

// getSocketCookie returns an error on non-Linux systems.
func getSocketCookie(fd int) (uint64, error) {
	return 0, ErrSockmapNotSupported
}

// getConnFDImpl returns an error on non-Linux systems.
func getConnFDImpl(conn net.Conn) (int, error) {
	return -1, ErrSockmapNotSupported
}

// setPolicyEntry is a no-op on non-Linux systems.
func setPolicyEntry(cookie uint64, flags uint32) error {
	return nil
}

// deletePolicyEntry is a no-op on non-Linux systems.
func deletePolicyEntry(cookie uint64) error {
	return nil
}

// isSocketAlive always returns false on non-Linux systems.
func isSocketAlive(fd int) bool {
	return false
}
