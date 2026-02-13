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

// addToSockmapImpl is a no-op on non-Linux systems.
func addToSockmapImpl(fd int) error {
	return ErrSockmapNotSupported
}

// removeFromSockmapImpl is a no-op on non-Linux systems.
func removeFromSockmapImpl(fd int) error {
	return nil
}

// setupForwardingImpl is a no-op on non-Linux systems.
func setupForwardingImpl(inboundFD, outboundFD int, inboundCookie, outboundCookie uint64) error {
	return ErrSockmapNotSupported
}

// removeForwardingImpl is a no-op on non-Linux systems.
func removeForwardingImpl(inboundCookie, outboundCookie uint64) error {
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

// isSocketAlive always returns false on non-Linux systems.
func isSocketAlive(fd int) bool {
	return false
}
