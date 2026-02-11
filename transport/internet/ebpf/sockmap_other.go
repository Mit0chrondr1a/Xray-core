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
func setupForwardingImpl(inboundFD, outboundFD int) error {
	return ErrSockmapNotSupported
}

// getConnFDImpl returns an error on non-Linux systems.
func getConnFDImpl(conn net.Conn) (int, error) {
	return -1, ErrSockmapNotSupported
}
