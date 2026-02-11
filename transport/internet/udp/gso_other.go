//go:build !linux || (!amd64 && !arm64)

package udp

import "net"

// GSOSupported returns false on non-Linux platforms.
func GSOSupported() bool { return false }

// GROSupported returns false on non-Linux platforms.
func GROSupported() bool { return false }

// EnableGRO is a no-op on non-Linux platforms.
func EnableGRO(conn *net.UDPConn) error { return nil }

// EnableGSO is a no-op on non-Linux platforms.
func EnableGSO(conn *net.UDPConn) error { return nil }
