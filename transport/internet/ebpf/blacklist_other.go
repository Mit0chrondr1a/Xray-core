//go:build !linux

package ebpf

// enableXDP is a no-op on non-Linux systems.
func (m *BlacklistManager) enableXDP(ifname string) error {
	return ErrXDPNotSupported
}

// disableXDP is a no-op on non-Linux systems.
func (m *BlacklistManager) disableXDP() error {
	return nil
}

// bpfMapUpdateBlacklist is a no-op on non-Linux systems.
func bpfMapUpdateBlacklist(fd int, key [16]byte) {}

// bpfMapDeleteBlacklist is a no-op on non-Linux systems.
func bpfMapDeleteBlacklist(fd int, key [16]byte) {}
