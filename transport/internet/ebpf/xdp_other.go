//go:build !linux

package ebpf

// attachXDPImpl is a no-op on non-Linux systems.
func attachXDPImpl(ifname string, config XDPConfig) error {
	return ErrXDPNotSupported
}

// detachXDPImpl is a no-op on non-Linux systems.
func detachXDPImpl() error {
	return nil
}

// updateFlowMapImpl is a no-op on non-Linux systems.
func updateFlowMapImpl(key FlowKey, entry *FlowEntry) error {
	return ErrXDPNotSupported
}

// deleteFlowMapImpl is a no-op on non-Linux systems.
func deleteFlowMapImpl(key FlowKey) error {
	return nil
}

// readFlowStatsImpl is a no-op on non-Linux systems.
func readFlowStatsImpl(key FlowKey, entry *FlowEntry) error {
	return nil
}
