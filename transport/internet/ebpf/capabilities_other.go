//go:build !linux

package ebpf

// probeCapabilities returns empty capabilities on non-Linux systems.
// eBPF is a Linux-specific feature.
func probeCapabilities() Capabilities {
	return Capabilities{}
}
