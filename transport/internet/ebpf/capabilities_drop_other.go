//go:build !linux

package ebpf

// dropExcessCapabilities is a no-op on non-Linux systems.
func dropExcessCapabilities() error { return nil }
