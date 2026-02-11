// Package ebpf provides eBPF-based optimizations for network operations.
// This package offers XDP for UDP acceleration, sockmap for zero-copy TCP proxying,
// and BPF-based routing cache for improved performance.
//
// All eBPF features require Linux kernel 4.8+ and gracefully fall back to
// pure Go implementations when eBPF is not available.
package ebpf

import (
	"sync"
)

// Capabilities represents the detected eBPF capabilities of the system.
type Capabilities struct {
	// XDPSupported indicates XDP (eXpress Data Path) is available.
	// Requires kernel 4.8+, with XDP_REDIRECT requiring 5.3+.
	XDPSupported bool

	// XDPRedirectSupported indicates XDP_REDIRECT action is available.
	// Requires kernel 5.3+.
	XDPRedirectSupported bool

	// SockmapSupported indicates sockmap/sk_msg is available for zero-copy TCP.
	// Requires kernel 4.17+, with improved sk_msg requiring 5.4+.
	SockmapSupported bool

	// SockmapSKMsgSupported indicates improved sk_msg support.
	// Requires kernel 5.4+.
	SockmapSKMsgSupported bool

	// TCBPFSupported indicates TC BPF classifier is available.
	// Used for routing cache acceleration.
	TCBPFSupported bool

	// ReuseportBPFSupported indicates SO_REUSEPORT BPF is available.
	// Used for CPU-aware connection steering.
	ReuseportBPFSupported bool

	// BTFSupported indicates BTF (BPF Type Format) is available.
	// Enables CO-RE (Compile Once, Run Everywhere).
	BTFSupported bool

	// KernelVersion is the detected kernel version.
	KernelVersion KernelVersion
}

// KernelVersion represents a Linux kernel version.
type KernelVersion struct {
	Major int
	Minor int
	Patch int
}

// AtLeast returns true if this version is at least the specified version.
func (v KernelVersion) AtLeast(major, minor, patch int) bool {
	if v.Major != major {
		return v.Major > major
	}
	if v.Minor != minor {
		return v.Minor > minor
	}
	return v.Patch >= patch
}

// String returns the version as a string.
func (v KernelVersion) String() string {
	return ""
}

var (
	detectedCaps     Capabilities
	capsOnce         sync.Once
	capsDetected     bool
	capsMu           sync.RWMutex
)

// GetCapabilities returns the detected eBPF capabilities of the system.
// Results are cached after the first call.
func GetCapabilities() Capabilities {
	capsOnce.Do(func() {
		detectedCaps = probeCapabilities()
		capsDetected = true
	})
	return detectedCaps
}

// IsAvailable returns true if any eBPF feature is available on this system.
func IsAvailable() bool {
	caps := GetCapabilities()
	return caps.XDPSupported || caps.SockmapSupported || caps.TCBPFSupported
}

// XDPConfig configures XDP program behavior.
type XDPConfig struct {
	// Mode specifies the XDP attach mode.
	Mode XDPMode

	// FlowTableSize is the maximum number of flows to track.
	// Default is 65536.
	FlowTableSize uint32

	// FlowTimeout is the flow entry timeout in seconds.
	// Default is 300 (5 minutes).
	FlowTimeout uint32
}

// XDPMode specifies how XDP programs are attached to interfaces.
type XDPMode int

const (
	// XDPModeAuto selects the best available mode.
	XDPModeAuto XDPMode = iota

	// XDPModeNative uses driver-level XDP (fastest).
	XDPModeNative

	// XDPModeOffload uses hardware offload (if supported by NIC).
	XDPModeOffload

	// XDPModeGeneric uses generic/SKB mode (slower but more compatible).
	XDPModeGeneric
)

// SockmapConfig configures sockmap behavior.
type SockmapConfig struct {
	// MaxEntries is the maximum number of socket entries.
	// Default is 65536.
	MaxEntries uint32
}

// RoutingCacheConfig configures the BPF routing cache.
type RoutingCacheConfig struct {
	// MaxEntries is the maximum number of cached routing decisions.
	// Default is 32768.
	MaxEntries uint32

	// TTLSeconds is the cache entry time-to-live.
	// Default is 60.
	TTLSeconds uint32
}

// DefaultXDPConfig returns the default XDP configuration.
func DefaultXDPConfig() XDPConfig {
	return XDPConfig{
		Mode:          XDPModeAuto,
		FlowTableSize: 65536,
		FlowTimeout:   300,
	}
}

// DefaultSockmapConfig returns the default sockmap configuration.
func DefaultSockmapConfig() SockmapConfig {
	return SockmapConfig{
		MaxEntries: 65536,
	}
}

// DefaultRoutingCacheConfig returns the default routing cache configuration.
func DefaultRoutingCacheConfig() RoutingCacheConfig {
	return RoutingCacheConfig{
		MaxEntries: 32768,
		TTLSeconds: 60,
	}
}
