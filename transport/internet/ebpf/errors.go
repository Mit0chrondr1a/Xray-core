package ebpf

import "errors"

var (
	// ErrXDPNotSupported is returned when XDP is not available on the system.
	ErrXDPNotSupported = errors.New("XDP is not supported on this system")

	// ErrXDPNotEnabled is returned when trying to use XDP without enabling it first.
	ErrXDPNotEnabled = errors.New("XDP is not enabled")

	// ErrSockmapNotSupported is returned when sockmap is not available.
	ErrSockmapNotSupported = errors.New("sockmap is not supported on this system")

	// ErrSockmapNotEnabled is returned when trying to use sockmap without enabling it.
	ErrSockmapNotEnabled = errors.New("sockmap is not enabled")

	// ErrRoutingCacheNotSupported is returned when BPF routing cache is not available.
	ErrRoutingCacheNotSupported = errors.New("BPF routing cache is not supported on this system")

	// ErrRoutingCacheNotEnabled is returned when trying to use routing cache without enabling it.
	ErrRoutingCacheNotEnabled = errors.New("BPF routing cache is not enabled")

	// ErrKernelTooOld is returned when the kernel version doesn't support the requested feature.
	ErrKernelTooOld = errors.New("kernel version is too old for this feature")

	// ErrPermissionDenied is returned when the process lacks required capabilities.
	ErrPermissionDenied = errors.New("permission denied: CAP_BPF or CAP_SYS_ADMIN required")

	// ErrInvalidInterface is returned when the specified network interface doesn't exist.
	ErrInvalidInterface = errors.New("invalid network interface")

	// ErrFlowTableFull is returned when the flow table is at capacity.
	ErrFlowTableFull = errors.New("flow table is full")
)
