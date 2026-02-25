package ebpf

import (
	"context"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

var (
	globalManager     *SockmapManager
	globalManagerOnce sync.Once
)

// GlobalSockmapManager returns the global sockmap manager, initializing it
// lazily on first call. Returns nil if sockmap is not supported.
func GlobalSockmapManager() *SockmapManager {
	globalManagerOnce.Do(func() {
		ctx := context.Background()
		caps := GetCapabilities()
		if !caps.SockmapSupported {
			errors.LogDebug(
				ctx,
				"eBPF sockmap disabled: unsupported on kernel ",
				caps.KernelVersion.Major, ".", caps.KernelVersion.Minor, ".", caps.KernelVersion.Patch,
			)
			logSockmapDeploymentDebug(ctx, caps, nil)
			return
		}
		mgr := NewSockmapManager(DefaultSockmapConfig())
		if err := mgr.Enable(); err != nil {
			errors.LogInfoInner(ctx, err, "eBPF sockmap disabled, falling back to splice/readv")
			logSockmapDeploymentDebug(ctx, caps, err)
			return
		}
		globalManager = mgr
		errors.LogDebug(ctx, "eBPF sockmap enabled")
		logAccelerationSummary(ctx)
	})
	return globalManager
}
