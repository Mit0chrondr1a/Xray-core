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
		caps := GetCapabilities()
		if !caps.SockmapSupported {
			errors.LogDebug(
				context.Background(),
				"eBPF sockmap disabled: unsupported on kernel ",
				caps.KernelVersion.Major, ".", caps.KernelVersion.Minor, ".", caps.KernelVersion.Patch,
			)
			return
		}
		mgr := NewSockmapManager(DefaultSockmapConfig())
		if err := mgr.Enable(); err != nil {
			errors.LogInfoInner(context.Background(), err, "eBPF sockmap disabled, falling back to splice/readv")
			return
		}
		globalManager = mgr
		errors.LogDebug(context.Background(), "eBPF sockmap enabled")
	})
	return globalManager
}
