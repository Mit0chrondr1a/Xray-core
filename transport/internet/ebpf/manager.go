package ebpf

import (
	"sync"
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
			return
		}
		mgr := NewSockmapManager(DefaultSockmapConfig())
		if err := mgr.Enable(); err != nil {
			return
		}
		globalManager = mgr
	})
	return globalManager
}
