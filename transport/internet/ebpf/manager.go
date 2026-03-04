package ebpf

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

var (
	globalManager             atomic.Pointer[SockmapManager]
	globalManagerMu           sync.Mutex
	globalManagerRetryAfterNs atomic.Int64

	globalManagerNowUnixNano   = func() int64 { return time.Now().UnixNano() }
	globalManagerCapabilities  = GetCapabilities
	globalManagerInitializerFn = defaultGlobalSockmapManagerInitializer
)

const (
	globalManagerRetryInterval = 5 * time.Second
	globalManagerNoRetry       = int64(^uint64(0) >> 1)
)

func defaultGlobalSockmapManagerInitializer() (*SockmapManager, error) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Enable(); err != nil {
		return nil, err
	}
	return mgr, nil
}

func logSockmapCapabilityDisable(ctx context.Context, caps Capabilities) {
	switch caps.sockmapFailureKind() {
	case sockmapProbeFailurePermissionDenied:
		errors.LogInfo(
			ctx,
			"eBPF sockmap disabled: probe blocked by permission/seccomp (",
			caps.sockmapProbeSummary(),
			")",
		)
	case sockmapProbeFailureTransient:
		errors.LogInfo(
			ctx,
			"eBPF sockmap disabled: startup probe failed transiently (",
			caps.sockmapProbeSummary(),
			")",
		)
	case sockmapProbeFailureUnknown:
		errors.LogInfo(
			ctx,
			"eBPF sockmap disabled: startup probe failed (",
			caps.sockmapProbeSummary(),
			")",
		)
	default:
		errors.LogDebug(
			ctx,
			"eBPF sockmap disabled: unsupported on kernel ",
			caps.KernelVersion.Major, ".", caps.KernelVersion.Minor, ".", caps.KernelVersion.Patch,
		)
	}
}

// GlobalSockmapManager returns the global sockmap manager, initializing it
// lazily on first call. Returns nil if sockmap is not supported.
//
// On initialization failure, retries are throttled to avoid hot-path overhead.
func GlobalSockmapManager() *SockmapManager {
	if mgr := globalManager.Load(); mgr != nil && mgr.IsEnabled() {
		return mgr
	}

	nowNs := globalManagerNowUnixNano()
	if retryAfter := globalManagerRetryAfterNs.Load(); retryAfter != 0 && nowNs < retryAfter {
		return nil
	}

	globalManagerMu.Lock()
	defer globalManagerMu.Unlock()

	if mgr := globalManager.Load(); mgr != nil {
		if mgr.IsEnabled() {
			return mgr
		}
		// Reset stale pointer if manager was disabled.
		globalManager.Store(nil)
	}

	nowNs = globalManagerNowUnixNano()
	if retryAfter := globalManagerRetryAfterNs.Load(); retryAfter != 0 && nowNs < retryAfter {
		return nil
	}

	ctx := context.Background()
	caps := globalManagerCapabilities()
	if !caps.SockmapSupported {
		logSockmapCapabilityDisable(ctx, caps)
		logSockmapDeploymentDebug(ctx, caps, nil)
		// Capability-gated disable is treated as stable for process lifetime.
		globalManagerRetryAfterNs.Store(globalManagerNoRetry)
		return nil
	}

	mgr, err := globalManagerInitializerFn()
	if err != nil {
		errors.LogInfoInner(ctx, err, "eBPF sockmap init failed, falling back to splice/readv (will retry)")
		logSockmapDeploymentDebug(ctx, caps, err)
		globalManagerRetryAfterNs.Store(nowNs + int64(globalManagerRetryInterval))
		return nil
	}

	globalManager.Store(mgr)
	globalManagerRetryAfterNs.Store(0)
	errors.LogDebug(ctx, "eBPF sockmap enabled")
	logAccelerationSummary(ctx)
	return mgr
}
