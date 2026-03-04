package ebpf

import (
	"errors"
	"syscall"
	"testing"
)

func resetGlobalManagerStateForTest() {
	globalManagerMu.Lock()
	defer globalManagerMu.Unlock()
	globalManager.Store(nil)
	globalManagerRetryAfterNs.Store(0)
}

func TestGlobalSockmapManagerRetriesAfterInitFailure(t *testing.T) {
	resetGlobalManagerStateForTest()
	defer resetGlobalManagerStateForTest()

	oldNow := globalManagerNowUnixNano
	oldCaps := globalManagerCapabilities
	oldInit := globalManagerInitializerFn
	defer func() {
		globalManagerNowUnixNano = oldNow
		globalManagerCapabilities = oldCaps
		globalManagerInitializerFn = oldInit
	}()

	nowNs := int64(1_000_000_000)
	globalManagerNowUnixNano = func() int64 { return nowNs }
	globalManagerCapabilities = func() Capabilities {
		return Capabilities{
			SockmapSupported: true,
			KernelVersion:    KernelVersion{Major: 6, Minor: 1, Patch: 0},
		}
	}

	attempts := 0
	readyMgr := NewSockmapManager(DefaultSockmapConfig())
	readyMgr.enabled.Store(true)
	globalManagerInitializerFn = func() (*SockmapManager, error) {
		attempts++
		if attempts == 1 {
			return nil, errors.New("transient init failure")
		}
		return readyMgr, nil
	}

	if mgr := GlobalSockmapManager(); mgr != nil {
		t.Fatal("first call should fail and return nil")
	}
	if attempts != 1 {
		t.Fatalf("attempt count mismatch after first call: got %d, want 1", attempts)
	}

	// Retry is throttled before backoff elapses.
	if mgr := GlobalSockmapManager(); mgr != nil {
		t.Fatal("retry should be throttled before backoff elapses")
	}
	if attempts != 1 {
		t.Fatalf("attempt count should remain 1 while throttled, got %d", attempts)
	}

	nowNs += int64(globalManagerRetryInterval)

	mgr := GlobalSockmapManager()
	if mgr != readyMgr {
		t.Fatal("expected manager to be initialized after retry window")
	}
	if attempts != 2 {
		t.Fatalf("attempt count mismatch after retry: got %d, want 2", attempts)
	}

	// Fast path must return cached manager without reinitialization.
	if got := GlobalSockmapManager(); got != readyMgr {
		t.Fatal("expected cached manager on fast path")
	}
	if attempts != 2 {
		t.Fatalf("fast path should not reinitialize manager, got attempts=%d", attempts)
	}
}

func TestGlobalSockmapManagerCapabilityGateNoRetry(t *testing.T) {
	resetGlobalManagerStateForTest()
	defer resetGlobalManagerStateForTest()

	oldNow := globalManagerNowUnixNano
	oldCaps := globalManagerCapabilities
	oldInit := globalManagerInitializerFn
	defer func() {
		globalManagerNowUnixNano = oldNow
		globalManagerCapabilities = oldCaps
		globalManagerInitializerFn = oldInit
	}()

	nowNs := int64(2_000_000_000)
	globalManagerNowUnixNano = func() int64 { return nowNs }

	capCalls := 0
	globalManagerCapabilities = func() Capabilities {
		capCalls++
		return Capabilities{
			SockmapSupported:  false,
			KernelVersion:     KernelVersion{Major: 6, Minor: 1, Patch: 0},
			sockmapProbeStage: sockmapProbeStageMapCreate,
			sockmapProbeErrno: syscall.EPERM,
		}
	}

	initCalls := 0
	globalManagerInitializerFn = func() (*SockmapManager, error) {
		initCalls++
		return nil, errors.New("should not be called")
	}

	if mgr := GlobalSockmapManager(); mgr != nil {
		t.Fatal("capability-gated call should return nil")
	}
	if capCalls != 1 {
		t.Fatalf("capability probe calls mismatch: got %d, want 1", capCalls)
	}
	if initCalls != 0 {
		t.Fatalf("initializer should not be called, got %d", initCalls)
	}

	// No-retry state should skip further initialization attempts.
	nowNs += int64(globalManagerRetryInterval) * 10
	if mgr := GlobalSockmapManager(); mgr != nil {
		t.Fatal("capability-gated call should still return nil")
	}
	if capCalls != 1 {
		t.Fatalf("capability probe should not rerun after stable gate, got %d", capCalls)
	}
	if initCalls != 0 {
		t.Fatalf("initializer should remain unused, got %d", initCalls)
	}
}
