package ebpf

import (
	"fmt"
	"syscall"
	"testing"
	"time"
)

func TestShouldFallbackToSpliceUsesRecentRegistrationWindow(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.regWindowStartNs.Store(time.Now().UnixNano())
	mgr.regWindowTotal.Store(25)
	mgr.regWindowFailures.Store(6) // 24%

	if !mgr.ShouldFallbackToSplice() {
		t.Fatal("expected fallback when recent registration failure rate exceeds 20%")
	}
	if got := mgr.spliceFallbacks.Load(); got != 1 {
		t.Fatalf("splice fallback counter mismatch: got %d, want 1", got)
	}
}

func TestShouldFallbackToSpliceRecoversAfterWindowExpiry(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.regWindowStartNs.Store(time.Now().Add(-regFailureWindow - time.Second).UnixNano())
	mgr.regWindowTotal.Store(25)
	mgr.regWindowFailures.Store(6)

	if mgr.ShouldFallbackToSplice() {
		t.Fatal("fallback should recover after registration window rotates")
	}
	if got := mgr.regWindowTotal.Load(); got != 0 {
		t.Fatalf("window total should reset on rotation, got %d", got)
	}
	if got := mgr.regWindowFailures.Load(); got != 0 {
		t.Fatalf("window failures should reset on rotation, got %d", got)
	}
}

func TestShouldFallbackToSpliceOnStaleSweepRatio(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.sweepStaleRatio.Store(101)

	if !mgr.ShouldFallbackToSplice() {
		t.Fatal("expected fallback when stale sweep ratio exceeds 10%")
	}
	if got := mgr.spliceFallbacks.Load(); got != 1 {
		t.Fatalf("splice fallback counter mismatch: got %d, want 1", got)
	}
}

func TestIncrementKTLSSpliceFallbackDoesNotAffectGenericFallbackWindow(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.regWindowStartNs.Store(time.Now().UnixNano())
	for i := 0; i < 32; i++ {
		mgr.IncrementKTLSSpliceFallback()
	}

	if got := mgr.ktlsSpliceFallbacks.Load(); got != 32 {
		t.Fatalf("ktls splice fallback counter mismatch: got %d, want 32", got)
	}
	if got := mgr.regWindowTotal.Load(); got != 0 {
		t.Fatalf("generic registration total should stay untouched, got %d", got)
	}
	if got := mgr.regWindowFailures.Load(); got != 0 {
		t.Fatalf("generic registration failures should stay untouched, got %d", got)
	}
	if mgr.ShouldFallbackToSplice() {
		t.Fatal("kTLS incompatibility should not trigger global generic sockmap fallback")
	}
}

func TestFullRejectDoesNotAffectGenericFallbackWindow(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.regWindowStartNs.Store(time.Now().UnixNano())

	for i := 0; i < 32; i++ {
		mgr.recordSockmapRegistrationFailure(fmt.Errorf("wrap: %w", syscall.ENOSPC))
	}

	if got := mgr.fullRejects.Load(); got != 32 {
		t.Fatalf("full rejects = %d, want 32", got)
	}
	if got := mgr.regWindowTotal.Load(); got != 0 {
		t.Fatalf("generic registration total should stay untouched, got %d", got)
	}
	if got := mgr.regWindowFailures.Load(); got != 0 {
		t.Fatalf("generic registration failures should stay untouched, got %d", got)
	}
	if mgr.ShouldFallbackToSplice() {
		t.Fatal("sockmap full pressure should not trigger global generic sockmap fallback")
	}

	mgr = NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.regWindowStartNs.Store(time.Now().UnixNano())
	for i := 0; i < 32; i++ {
		mgr.recordSockmapRegistrationFailure(syscall.ENOSPC)
	}

	if got := mgr.fullRejects.Load(); got != 32 {
		t.Fatalf("full rejects = %d, want 32", got)
	}
	if got := mgr.regWindowTotal.Load(); got != 0 {
		t.Fatalf("generic registration total should stay untouched, got %d", got)
	}
	if got := mgr.regWindowFailures.Load(); got != 0 {
		t.Fatalf("generic registration failures should stay untouched, got %d", got)
	}
	if mgr.ShouldFallbackToSplice() {
		t.Fatal("sockmap full pressure should not trigger global generic sockmap fallback")
	}

	mgr = NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.regWindowStartNs.Store(time.Now().UnixNano())
	for i := 0; i < 32; i++ {
		mgr.recordSockmapRegistrationFailure(syscall.EINVAL)
	}

	if got := mgr.fullRejects.Load(); got != 0 {
		t.Fatalf("full rejects should stay untouched for generic failures, got %d", got)
	}
	if got := mgr.regWindowTotal.Load(); got != 32 {
		t.Fatalf("generic registration total = %d, want 32", got)
	}
	if got := mgr.regWindowFailures.Load(); got != 32 {
		t.Fatalf("generic registration failures = %d, want 32", got)
	}
	if !mgr.ShouldFallbackToSplice() {
		t.Fatal("generic failures should still trigger fallback")
	}
}

func TestCapabilityRejectDoesNotAffectGenericFallbackWindow(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.regWindowStartNs.Store(time.Now().UnixNano())

	for i := 0; i < 32; i++ {
		mgr.recordSockmapRegistrationFailure(fmt.Errorf("wrap: %w", syscall.EOPNOTSUPP))
	}

	if got := mgr.fullRejects.Load(); got != 0 {
		t.Fatalf("full rejects should stay untouched for capability rejects, got %d", got)
	}
	if got := mgr.regFailures.Load(); got != 0 {
		t.Fatalf("generic registration failures should stay untouched, got %d", got)
	}
	if got := mgr.regWindowTotal.Load(); got != 0 {
		t.Fatalf("generic registration total should stay untouched, got %d", got)
	}
	if got := mgr.regWindowFailures.Load(); got != 0 {
		t.Fatalf("generic registration failures should stay untouched, got %d", got)
	}
	if mgr.ShouldFallbackToSplice() {
		t.Fatal("capability rejects should not trigger global generic sockmap fallback")
	}
}
