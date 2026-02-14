package ebpf

import (
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
