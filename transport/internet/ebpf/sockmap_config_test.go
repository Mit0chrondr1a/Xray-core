package ebpf

import (
	"syscall"
	"testing"
	"time"
)

// TestNewSockmapManager_ClampsZeroMaxEntries verifies that zero MaxEntries gets
// the default value of 65536.
func TestNewSockmapManager_ClampsZeroMaxEntries(t *testing.T) {
	mgr := NewSockmapManager(SockmapConfig{MaxEntries: 0})
	if mgr.config.MaxEntries != 65536 {
		t.Fatalf("MaxEntries=%d, want 65536 (zero should be clamped to default)", mgr.config.MaxEntries)
	}
}

// TestNewSockmapManager_ClampsExcessiveMaxEntries verifies that values above 1M
// are clamped to 1M.
func TestNewSockmapManager_ClampsExcessiveMaxEntries(t *testing.T) {
	const maxSockmapEntries = 1 << 20
	mgr := NewSockmapManager(SockmapConfig{MaxEntries: maxSockmapEntries + 1})
	if mgr.config.MaxEntries != maxSockmapEntries {
		t.Fatalf("MaxEntries=%d, want %d (should be clamped to max)", mgr.config.MaxEntries, maxSockmapEntries)
	}
}

// TestNewSockmapManager_AcceptsValidMaxEntries verifies that a normal value passes
// through unchanged.
func TestNewSockmapManager_AcceptsValidMaxEntries(t *testing.T) {
	mgr := NewSockmapManager(SockmapConfig{MaxEntries: 4096})
	if mgr.config.MaxEntries != 4096 {
		t.Fatalf("MaxEntries=%d, want 4096", mgr.config.MaxEntries)
	}
}

// TestNewSockmapManager_ExactMaxBoundary verifies the exact maximum is accepted.
func TestNewSockmapManager_ExactMaxBoundary(t *testing.T) {
	const maxSockmapEntries = 1 << 20
	mgr := NewSockmapManager(SockmapConfig{MaxEntries: maxSockmapEntries})
	if mgr.config.MaxEntries != maxSockmapEntries {
		t.Fatalf("MaxEntries=%d, want %d (exact max should be accepted)", mgr.config.MaxEntries, maxSockmapEntries)
	}
}

// TestNewSockmapManager_InitializesLRU verifies that the LRU structures are initialized.
func TestNewSockmapManager_InitializesLRU(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	if mgr.lruList == nil {
		t.Fatal("lruList must not be nil after construction")
	}
	if mgr.lruIndex == nil {
		t.Fatal("lruIndex must not be nil after construction")
	}
}

// TestSockmapManager_IsEnabled_DefaultsFalse verifies new managers are disabled.
func TestSockmapManager_IsEnabled_DefaultsFalse(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	if mgr.IsEnabled() {
		t.Fatal("newly created SockmapManager should not be enabled")
	}
}

// TestSockmapManager_UsingNativeLoader_DefaultsFalse verifies new managers use Go-native by default.
func TestSockmapManager_UsingNativeLoader_DefaultsFalse(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	if mgr.UsingNativeLoader() {
		t.Fatal("newly created SockmapManager should not use native loader by default")
	}
}

// TestSockmapManager_DisableIdempotent verifies calling Disable on an already-disabled manager is safe.
func TestSockmapManager_DisableIdempotent(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	if err := mgr.Disable(); err != nil {
		t.Fatalf("Disable on already-disabled manager should succeed: %v", err)
	}
	if err := mgr.Disable(); err != nil {
		t.Fatalf("second Disable should also succeed: %v", err)
	}
}

// TestSockmapManager_GetStatsEmpty verifies stats on a fresh manager.
func TestSockmapManager_GetStatsEmpty(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	stats := mgr.GetSockmapStats()
	if stats.ActivePairs != 0 {
		t.Fatalf("ActivePairs=%d, want 0", stats.ActivePairs)
	}
	if stats.TotalPairs != 0 {
		t.Fatalf("TotalPairs=%d, want 0", stats.TotalPairs)
	}
	if stats.FullRejects != 0 {
		t.Fatalf("FullRejects=%d, want 0", stats.FullRejects)
	}
	if stats.PeakPairs != 0 {
		t.Fatalf("PeakPairs=%d, want 0", stats.PeakPairs)
	}
	if stats.Enabled {
		t.Fatal("Enabled should be false")
	}
	if stats.NativeLoader {
		t.Fatal("NativeLoader should be false")
	}
	if stats.MaxEntries != 65536 {
		t.Fatalf("MaxEntries=%d, want 65536 (from DefaultSockmapConfig)", stats.MaxEntries)
	}
}

// TestComputeRedirectPolicy_BothPlain verifies plain TCP pairs are allowed.
func TestComputeRedirectPolicy_BothPlain(t *testing.T) {
	policy := computeRedirectPolicy(CryptoNone, CryptoNone)
	if policy&PolicyAllowRedirect == 0 {
		t.Fatal("CryptoNone <-> CryptoNone should allow redirect")
	}
	if policy&PolicyKTLSActive != 0 {
		t.Fatal("CryptoNone <-> CryptoNone should not set PolicyKTLSActive")
	}
}

// TestComputeRedirectPolicy_BothKTLS verifies kTLS pairs are allowed with flag.
func TestComputeRedirectPolicy_BothKTLS(t *testing.T) {
	policy := computeRedirectPolicy(CryptoKTLSBoth, CryptoKTLSBoth)
	if policy&PolicyAllowRedirect == 0 {
		t.Fatal("CryptoKTLSBoth <-> CryptoKTLSBoth should allow redirect")
	}
	if policy&PolicyKTLSActive == 0 {
		t.Fatal("CryptoKTLSBoth <-> CryptoKTLSBoth should set PolicyKTLSActive")
	}
}

// TestComputeRedirectPolicy_AsymmetricKTLS verifies mixed kTLS + plain is allowed.
func TestComputeRedirectPolicy_AsymmetricKTLS(t *testing.T) {
	policy := computeRedirectPolicy(CryptoKTLSBoth, CryptoNone)
	if policy&PolicyAllowRedirect == 0 {
		t.Fatal("CryptoKTLSBoth <-> CryptoNone should allow redirect (normal proxy scenario)")
	}
	if policy&PolicyKTLSActive == 0 {
		t.Fatal("should set PolicyKTLSActive when one side is kTLS")
	}
}

// TestComputeRedirectPolicy_UserspaceTLS_Denied verifies userspace TLS is rejected.
func TestComputeRedirectPolicy_UserspaceTLS_Denied(t *testing.T) {
	tests := []struct {
		name     string
		inbound  CryptoHint
		outbound CryptoHint
	}{
		{"userspace inbound", CryptoUserspaceTLS, CryptoNone},
		{"userspace outbound", CryptoNone, CryptoUserspaceTLS},
		{"both userspace", CryptoUserspaceTLS, CryptoUserspaceTLS},
		{"userspace + kTLS", CryptoUserspaceTLS, CryptoKTLSBoth},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := computeRedirectPolicy(tt.inbound, tt.outbound)
			if policy != 0 {
				t.Fatalf("policy=%d, want 0 (userspace TLS must not be redirected)", policy)
			}
		})
	}
}

// TestComputeRedirectPolicy_PartialKTLS_Denied verifies partial kTLS is rejected.
func TestComputeRedirectPolicy_PartialKTLS_Denied(t *testing.T) {
	tests := []struct {
		name     string
		inbound  CryptoHint
		outbound CryptoHint
	}{
		{"TX-only inbound", CryptoKTLSTxOnly, CryptoNone},
		{"RX-only outbound", CryptoNone, CryptoKTLSRxOnly},
		{"TX-only + RX-only", CryptoKTLSTxOnly, CryptoKTLSRxOnly},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := computeRedirectPolicy(tt.inbound, tt.outbound)
			if policy != 0 {
				t.Fatalf("policy=%d, want 0 (partial kTLS must not be redirected)", policy)
			}
		})
	}
}

// TestCryptoHint_String verifies string representations.
func TestCryptoHint_String(t *testing.T) {
	tests := []struct {
		hint CryptoHint
		want string
	}{
		{CryptoNone, "none"},
		{CryptoKTLSBoth, "kTLS-both"},
		{CryptoKTLSTxOnly, "kTLS-TX"},
		{CryptoKTLSRxOnly, "kTLS-RX"},
		{CryptoUserspaceTLS, "userspace"},
		{CryptoHint(99), "unknown"},
	}
	for _, tt := range tests {
		got := tt.hint.String()
		if got != tt.want {
			t.Fatalf("CryptoHint(%d).String() = %q, want %q", tt.hint, got, tt.want)
		}
	}
}

// TestIsSockmapFull verifies the ENOSPC/E2BIG error detection.
func TestIsSockmapFull(t *testing.T) {
	if !isSockmapFull(syscall.ENOSPC) {
		t.Fatal("ENOSPC should indicate sockmap full")
	}
	if !isSockmapFull(syscall.E2BIG) {
		t.Fatal("E2BIG should indicate sockmap full")
	}
	if isSockmapFull(syscall.EINVAL) {
		t.Fatal("EINVAL should not indicate sockmap full")
	}
	if isSockmapFull(nil) {
		t.Fatal("nil should not indicate sockmap full")
	}
}

// TestAdaptSweepIntervalEdgeCases verifies additional sweep interval edge cases
// beyond the linux-specific test. This covers boundary values and the floor/ceiling.
func TestAdaptSweepIntervalEdgeCases(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())

	tests := []struct {
		name       string
		current    time.Duration
		stale      int
		total      int
		expectFunc func(result time.Duration) bool
		desc       string
	}{
		{
			name:       "zero total keeps interval",
			current:    30 * time.Second,
			stale:      0,
			total:      0,
			expectFunc: func(r time.Duration) bool { return r == 30*time.Second },
			desc:       "30s",
		},
		{
			name:       "floor at 5s",
			current:    5 * time.Second,
			stale:      60,
			total:      100,
			expectFunc: func(r time.Duration) bool { return r == 5*time.Second },
			desc:       "5s (floor)",
		},
		{
			name:       "ceiling at 60s",
			current:    60 * time.Second,
			stale:      0,
			total:      1000,
			expectFunc: func(r time.Duration) bool { return r == 60*time.Second },
			desc:       "60s (ceiling)",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mgr.adaptSweepInterval(tt.current, tt.stale, tt.total)
			if !tt.expectFunc(result) {
				t.Fatalf("got %v, want %s", result, tt.desc)
			}
		})
	}
}

// TestUpdatePeakPairs verifies the high-water mark CAS logic.
func TestUpdatePeakPairs(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.updatePeakPairs(10)
	if got := mgr.peakPairs.Load(); got != 10 {
		t.Fatalf("peak=%d, want 10", got)
	}
	mgr.updatePeakPairs(5)
	if got := mgr.peakPairs.Load(); got != 10 {
		t.Fatalf("peak=%d, want 10 (should not decrease)", got)
	}
	mgr.updatePeakPairs(20)
	if got := mgr.peakPairs.Load(); got != 20 {
		t.Fatalf("peak=%d, want 20", got)
	}
}

// TestShouldFallbackToSplice_WhenDisabled verifies disabled manager always falls back.
func TestShouldFallbackToSplice_WhenDisabled(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	// Not enabled -- should fall back
	if !mgr.ShouldFallbackToSplice() {
		t.Fatal("disabled manager should always fall back to splice")
	}
}

// TestShouldFallbackToSplice_HealthyManager verifies healthy manager does not fall back.
func TestShouldFallbackToSplice_HealthyManager(t *testing.T) {
	mgr := NewSockmapManager(DefaultSockmapConfig())
	mgr.enabled.Store(true)
	mgr.regWindowStartNs.Store(time.Now().UnixNano())
	mgr.regWindowTotal.Store(100)
	mgr.regWindowFailures.Store(0)
	mgr.sweepStaleRatio.Store(0)

	if mgr.ShouldFallbackToSplice() {
		t.Fatal("healthy manager should not fall back to splice")
	}
}
