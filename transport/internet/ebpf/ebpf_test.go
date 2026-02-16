package ebpf

import (
	"net"
	"testing"
)

// --- KernelVersion ---

func TestKernelVersionAtLeast(t *testing.T) {
	tests := []struct {
		v      KernelVersion
		major  int
		minor  int
		patch  int
		expect bool
	}{
		{KernelVersion{5, 4, 0}, 5, 4, 0, true},   // exact match
		{KernelVersion{5, 4, 1}, 5, 4, 0, true},   // patch higher
		{KernelVersion{5, 5, 0}, 5, 4, 0, true},   // minor higher
		{KernelVersion{6, 0, 0}, 5, 4, 0, true},   // major higher
		{KernelVersion{5, 3, 255}, 5, 4, 0, false}, // minor lower
		{KernelVersion{4, 17, 0}, 5, 4, 0, false},  // major lower
		{KernelVersion{5, 4, 0}, 5, 4, 1, false},   // patch lower
		{KernelVersion{0, 0, 0}, 0, 0, 0, true},    // zero == zero
	}
	for _, tt := range tests {
		got := tt.v.AtLeast(tt.major, tt.minor, tt.patch)
		if got != tt.expect {
			t.Errorf("KernelVersion%v.AtLeast(%d,%d,%d) = %v, want %v",
				tt.v, tt.major, tt.minor, tt.patch, got, tt.expect)
		}
	}
}

func TestKernelVersionString(t *testing.T) {
	tests := []struct {
		v    KernelVersion
		want string
	}{
		{KernelVersion{5, 4, 0}, "5.4.0"},
		{KernelVersion{6, 1, 123}, "6.1.123"},
		{KernelVersion{0, 0, 0}, "0.0.0"},
	}
	for _, tt := range tests {
		got := tt.v.String()
		if got != tt.want {
			t.Errorf("KernelVersion%v.String() = %q, want %q", tt.v, got, tt.want)
		}
	}
}

// --- Default Configs ---

func TestDefaultXDPConfig(t *testing.T) {
	cfg := DefaultXDPConfig()
	if cfg.Mode != XDPModeAuto {
		t.Fatalf("Mode=%v, want XDPModeAuto", cfg.Mode)
	}
	if cfg.FlowTableSize != 65536 {
		t.Fatalf("FlowTableSize=%d, want 65536", cfg.FlowTableSize)
	}
	if cfg.FlowTimeout != 300 {
		t.Fatalf("FlowTimeout=%d, want 300", cfg.FlowTimeout)
	}
}

func TestDefaultSockmapConfig(t *testing.T) {
	cfg := DefaultSockmapConfig()
	if cfg.MaxEntries != 65536 {
		t.Fatalf("MaxEntries=%d, want 65536", cfg.MaxEntries)
	}
	if cfg.PinPath != "/sys/fs/bpf/xray/" {
		t.Fatalf("PinPath=%q, want /sys/fs/bpf/xray/", cfg.PinPath)
	}
}

func TestDefaultRoutingCacheConfig(t *testing.T) {
	cfg := DefaultRoutingCacheConfig()
	if cfg.MaxEntries != 32768 {
		t.Fatalf("MaxEntries=%d, want 32768", cfg.MaxEntries)
	}
	if cfg.TTLSeconds != 60 {
		t.Fatalf("TTLSeconds=%d, want 60", cfg.TTLSeconds)
	}
}

// --- RoutingCache ---

func TestHashDomainDeterministic(t *testing.T) {
	h1 := hashDomain("example.com")
	h2 := hashDomain("example.com")
	if h1 != h2 {
		t.Fatalf("hashDomain not deterministic: %d != %d", h1, h2)
	}
}

func TestHashDomainDifferentInputs(t *testing.T) {
	h1 := hashDomain("example.com")
	h2 := hashDomain("example.org")
	if h1 == h2 {
		t.Fatal("hashDomain returned same hash for different domains")
	}
}

func TestHashDomainEmpty(t *testing.T) {
	// FNV-1a initial basis with no iterations.
	h := hashDomain("")
	if h != 2166136261 {
		t.Fatalf("hashDomain(\"\") = %d, want 2166136261", h)
	}
}

func TestMakeKey(t *testing.T) {
	key := MakeKey(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		443,
		6,
		"example.com",
	)
	if key.DstPort != 443 {
		t.Fatalf("DstPort=%d, want 443", key.DstPort)
	}
	if key.Protocol != 6 {
		t.Fatalf("Protocol=%d, want 6", key.Protocol)
	}
	if key.DomainHash == 0 {
		t.Fatal("DomainHash should be non-zero for non-empty domain")
	}
}

func TestMakeKeyNoDomain(t *testing.T) {
	key := MakeKey(nil, nil, 80, 6, "")
	if key.DomainHash != 0 {
		t.Fatalf("DomainHash=%d, want 0 for empty domain", key.DomainHash)
	}
}

func TestMakeKeyIPv6(t *testing.T) {
	key := MakeKey(
		net.ParseIP("::1"),
		net.ParseIP("2001:db8::1"),
		8080,
		17,
		"",
	)
	if key.DstPort != 8080 {
		t.Fatalf("DstPort=%d, want 8080", key.DstPort)
	}
	if key.Protocol != 17 {
		t.Fatalf("Protocol=%d, want 17", key.Protocol)
	}
}

func TestRoutingCacheNotEnabledReturnsNil(t *testing.T) {
	cache := NewRoutingCache(DefaultRoutingCacheConfig())
	entry, ok := cache.Lookup(RoutingCacheKey{})
	if ok || entry != nil {
		t.Fatal("Lookup on disabled cache should return nil, false")
	}
}

func TestRoutingCacheInsertNotEnabled(t *testing.T) {
	cache := NewRoutingCache(DefaultRoutingCacheConfig())
	err := cache.Insert(RoutingCacheKey{}, "tag", "rule")
	if err != ErrRoutingCacheNotEnabled {
		t.Fatalf("Insert on disabled cache: got %v, want ErrRoutingCacheNotEnabled", err)
	}
}

func TestRoutingCacheInvalidate(t *testing.T) {
	cache := NewRoutingCache(DefaultRoutingCacheConfig())
	v1 := cache.version.Load()
	cache.Invalidate()
	v2 := cache.version.Load()
	if v2 != v1+1 {
		t.Fatalf("Invalidate: version=%d, want %d", v2, v1+1)
	}
}

func TestRoutingCacheIsEnabled(t *testing.T) {
	cache := NewRoutingCache(DefaultRoutingCacheConfig())
	if cache.IsEnabled() {
		t.Fatal("newly created cache should be disabled")
	}
}

func TestRoutingCacheGetStatsEmpty(t *testing.T) {
	cache := NewRoutingCache(DefaultRoutingCacheConfig())
	stats := cache.GetStats()
	if stats.Hits != 0 || stats.Misses != 0 || stats.Evictions != 0 || stats.Entries != 0 {
		t.Fatalf("empty cache stats should be all zero: %+v", stats)
	}
}

func TestRoutingCacheDeleteNotEnabled(t *testing.T) {
	cache := NewRoutingCache(DefaultRoutingCacheConfig())
	err := cache.Delete(RoutingCacheKey{})
	if err != nil {
		t.Fatalf("Delete on disabled cache should return nil, got %v", err)
	}
}

func TestRoutingCacheDisableIdempotent(t *testing.T) {
	cache := NewRoutingCache(DefaultRoutingCacheConfig())
	// Disable on already-disabled should be no-op.
	if err := cache.Disable(); err != nil {
		t.Fatalf("Disable on disabled cache: %v", err)
	}
}

// --- Error Sentinel Values ---

func TestErrorSentinels(t *testing.T) {
	errors := []error{
		ErrXDPNotSupported,
		ErrXDPNotEnabled,
		ErrSockmapNotSupported,
		ErrSockmapNotEnabled,
		ErrRoutingCacheNotSupported,
		ErrRoutingCacheNotEnabled,
		ErrKernelTooOld,
		ErrPermissionDenied,
		ErrInvalidInterface,
		ErrFlowTableFull,
	}
	for _, e := range errors {
		if e == nil {
			t.Fatal("sentinel error should not be nil")
		}
		if e.Error() == "" {
			t.Fatalf("sentinel error has empty message: %v", e)
		}
	}
}

// --- IsAvailable ---

func TestIsAvailableDoesNotPanic(t *testing.T) {
	// Just verify it does not panic.
	_ = IsAvailable()
}

func TestGetCapabilitiesDoesNotPanic(t *testing.T) {
	caps := GetCapabilities()
	// Verify the version string is well-formed.
	if caps.KernelVersion.String() == "" {
		t.Fatal("kernel version string should not be empty")
	}
}
