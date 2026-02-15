package ebpf

import (
	"net"
	"sync"
	"time"
)

// BlacklistConfig configures the IP blacklist behavior.
type BlacklistConfig struct {
	// MaxEntries is the BPF map capacity. Default 4096.
	MaxEntries uint32

	// FailThreshold is the number of failures before banning. Default 5.
	FailThreshold int

	// FailWindow is the sliding window for counting failures. Default 60s.
	FailWindow time.Duration

	// BanDuration is how long an IP stays banned. Default 5m.
	BanDuration time.Duration

	// CleanupInterval is the expired-entry sweep interval. Default 30s.
	CleanupInterval time.Duration
}

// DefaultBlacklistConfig returns sensible defaults.
func DefaultBlacklistConfig() BlacklistConfig {
	return BlacklistConfig{
		MaxEntries:      4096,
		FailThreshold:   5,
		FailWindow:      60 * time.Second,
		BanDuration:     5 * time.Minute,
		CleanupInterval: 30 * time.Second,
	}
}

// BlacklistManager tracks REALITY auth failures per IP and optionally
// installs an XDP program that drops packets from banned IPs at the
// NIC driver level. On non-Linux or when XDP attachment fails, the
// manager still tracks failures in Go (graceful degradation).
type BlacklistManager struct {
	mu       sync.Mutex
	config   BlacklistConfig
	failures map[[16]byte]*failureRecord // per-IP failure tracking
	banned   map[[16]byte]time.Time      // ban expiry times
	mapFD    int                         // BPF hash map fd (-1 if not attached)
	progFD   int                         // XDP program fd (-1 if not attached)
	ifindex  int
	linkFD   int
	stopCh    chan struct{}
	once      sync.Once
	closeOnce sync.Once
}

type failureRecord struct {
	timestamps []time.Time
}

// NewBlacklistManager creates a new manager with the given config.
func NewBlacklistManager(config BlacklistConfig) *BlacklistManager {
	return &BlacklistManager{
		config:   config,
		failures: make(map[[16]byte]*failureRecord),
		banned:   make(map[[16]byte]time.Time),
		mapFD:    -1,
		progFD:   -1,
		linkFD:   -1,
		stopCh:   make(chan struct{}),
	}
}

// IPToKey converts a net.IP to the [16]byte key used for map lookups.
// IPv4 addresses are stored as IPv4-mapped IPv6.
func IPToKey(ip net.IP) [16]byte {
	var key [16]byte
	if ip4 := ip.To4(); ip4 != nil {
		// IPv4-mapped IPv6: ::ffff:x.x.x.x
		key[10] = 0xff
		key[11] = 0xff
		copy(key[12:], ip4)
	} else if ip16 := ip.To16(); ip16 != nil {
		copy(key[:], ip16)
	}
	return key
}

// Enable activates the XDP blacklist on the specified interface.
// Platform-specific: on non-Linux, returns ErrXDPNotSupported.
func (m *BlacklistManager) Enable(ifname string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	err := m.enableXDP(ifname)
	// Start cleanup goroutine regardless of XDP success.
	m.once.Do(func() {
		go m.cleanup()
	})
	return err
}

// Disable detaches the XDP program and stops the cleanup goroutine.
func (m *BlacklistManager) Disable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.closeOnce.Do(func() { close(m.stopCh) })
	return m.disableXDP()
}

// RecordFailure records an auth failure for the given IP.
// If the failure threshold is exceeded within the window, the IP is banned.
func (m *BlacklistManager) RecordFailure(ip net.IP) {
	if ip == nil {
		return
	}
	key := IPToKey(ip)
	now := time.Now()

	m.mu.Lock()
	defer m.mu.Unlock()

	// Start cleanup goroutine on first failure if not started.
	m.once.Do(func() {
		go m.cleanup()
	})

	// Already banned?
	if expiry, ok := m.banned[key]; ok && now.Before(expiry) {
		return
	}

	rec := m.failures[key]
	if rec == nil {
		rec = &failureRecord{}
		m.failures[key] = rec
	}

	// Prune timestamps outside the failure window.
	cutoff := now.Add(-m.config.FailWindow)
	valid := rec.timestamps[:0]
	for _, ts := range rec.timestamps {
		if ts.After(cutoff) {
			valid = append(valid, ts)
		}
	}
	rec.timestamps = append(valid, now)

	if len(rec.timestamps) >= m.config.FailThreshold {
		// Ban this IP.
		m.banned[key] = now.Add(m.config.BanDuration)
		delete(m.failures, key)
		m.addToBPFMap(key)
	}
}

// IsBanned returns true if the given IP is currently banned.
func (m *BlacklistManager) IsBanned(ip net.IP) bool {
	if ip == nil {
		return false
	}
	key := IPToKey(ip)
	m.mu.Lock()
	defer m.mu.Unlock()
	if expiry, ok := m.banned[key]; ok {
		return time.Now().Before(expiry)
	}
	return false
}

// cleanup runs in a background goroutine, periodically removing expired bans.
func (m *BlacklistManager) cleanup() {
	ticker := time.NewTicker(m.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.sweepExpired()
		}
	}
}

func (m *BlacklistManager) sweepExpired() {
	now := time.Now()
	m.mu.Lock()
	defer m.mu.Unlock()

	for key, expiry := range m.banned {
		if now.After(expiry) {
			delete(m.banned, key)
			m.removeFromBPFMap(key)
		}
	}

	// Also prune stale failure records (no activity within the window).
	cutoff := now.Add(-m.config.FailWindow)
	for key, rec := range m.failures {
		if len(rec.timestamps) == 0 || rec.timestamps[len(rec.timestamps)-1].Before(cutoff) {
			delete(m.failures, key)
		}
	}
}

// addToBPFMap adds a banned IP to the BPF map (if attached).
// Must be called with m.mu held.
func (m *BlacklistManager) addToBPFMap(key [16]byte) {
	if m.mapFD < 0 {
		return
	}
	bpfMapUpdateBlacklist(m.mapFD, key)
}

// removeFromBPFMap removes a banned IP from the BPF map (if attached).
// Must be called with m.mu held.
func (m *BlacklistManager) removeFromBPFMap(key [16]byte) {
	if m.mapFD < 0 {
		return
	}
	bpfMapDeleteBlacklist(m.mapFD, key)
}
