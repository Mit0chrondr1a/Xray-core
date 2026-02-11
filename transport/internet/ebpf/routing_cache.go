package ebpf

import (
	"net"
	"sync"
	"sync/atomic"
)

// RoutingCache provides a BPF-backed cache for routing decisions.
// It caches Router.PickRoute() results to reduce routing latency.
type RoutingCache struct {
	mu        sync.RWMutex
	config    RoutingCacheConfig
	enabled   bool
	version   atomic.Uint64
	stats     RoutingCacheStats
}

// RoutingCacheKey identifies a routing lookup key.
type RoutingCacheKey struct {
	// SrcIP is the source IP address.
	SrcIP [16]byte
	// DstIP is the destination IP address.
	DstIP [16]byte
	// DstPort is the destination port.
	DstPort uint16
	// Protocol is the IP protocol (TCP=6, UDP=17).
	Protocol uint8
	// Domain is a hash of the target domain (if applicable).
	DomainHash uint32
}

// RoutingCacheEntry contains the cached routing decision.
type RoutingCacheEntry struct {
	// OutboundTag is the selected outbound tag.
	OutboundTag string
	// RuleTag is the matched rule tag (if any).
	RuleTag string
	// Version is the config version when this entry was created.
	Version uint64
	// Hits is the number of cache hits for this entry.
	Hits uint64
}

// RoutingCacheStats contains cache statistics.
type RoutingCacheStats struct {
	// Hits is the total number of cache hits.
	Hits uint64
	// Misses is the total number of cache misses.
	Misses uint64
	// Evictions is the total number of evicted entries.
	Evictions uint64
	// Entries is the current number of cache entries.
	Entries uint64
}

// NewRoutingCache creates a new routing cache.
func NewRoutingCache(config RoutingCacheConfig) *RoutingCache {
	return &RoutingCache{
		config: config,
	}
}

// Enable activates the routing cache.
func (c *RoutingCache) Enable() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	caps := GetCapabilities()
	if !caps.TCBPFSupported {
		return ErrRoutingCacheNotSupported
	}

	if err := c.setupBPFMap(); err != nil {
		return err
	}

	c.enabled = true
	return nil
}

// Disable deactivates the routing cache.
func (c *RoutingCache) Disable() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return nil
	}

	if err := c.teardownBPFMap(); err != nil {
		return err
	}

	c.enabled = false
	return nil
}

// Lookup looks up a routing decision in the cache.
// Returns the entry and true if found and valid, otherwise nil and false.
func (c *RoutingCache) Lookup(key RoutingCacheKey) (*RoutingCacheEntry, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.enabled {
		return nil, false
	}

	entry, ok := c.lookupBPFMap(key)
	if !ok {
		atomic.AddUint64(&c.stats.Misses, 1)
		return nil, false
	}

	// Check if entry is still valid (config version matches)
	currentVersion := c.version.Load()
	if entry.Version != currentVersion {
		atomic.AddUint64(&c.stats.Misses, 1)
		return nil, false
	}

	atomic.AddUint64(&c.stats.Hits, 1)
	atomic.AddUint64(&entry.Hits, 1)
	return entry, true
}

// Insert adds or updates a routing decision in the cache.
func (c *RoutingCache) Insert(key RoutingCacheKey, outboundTag, ruleTag string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return ErrRoutingCacheNotEnabled
	}

	entry := &RoutingCacheEntry{
		OutboundTag: outboundTag,
		RuleTag:     ruleTag,
		Version:     c.version.Load(),
	}

	return c.updateBPFMap(key, entry)
}

// Invalidate invalidates all cache entries.
// This should be called when the routing configuration changes.
func (c *RoutingCache) Invalidate() {
	c.version.Add(1)
}

// Delete removes a specific entry from the cache.
func (c *RoutingCache) Delete(key RoutingCacheKey) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.enabled {
		return nil
	}

	return c.deleteBPFMap(key)
}

// GetStats returns cache statistics.
func (c *RoutingCache) GetStats() RoutingCacheStats {
	return RoutingCacheStats{
		Hits:      atomic.LoadUint64(&c.stats.Hits),
		Misses:    atomic.LoadUint64(&c.stats.Misses),
		Evictions: atomic.LoadUint64(&c.stats.Evictions),
		Entries:   atomic.LoadUint64(&c.stats.Entries),
	}
}

// IsEnabled returns true if the cache is active.
func (c *RoutingCache) IsEnabled() bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.enabled
}

// MakeKey creates a routing cache key from connection parameters.
func MakeKey(srcIP, dstIP net.IP, dstPort uint16, protocol uint8, domain string) RoutingCacheKey {
	key := RoutingCacheKey{
		DstPort:  dstPort,
		Protocol: protocol,
	}

	if srcIP != nil {
		copy(key.SrcIP[:], srcIP.To16())
	}
	if dstIP != nil {
		copy(key.DstIP[:], dstIP.To16())
	}
	if domain != "" {
		key.DomainHash = hashDomain(domain)
	}

	return key
}

// hashDomain computes a fast hash of a domain name.
func hashDomain(domain string) uint32 {
	// FNV-1a hash
	var hash uint32 = 2166136261
	for i := 0; i < len(domain); i++ {
		hash ^= uint32(domain[i])
		hash *= 16777619
	}
	return hash
}

// Platform-specific implementations
func (c *RoutingCache) setupBPFMap() error {
	return setupRoutingCacheImpl(c.config)
}

func (c *RoutingCache) teardownBPFMap() error {
	return teardownRoutingCacheImpl()
}

func (c *RoutingCache) lookupBPFMap(key RoutingCacheKey) (*RoutingCacheEntry, bool) {
	return lookupRoutingCacheImpl(key)
}

func (c *RoutingCache) updateBPFMap(key RoutingCacheKey, entry *RoutingCacheEntry) error {
	return updateRoutingCacheImpl(key, entry)
}

func (c *RoutingCache) deleteBPFMap(key RoutingCacheKey) error {
	return deleteRoutingCacheImpl(key)
}
